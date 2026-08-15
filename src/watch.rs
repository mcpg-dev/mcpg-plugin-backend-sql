//! Polling watch strategy for SQL sources.
//!
//! Implements [`WatchStrategyPlugin`] with `kind: "sql_polling"`. A
//! registered watcher runs a short **tracking query** on a fixed
//! interval and emits a [`WatchEvent`] whenever the scalar it returns
//! changes between polls. Engine-agnostic: dispatches through the same
//! [`SqlDriver`] registry the [`crate::SqlBackendPlugin`] uses.
//!
//! Design notes
//!
//! - The tracking query should return a single row with a single
//!   scalar value (typical: `SELECT MAX(updated_at) FROM t` or
//!   `SELECT COUNT(*) FROM t`). Only the first column of the first row
//!   is inspected.
//! - The plugin opens its own pool. Sharing the binding plugin's pool
//!   is attractive but introduces cross-plugin state-sharing that has
//!   not been designed yet, so each watcher keeps its own connection
//!   set for simplicity.
//! - `interval_ms` has a hard floor (100 ms). This is a safety rail —
//!   polling faster than that hammers the DB without meaningfully
//!   improving change-detection latency.
//! - [`WatchEvent`] carries no payload today: the host uses it to fan
//!   out `resources/updated` and consumers re-read the resource. Row
//!   diffing and user/session extraction are explicitly out of scope
//!   here and tracked as later work.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    PluginManifest, WatchError, WatchEvent, WatchEventSink, WatchHandle, WatchStrategyPlugin,
    firstparty_manifest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::SqlBackendConfig;
use crate::driver::{self, PoolHandle, SqlDriver};
use crate::errors::SqlError;
use crate::params::{self, PreparedStmt};
use crate::pool;
use crate::session::SessionVars;

/// Minimum polling interval accepted at spec validation. Faster than
/// this is nearly always a misconfiguration and puts pressure on the
/// target DB with no practical benefit.
const MIN_INTERVAL_MS: u64 = 100;

/// Default polling interval when the spec omits `interval_ms`.
const DEFAULT_INTERVAL_MS: u64 = 1_000;

/// Per-watch spec. Flattens [`SqlBackendConfig`] so operators can
/// reuse the same driver / url / credentials / query shape they
/// already know from the binding block.
///
/// Example TOML:
/// ```toml
/// [watch.orders_feed]
/// strategy = "sql_polling"
/// driver   = "postgres"
/// url      = "postgres://app@db/orders"
/// interval_ms = 2000
///
/// [watch.orders_feed.credentials]
/// password_env = "ORDERS_DB_PW"
///
/// [watch.orders_feed.query]
/// sql      = "SELECT MAX(updated_at) FROM orders"
/// row_mode = "scalar"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlPollingWatchSpec {
    /// Reuses the binding config (driver, url, credentials, pool,
    /// query, session_vars). The query should return a single scalar.
    #[serde(flatten)]
    pub connection: SqlBackendConfig,
    /// Polling interval in milliseconds. Floored at
    /// [`MIN_INTERVAL_MS`] by [`Self::validate`].
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
}

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

impl SqlPollingWatchSpec {
    fn validate(&self) -> Result<(), SqlError> {
        self.connection.validate()?;
        if self.interval_ms < MIN_INTERVAL_MS {
            return Err(SqlError::InvalidSpec(format!(
                "watch.interval_ms ({} ms) is below the {MIN_INTERVAL_MS} ms floor",
                self.interval_ms,
            )));
        }
        Ok(())
    }
}

/// `WatchStrategyPlugin` for `kind: "sql_polling"`.
///
/// Shares the driver registry constructed from active feature flags —
/// a watcher pointed at a driver that isn't compiled in fails spec
/// validation at register time, not silently at poll time.
pub struct SqlPollingWatchPlugin {
    manifest: PluginManifest,
    drivers: std::collections::HashMap<crate::config::DriverKind, Arc<dyn SqlDriver>>,
}

impl std::fmt::Debug for SqlPollingWatchPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlPollingWatchPlugin")
            .field("id", &self.manifest.id)
            .field(
                "drivers",
                &self.drivers.keys().map(|k| k.as_str()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for SqlPollingWatchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlPollingWatchPlugin {
    /// Build a watch plugin using the default driver registry.
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.watch.sql_polling",
                name: "SQL Polling Watch",
                class: WatchStrategy,
            },
            drivers: driver::build_registry(),
        }
    }

    /// Construct a watch plugin with a custom driver registry. Tests
    /// inject in-memory doubles through this constructor.
    pub fn with_drivers(
        drivers: std::collections::HashMap<crate::config::DriverKind, Arc<dyn SqlDriver>>,
    ) -> Self {
        let mut p = Self::new();
        p.drivers = drivers;
        p
    }
}

/// Handle returned to the host. Dropping the handle is not sufficient
/// to cancel the watcher per the [`WatchHandle`] contract — the host
/// calls [`WatchHandle::cancel`] explicitly.
struct SqlPollingWatchHandle {
    cancel: CancellationToken,
}

#[async_trait]
impl WatchHandle for SqlPollingWatchHandle {
    async fn cancel(&self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl WatchStrategyPlugin for SqlPollingWatchPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "sql_polling"
    }

    async fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError> {
        let parsed: SqlPollingWatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("sql_polling watch spec: {e}"),
            })?;

        parsed.validate().map_err(|e| WatchError::InvalidSpec {
            message: e.to_string(),
        })?;

        let driver = self
            .drivers
            .get(&parsed.connection.driver)
            .cloned()
            .ok_or_else(|| WatchError::InvalidSpec {
                message: format!(
                    "driver '{}' is not compiled into this build",
                    parsed.connection.driver.as_str()
                ),
            })?;

        let stmt =
            build_prepared_stmt(&parsed.connection).map_err(|e| WatchError::InvalidSpec {
                message: e.to_string(),
            })?;

        let (pool_handle, _auth_rotator) = pool::build_pool(&parsed.connection, &driver)
            .await
            .map_err(|e| WatchError::Subscribe {
                message: e.to_string(),
            })?;
        // Cloud-auth rotator (if any) is intentionally dropped here:
        // sql-watch profiles don't carry an `auth:` block today
        // (config validate already rejects them on non-Postgres
        // drivers and watch profiles tend to use static creds), and
        // even if they did, this binding spawns one independent pool
        // per watch — letting the rotator live alongside it adds
        // complexity for no current operator value. Revisit when a
        // future change wires watch onto the same shared cloud-auth
        // pool as the parent binding.
        driver
            .health_check(&pool_handle)
            .await
            .map_err(|e| WatchError::Subscribe {
                message: e.to_string(),
            })?;

        let session = SessionVars::from_map(parsed.connection.session_vars.clone());
        let interval = Duration::from_millis(parsed.interval_ms);
        let cancel = CancellationToken::new();
        let cancel_child = cancel.clone();
        let uri_owned = resource_uri.to_owned();

        info!(
            uri = %uri_owned,
            driver = parsed.connection.driver.as_str(),
            interval_ms = parsed.interval_ms,
            "sql_polling watch: started"
        );

        tokio::spawn(poll_loop(
            pool_handle,
            driver,
            stmt,
            session,
            interval,
            cancel_child,
            uri_owned,
            sink,
        ));

        Ok(Box::new(SqlPollingWatchHandle { cancel }))
    }
}

/// Build a [`PreparedStmt`] from the tracking query. Mirrors the
/// binding plugin's prep path; kept in sync by construction.
fn build_prepared_stmt(cfg: &SqlBackendConfig) -> Result<PreparedStmt, SqlError> {
    use crate::config::QueryBody;
    let raw = match &cfg.query.body {
        QueryBody::Sql { sql } => sql.clone(),
        QueryBody::SqlFile { sql_file } => std::fs::read_to_string(sql_file).map_err(|e| {
            SqlError::InvalidSpec(format!("sql_file '{}': {e}", sql_file.display()))
        })?,
        QueryBody::Procedure { procedure } => {
            params::call_statement(procedure, cfg.query.params.len(), cfg.driver)
        }
    };
    let (rewritten, _order) = params::rewrite_placeholders(&raw, cfg.driver);
    Ok(PreparedStmt {
        sql: rewritten,
        param_order: cfg.query.params.clone(),
        driver: cfg.driver,
    })
}

/// Background poll loop. Runs until `cancel` fires. On each tick it
/// executes the tracking query, extracts the first column of the first
/// row as the cursor, and compares with the previous value. On change
/// it emits a [`WatchEvent`] — default-constructed; consumers re-read
/// the resource URI to pick up the change.
///
/// Errors from the driver are logged and the loop continues: a single
/// failed poll must not tear down the watcher, because the usual cause
/// (transient connectivity) is self-healing.
#[allow(clippy::too_many_arguments)]
async fn poll_loop(
    pool_handle: PoolHandle,
    driver: Arc<dyn SqlDriver>,
    stmt: PreparedStmt,
    session: SessionVars,
    interval: Duration,
    cancel: CancellationToken,
    uri: String,
    sink: Arc<dyn WatchEventSink>,
) {
    let mut last_cursor: Option<Value> = None;
    let mut ticker = tokio::time::interval(interval);
    // First tick fires immediately; subsequent ticks are evenly spaced.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(uri = %uri, "sql_polling watch: cancelled");
                return;
            }
            _ = ticker.tick() => {
                match driver.execute(&pool_handle, &stmt, &[], &session).await {
                    Ok(batch) => {
                        let cursor = first_scalar(&batch.rows);
                        if cursor != last_cursor {
                            if last_cursor.is_some() {
                                // Only emit on *change* — the first
                                // successful poll establishes the
                                // baseline and does not fire an event.
                                sink.emit(WatchEvent::default()).await;
                            }
                            last_cursor = cursor;
                        }
                    }
                    Err(e) => {
                        warn!(uri = %uri, error = %e, "sql_polling watch: poll failed");
                    }
                }
            }
        }
    }
}

/// Return the scalar cursor value for a tracking batch: the first
/// column of the first row, or `Null` when the batch is empty.
fn first_scalar(rows: &[Value]) -> Option<Value> {
    let first = rows.first()?;
    match first {
        Value::Object(map) => map.values().next().cloned(),
        other => Some(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DriverKind;
    use crate::driver::{ConnectCfg, RowBatch};
    use crate::params::BoundParam;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    // ------------------------------------------------------------------
    // Spec validation
    // ------------------------------------------------------------------

    fn minimal_spec_json(interval_ms: u64) -> Value {
        serde_json::json!({
            "driver": "sqlite",
            "url": "sqlite::memory:",
            "interval_ms": interval_ms,
            "query": {
                "sql": "SELECT 1",
                "row_mode": "scalar"
            }
        })
    }

    #[test]
    fn spec_parses_minimal() {
        let s: SqlPollingWatchSpec = serde_json::from_value(minimal_spec_json(500)).unwrap();
        assert_eq!(s.interval_ms, 500);
        assert_eq!(s.connection.driver, DriverKind::Sqlite);
    }

    #[test]
    fn validate_rejects_interval_below_floor() {
        let s: SqlPollingWatchSpec = serde_json::from_value(minimal_spec_json(10)).unwrap();
        let err = s.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("below")));
    }

    #[test]
    fn validate_accepts_interval_at_floor() {
        let s: SqlPollingWatchSpec =
            serde_json::from_value(minimal_spec_json(MIN_INTERVAL_MS)).unwrap();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn interval_defaults_when_omitted() {
        let spec = serde_json::json!({
            "driver": "sqlite",
            "url": "sqlite::memory:",
            "query": { "sql": "SELECT 1", "row_mode": "scalar" }
        });
        let s: SqlPollingWatchSpec = serde_json::from_value(spec).unwrap();
        assert_eq!(s.interval_ms, DEFAULT_INTERVAL_MS);
    }

    // ------------------------------------------------------------------
    // Scalar extraction
    // ------------------------------------------------------------------

    #[test]
    fn first_scalar_picks_first_value_of_object_row() {
        let rows = vec![serde_json::json!({"max": 42, "other": 7})];
        assert_eq!(first_scalar(&rows), Some(serde_json::json!(42)));
    }

    #[test]
    fn first_scalar_handles_scalar_row() {
        let rows = vec![serde_json::json!("abc")];
        assert_eq!(first_scalar(&rows), Some(serde_json::json!("abc")));
    }

    #[test]
    fn first_scalar_empty_returns_none() {
        assert_eq!(first_scalar(&[]), None);
    }

    // ------------------------------------------------------------------
    // End-to-end poll loop with a fake driver.
    // ------------------------------------------------------------------

    /// Driver double: returns a sequence of pre-seeded `RowBatch`es.
    struct ScriptedDriver {
        batches: Mutex<Vec<RowBatch>>,
        calls: AtomicU64,
    }

    impl ScriptedDriver {
        fn new(batches: Vec<RowBatch>) -> Self {
            Self {
                batches: Mutex::new(batches),
                calls: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl SqlDriver for ScriptedDriver {
        fn kind(&self) -> &'static str {
            "scripted"
        }

        async fn connect(
            &self,
            _cfg: &ConnectCfg,
        ) -> Result<crate::driver::ConnectOutcome, SqlError> {
            // Fake driver: not actually usable, but we never invoke
            // `build_pool` in poll-loop tests — we hand-wire the pool
            // in `drive_once`.
            Err(SqlError::InvalidSpec(
                "scripted::connect unsupported in tests".into(),
            ))
        }

        async fn execute(
            &self,
            _pool: &PoolHandle,
            _stmt: &PreparedStmt,
            _args: &[BoundParam],
            _session: &SessionVars,
        ) -> Result<RowBatch, SqlError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut guard = self.batches.lock().unwrap();
            // After exhausting the script, stay on the last batch so
            // extra ticks don't synthesize spurious "cursor reset"
            // events.
            if guard.len() > 1 {
                Ok(guard.remove(0))
            } else {
                Ok(guard.first().cloned().unwrap_or_default())
            }
        }

        async fn execute_affected(
            &self,
            _pool: &PoolHandle,
            _stmt: &PreparedStmt,
            _args: &[BoundParam],
            _session: &SessionVars,
        ) -> Result<u64, SqlError> {
            Ok(0)
        }

        async fn health_check(&self, _pool: &PoolHandle) -> Result<(), SqlError> {
            Ok(())
        }
    }

    struct CollectingSink {
        count: AtomicU64,
    }
    #[async_trait]
    impl WatchEventSink for CollectingSink {
        async fn emit(&self, _event: WatchEvent) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(feature = "sqlite")]
    async fn dummy_pool_handle() -> PoolHandle {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .expect("sqlite in-memory pool");
        PoolHandle::Sqlite(pool)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn poll_loop_emits_on_cursor_change_and_not_before() {
        let pool_handle = dummy_pool_handle().await;
        let driver = Arc::new(ScriptedDriver::new(vec![
            RowBatch {
                rows: vec![serde_json::json!({"max": 1})],
                ..RowBatch::default()
            },
            // Repeat — no change.
            RowBatch {
                rows: vec![serde_json::json!({"max": 1})],
                ..RowBatch::default()
            },
            // Change.
            RowBatch {
                rows: vec![serde_json::json!({"max": 2})],
                ..RowBatch::default()
            },
        ])) as Arc<dyn SqlDriver>;

        let stmt = PreparedStmt {
            sql: "SELECT 1".into(),
            param_order: vec![],
            driver: DriverKind::Sqlite,
        };
        let sink = Arc::new(CollectingSink {
            count: AtomicU64::new(0),
        });
        let cancel = CancellationToken::new();
        let cancel_child = cancel.clone();

        let h = tokio::spawn({
            let sink = sink.clone() as Arc<dyn WatchEventSink>;
            async move {
                poll_loop(
                    pool_handle,
                    driver,
                    stmt,
                    SessionVars::default(),
                    Duration::from_millis(MIN_INTERVAL_MS),
                    cancel_child,
                    "test://res".into(),
                    sink,
                )
                .await;
            }
        });

        // Let three intervals pass so all scripted batches fire.
        tokio::time::sleep(Duration::from_millis(MIN_INTERVAL_MS * 4)).await;
        cancel.cancel();
        let _ = h.await;

        // Baseline poll establishes cursor; unchanged poll is silent;
        // changed poll emits once.
        let emitted = sink.count.load(Ordering::SeqCst);
        assert_eq!(
            emitted, 1,
            "expected one emit on cursor change, got {emitted}"
        );
    }
}
