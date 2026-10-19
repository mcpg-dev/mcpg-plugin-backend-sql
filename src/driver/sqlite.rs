//! SQLite driver adapter.
//!
//! SQLite has dynamic typing — the declared column type is a *hint*
//! but values can be stored as any of NULL / integer / real / text /
//! blob. The decode path probes in that order via sqlx's typed
//! `try_get`.
//!
//! # Cancel
//!
//! SQLite has no server-side backend identifier and no side-channel
//! cancel. Each query that takes an `ExecCtx` gets a cancel flag of
//! its own, and a progress handler on its pinned connection that ends
//! the running statement with `SQLITE_INTERRUPT` once the flag is set:
//!
//! 1. `execute_with_ctx` pins a connection, installs the handler, and
//!    registers the flag in a per-driver table under a fresh `u64`
//!    nonce, which the in-flight registry records as
//!    `BackendId::Sqlite { handle }`.
//! 2. `cancel_backend` sets the flag. SQLite checks the handler where
//!    it checks for `sqlite3_interrupt`, so a running statement ends
//!    as promptly; unlike `sqlite3_interrupt`, which SQLite clears
//!    when a statement starts, a flag set before the statement starts
//!    still ends it.
//! 3. When the query ends, its flag goes inactive and leaves the table,
//!    so a handler left on the pooled connection stops no later query.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::{Map, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Column, Row};

use crate::driver::{ConnectCfg, ConnectOutcome, PoolHandle, RowBatch, SqlDriver};
use crate::errors::SqlError;
use crate::in_flight::BackendId;
use crate::params::{BoundParam, PreparedStmt};
use crate::session::SessionVars;

/// How many SQLite VM instructions run between two checks of a query's
/// cancel flag.
const CANCEL_CHECK_OPS: i32 = 1_000;

/// SQLite driver. Holds the table of running queries that
/// `cancel_backend` consults to cancel one.
pub struct SqliteDriver {
    /// Nonce → the cancel flag of a running query; in the table from
    /// when the query is registered until it ends.
    handles: Arc<DashMap<u64, Arc<Cancel>>>,
    /// Monotonically increasing handle id source. Wraps; collisions
    /// over `u64` are not a real risk.
    next_handle: AtomicU64,
}

/// One query's cancel state, read by the progress handler on its
/// connection.
#[derive(Debug)]
struct Cancel {
    cancelled: AtomicBool,
    /// Cleared when the query ends: the handler stays on the pooled
    /// connection when the query's future is dropped, and must then stop
    /// nothing.
    active: AtomicBool,
}

impl Cancel {
    /// Whether the statement running on the connection is to end now.
    fn stops(&self) -> bool {
        self.active.load(Ordering::Acquire) && self.cancelled.load(Ordering::Acquire)
    }
}

/// A query in the cancel table; it leaves the table, and its flag goes
/// inactive, when this drops, on every exit path of the query.
struct Running<'a> {
    handles: &'a DashMap<u64, Arc<Cancel>>,
    nonce: u64,
    cancel: Arc<Cancel>,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.cancel.active.store(false, Ordering::Release);
        self.handles.remove(&self.nonce);
    }
}

impl Default for SqliteDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl SqliteDriver {
    /// Construct an empty SQLite driver with a fresh handle table.
    pub fn new() -> Self {
        Self {
            handles: Arc::new(DashMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    /// Install a cancel flag's progress handler on `conn` and register
    /// the flag in the cancel table.
    async fn start(
        &self,
        conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    ) -> Result<Running<'_>, SqlError> {
        let cancel = Arc::new(Cancel {
            cancelled: AtomicBool::new(false),
            active: AtomicBool::new(true),
        });
        let watched = Arc::clone(&cancel);
        conn.lock_handle()
            .await
            .map_err(SqlError::from_execute)?
            .set_progress_handler(CANCEL_CHECK_OPS, move || !watched.stops());
        let nonce = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(nonce, Arc::clone(&cancel));
        Ok(Running {
            handles: &self.handles,
            nonce,
            cancel,
        })
    }
}

/// Take an ended query out of the cancel table and its handler off the
/// connection. A handler this cannot remove is inactive already.
async fn finish(conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>, running: Running<'_>) {
    drop(running);
    if let Ok(mut handle) = conn.lock_handle().await {
        handle.remove_progress_handler();
    }
}

#[async_trait]
impl SqlDriver for SqliteDriver {
    fn kind(&self) -> &'static str {
        "sqlite"
    }

    async fn connect(&self, cfg: &ConnectCfg) -> Result<ConnectOutcome, SqlError> {
        // SQLite cannot be IAM-authed — config validate already
        // rejects `auth:` blocks on this driver; defensive guard.
        if cfg.auth_provider.is_some() {
            return Err(SqlError::InvalidSpec(
                "auth: { ... } blocks are not applicable to SQLite (file-backed)".into(),
            ));
        }

        let opts = SqliteConnectOptions::from_str(&cfg.url)
            .map_err(|e| SqlError::InvalidSpec(format!("sqlite url: {e}")))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(cfg.max_connections)
            .min_connections(cfg.min_idle)
            .acquire_timeout(Duration::from_millis(cfg.acquire_timeout_ms))
            .idle_timeout(Some(Duration::from_millis(cfg.idle_timeout_ms)))
            .max_lifetime(Some(Duration::from_millis(cfg.max_lifetime_ms)))
            .test_before_acquire(cfg.test_before_acquire)
            .connect_with(opts)
            .await
            .map_err(SqlError::Connect)?;
        Ok(ConnectOutcome {
            pool: PoolHandle::Sqlite(pool),
            rotator: None,
        })
    }

    async fn execute(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        _session: &SessionVars,
    ) -> Result<RowBatch, SqlError> {
        // Pool-level dispatch (no cancel registry). Used by callers
        // that don't have an `ExecCtx` — most internal paths take the
        // `_with_ctx` variant which threads cancel state.
        let pool = match pool {
            PoolHandle::Sqlite(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "sqlite driver invoked with non-sqlite pool handle".into(),
                ));
            }
        };
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_sqlite(q, &arg.value);
        }
        let rows = q.fetch_all(pool).await.map_err(SqlError::from_execute)?;
        finish_rows(rows)
    }

    async fn execute_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        _session: &SessionVars,
        ctx: crate::driver::ExecCtx<'_>,
    ) -> Result<RowBatch, SqlError> {
        let pool = match pool {
            PoolHandle::Sqlite(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "sqlite driver invoked with non-sqlite pool handle".into(),
                ));
            }
        };
        // Pin one connection: the progress handler that honours the
        // cancel is on this connection, and the query must run there.
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        let running = self.start(&mut conn).await?;
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(
                rid,
                BackendId::Sqlite {
                    handle: running.nonce,
                },
            );
        }

        // A cancel ends the statement with SQLITE_INTERRUPT, which
        // sqlx surfaces as an error mapped through `from_execute`.
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_sqlite(q, &arg.value);
        }
        let rows_result = q
            .fetch_all(&mut *conn)
            .await
            .map_err(SqlError::from_execute);
        finish(&mut conn, running).await;
        finish_rows(rows_result?)
    }

    async fn execute_affected(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        _session: &SessionVars,
    ) -> Result<u64, SqlError> {
        let pool = match pool {
            PoolHandle::Sqlite(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "sqlite driver invoked with non-sqlite pool handle".into(),
                ));
            }
        };
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_sqlite(q, &arg.value);
        }
        let result = q.execute(pool).await.map_err(SqlError::from_execute)?;
        Ok(result.rows_affected())
    }

    async fn execute_affected_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        _session: &SessionVars,
        ctx: crate::driver::ExecCtx<'_>,
    ) -> Result<u64, SqlError> {
        let pool = match pool {
            PoolHandle::Sqlite(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "sqlite driver invoked with non-sqlite pool handle".into(),
                ));
            }
        };
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        let running = self.start(&mut conn).await?;
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(
                rid,
                BackendId::Sqlite {
                    handle: running.nonce,
                },
            );
        }

        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_sqlite(q, &arg.value);
        }
        let result = q.execute(&mut *conn).await.map_err(SqlError::from_execute);
        finish(&mut conn, running).await;
        Ok(result?.rows_affected())
    }

    async fn cancel_backend(
        &self,
        _pool: &PoolHandle,
        backend_id: BackendId,
    ) -> Result<(), SqlError> {
        let nonce = match backend_id {
            BackendId::Sqlite { handle } => handle,
            other => {
                return Err(SqlError::InvalidSpec(format!(
                    "sqlite cancel_backend: expected Sqlite backend id, got {other:?}"
                )));
            }
        };
        // A query no longer in the table has ended: nothing to cancel.
        if let Some(cancel) = self.handles.get(&nonce).map(|e| Arc::clone(e.value())) {
            cancel.cancelled.store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn health_check(&self, pool: &PoolHandle) -> Result<(), SqlError> {
        let pool = match pool {
            PoolHandle::Sqlite(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "sqlite health_check invoked with non-sqlite pool handle".into(),
                ));
            }
        };
        sqlx::query("SELECT 1")
            .fetch_one(pool)
            .await
            .map(|_| ())
            .map_err(SqlError::from_execute)
    }
}

/// Drain a successful row fetch into the driver's `RowBatch` shape.
fn finish_rows(rows: Vec<SqliteRow>) -> Result<RowBatch, SqlError> {
    let columns = rows
        .first()
        .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
        .unwrap_or_default();
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push(row_to_json_sqlite(row)?);
    }
    Ok(RowBatch {
        columns,
        rows: out,
        rows_affected: None,
        truncated: false,
        has_more: false,
    })
}

/// Bind one JSON scalar to a SQLite prepared-statement argument.
fn bind_sqlite<'q>(
    q: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    v: &'q Value,
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    match v {
        Value::Null => q.bind(Option::<String>::None),
        Value::Bool(b) => q.bind(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                q.bind(i)
            } else if let Some(f) = n.as_f64() {
                q.bind(f)
            } else {
                q.bind(n.to_string())
            }
        }
        Value::String(s) => q.bind(s.clone()),
        // SQLite has no native JSON type; serialize to text.
        Value::Array(_) | Value::Object(_) => q.bind(v.to_string()),
    }
}

/// Decode a SQLite row into a JSON object keyed by column name.
///
/// SQLite reports a declared column type that may or may not match
/// the stored value's dynamic type, so we probe in order.
///
/// # Type-fidelity notes (JSON / temporal / interval / encoding)
///
/// * **JSON / JSONB:** SQLite has no native JSON storage type. The
///   built-in `json1` extension stores JSON values as TEXT; the
///   binding's decoder cannot tell a JSON-bearing TEXT column apart
///   from any other TEXT, so JSON columns round-trip as
///   [`Value::String`]. Operators who want server-side JSON-aware
///   shaping should use `json_extract(...)` / `json_object(...)` /
///   `json_group_array(...)` in the query body — those return real
///   JSON-shaped results that this decoder will inline naturally
///   (the `json1` functions return TEXT; for true inlined JSON
///   pull the values out as `json_extract(col, '$.key')` and
///   compose with concrete column types).
/// * **TIMESTAMP / DATETIME:** SQLite has no native temporal type;
///   the canonical convention is to store ISO 8601 strings (or unix
///   epoch integers). They round-trip as [`Value::String`] /
///   [`Value::Number`] respectively — the decoder cannot reformat
///   a value whose semantic type isn't explicit in the schema.
/// * **INTERVAL:** No native type. Operators encode intervals
///   themselves (typically as ISO 8601 strings or microsecond
///   integers).
/// * **Encoding:** SQLite operates internally as UTF-8 (or
///   UTF-16 for `_le16` builds, which we don't ship); no
///   `after_connect` charset hook is needed.
fn row_to_json_sqlite(row: &SqliteRow) -> Result<Value, SqlError> {
    let mut obj = Map::with_capacity(row.columns().len());
    for (i, col) in row.columns().iter().enumerate() {
        let name = col.name().to_string();
        let value = decode_sqlite_column(row, i).unwrap_or_else(|e| {
            tracing::warn!(
                column = %name,
                error = %e,
                "sqlite: column decode failed, emitting null"
            );
            Value::Null
        });
        obj.insert(name, value);
    }
    Ok(Value::Object(obj))
}

fn decode_sqlite_column(row: &SqliteRow, idx: usize) -> Result<Value, String> {
    // Probe in the order SQLite is most likely to store the value.
    if let Ok(v) = row.try_get::<Option<i64>, _>(idx) {
        if let Some(i) = v {
            return Ok(Value::Number(i.into()));
        }
        return Ok(Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(idx) {
        return Ok(v
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    if let Ok(v) = row.try_get::<Option<bool>, _>(idx) {
        return Ok(v.map(Value::Bool).unwrap_or(Value::Null));
    }
    if let Ok(v) = row.try_get::<Option<String>, _>(idx) {
        return Ok(v.map(Value::String).unwrap_or(Value::Null));
    }
    if let Ok(v) = row.try_get::<Option<Vec<u8>>, _>(idx) {
        return Ok(match v {
            Some(bytes) => {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                serde_json::json!({ "base64": b64 })
            }
            None => Value::Null,
        });
    }
    Err("no decode path matched".into())
}

// ---------------------------------------------------------------------------
// cancel tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ExecCtx;
    use crate::in_flight::{InFlightGuard, InFlightRegistry};
    use crate::params::PreparedStmt;
    use crate::session::SessionVars;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Build a fresh in-memory SQLite pool tagged by the test name so
    /// the shared-cache database is isolated per test.
    async fn pool_for(tag: &str) -> (SqliteDriver, PoolHandle) {
        let driver = SqliteDriver::new();
        let cfg = ConnectCfg {
            url: format!("sqlite:file:cancel_{tag}?mode=memory&cache=shared"),
            max_connections: 4,
            min_idle: 0,
            acquire_timeout_ms: 5_000,
            idle_timeout_ms: 60_000,
            max_lifetime_ms: 300_000,
            test_before_acquire: false,
            statement_timeout_ms: None,
            auth_provider: None,
        };
        let outcome = driver.connect(&cfg).await.expect("connect");
        (driver, outcome.pool)
    }

    /// Recursive CTE that counts to 1B. SQLite's vdbe loop calls the
    /// progress handler between steps, so a cancel raises a
    /// SQLITE_INTERRUPT error promptly.
    const SLOW_QUERY: &str = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1000000000) \
         SELECT count(*) FROM n";

    fn sqlite_pool(pool: &PoolHandle) -> &sqlx::SqlitePool {
        match pool {
            PoolHandle::Sqlite(p) => p,
            #[allow(unreachable_patterns)]
            _ => unreachable!("an sqlite pool"),
        }
    }

    /// A cancel after the query is registered and before its statement
    /// starts still ends the statement: `sqlite3_interrupt` would be
    /// cleared when the statement starts, the query's flag is not. The
    /// handler it leaves on the connection, once the query has ended,
    /// stops no later statement there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancel_before_the_statement_starts_still_ends_it() {
        let (driver, pool) = pool_for("early").await;
        let mut conn = sqlite_pool(&pool).acquire().await.expect("acquire");
        let running = driver.start(&mut conn).await.expect("start");
        driver
            .cancel_backend(
                &pool,
                BackendId::Sqlite {
                    handle: running.nonce,
                },
            )
            .await
            .expect("cancel");

        let res = tokio::time::timeout(
            Duration::from_secs(30),
            sqlx::query(SLOW_QUERY).fetch_all(&mut *conn),
        )
        .await
        .expect("the cancelled statement ends instead of counting on");
        let Err(err) = res else {
            panic!("the cancelled statement returned rows");
        };
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("interrupt"), "got: {msg}");

        drop(running);
        assert!(driver.handles.is_empty(), "an ended query leaves the table");
        let one: i64 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .expect("a later statement on the connection runs");
        assert_eq!(one, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_interrupts_running_query() {
        let (driver, pool) = pool_for("interrupt").await;
        let driver = Arc::new(driver);
        let pool = Arc::new(pool);
        let registry = Arc::new(InFlightRegistry::new());
        let request_id = "req-cancel-1";

        // Pre-register the in-flight entry so set_backend_id has a
        // place to land. The gateway runtime normally registers via
        // InFlightGuard::register; tests do the same to keep the
        // production code path under test.
        let _guard = InFlightGuard::register(
            Arc::clone(&registry),
            request_id.into(),
            "cancel-test".into(),
            crate::config::DriverKind::Sqlite,
        );

        let stmt = PreparedStmt {
            sql: SLOW_QUERY.into(),
            param_order: vec![],
            driver: crate::config::DriverKind::Sqlite,
        };

        // Spawn the long query.
        let q_driver = Arc::clone(&driver);
        let q_pool = Arc::clone(&pool);
        let q_registry = Arc::clone(&registry);
        let session = SessionVars::default();
        let query_handle = tokio::spawn(async move {
            let ctx = ExecCtx {
                request_id: Some(request_id),
                in_flight: Some(&*q_registry),
            };
            q_driver
                .execute_with_ctx(&q_pool, &stmt, &[], &session, ctx)
                .await
        });

        // Wait for the registry to receive the backend id (means the
        // driver has captured the handle and is in the query loop).
        let backend_id = wait_for_backend_id(&registry, request_id, Duration::from_secs(10))
            .await
            .expect("driver should publish BackendId within 10s");

        // Cancel from this task. Time the round-trip — must complete
        // well before the query's natural deadline. The bounds are
        // sized for HEAVILY saturated CI runners (2s/1.5s and then
        // 15s/10s both flaked when the shard host ran several builds
        // at once); SLOW_QUERY counts to 1e9 and runs for minutes
        // uncancelled, so 45s still unambiguously proves the
        // interrupt did the work.
        let started = Instant::now();
        driver
            .cancel_backend(&pool, backend_id)
            .await
            .expect("cancel must succeed");

        let res = tokio::time::timeout(Duration::from_secs(60), query_handle)
            .await
            .expect("query should resolve after cancel within 60s")
            .expect("join");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(45),
            "cancel-to-error round trip took {elapsed:?}, expected < 10s"
        );

        // The driver surfaces the interrupt as a transport-class
        // SqlError. Match on the stringified message rather than a
        // sqlx-specific variant so we stay decoupled from sqlx
        // internals.
        let err = res.expect_err("interrupt must surface as Err");
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("interrupt") || msg.contains("interrupted"),
            "expected SQLITE_INTERRUPT-style message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn cancel_with_unknown_handle_is_noop() {
        let (driver, pool) = pool_for("unknown").await;
        // Nothing is registered — cancel should observe an empty
        // table and return Ok without panicking or erroring.
        let result = driver
            .cancel_backend(&pool, BackendId::Sqlite { handle: 999_999 })
            .await;
        assert!(result.is_ok(), "cancel against unknown handle is a no-op");
    }

    #[tokio::test]
    async fn cancel_with_wrong_backend_kind_returns_invalid_spec() {
        let (driver, pool) = pool_for("wrong_kind").await;
        let result = driver
            .cancel_backend(&pool, BackendId::Postgres { pid: 4242 })
            .await;
        match result {
            Err(SqlError::InvalidSpec(msg)) => {
                assert!(
                    msg.contains("Sqlite") || msg.contains("Postgres"),
                    "error should name the mismatched kinds, got: {msg}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Poll the registry until the entry has a backend id. Returns
    /// the id, or `None` on timeout.
    async fn wait_for_backend_id(
        registry: &InFlightRegistry,
        request_id: &str,
        deadline: Duration,
    ) -> Option<BackendId> {
        let started = Instant::now();
        loop {
            if let Some(id) = registry.backend_id_for(request_id) {
                return Some(id);
            }
            if started.elapsed() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
