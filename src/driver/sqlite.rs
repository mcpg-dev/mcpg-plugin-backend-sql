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
//! cancel. The runtime cancel path uses the FFI `sqlite3_interrupt`
//! call, which is one of the few SQLite C APIs that is documented as
//! safe to invoke from a different thread than the one currently
//! running the query. The driver:
//!
//! 1. On `execute_with_ctx`, captures the raw `*mut sqlite3` handle
//!    from sqlx's `LockedSqliteHandle::as_raw_handle()`, stores it
//!    (as `usize` for `Send`-ability) in a per-driver side-table
//!    keyed by a fresh `u64` nonce, and registers the nonce on the
//!    in-flight registry as `BackendId::Sqlite { handle }`.
//! 2. The query runs on the same pinned connection that owned the
//!    handle. The pointer is valid for that connection's lifetime.
//! 3. `cancel_backend` looks up the nonce, loads the atomic ptr, and
//!    calls `libsqlite3_sys::sqlite3_interrupt` if non-null.
//! 4. On any exit path (success or error) the executing future
//!    zeroes the atomic ptr and drops the table entry — concurrent
//!    cancels racing the cleanup harmlessly observe a null pointer.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// SQLite driver. Holds the in-flight handle table that
/// `cancel_backend` consults to issue `sqlite3_interrupt` against the
/// matching connection.
pub struct SqliteDriver {
    /// Nonce → atomic raw `*mut sqlite3` (as `usize`). Insert on
    /// query start, zero + remove on query exit. `cancel_backend`
    /// loads-and-checks-non-null under no extra lock.
    handles: Arc<DashMap<u64, Arc<AtomicUsize>>>,
    /// Monotonically increasing handle id source. Wraps; collisions
    /// over `u64` are not a real risk.
    next_handle: AtomicU64,
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

    /// Register a connection's raw sqlite3 pointer in the cancel
    /// table. Returns `(nonce, slot)` — the slot is held by the
    /// caller and zeroed on query exit so a racing cancel sees null.
    fn register_handle(&self, raw_ptr: usize) -> (u64, Arc<AtomicUsize>) {
        let nonce = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let slot = Arc::new(AtomicUsize::new(raw_ptr));
        self.handles.insert(nonce, Arc::clone(&slot));
        (nonce, slot)
    }

    /// Drop the handle entry. The slot is zeroed first so any racing
    /// cancel that loaded the Arc but hasn't checked yet sees a null
    /// pointer rather than dereferencing a stale handle.
    fn release_handle(&self, nonce: u64, slot: &Arc<AtomicUsize>) {
        slot.store(0, Ordering::Release);
        self.handles.remove(&nonce);
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
        // Pin one connection; the captured raw pointer is valid for
        // its lifetime. Without pinning, a parallel cancel might
        // target the wrong connection.
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        let raw_ptr = capture_raw_handle(&mut conn).await?;
        let (nonce, slot) = self.register_handle(raw_ptr);
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(rid, BackendId::Sqlite { handle: nonce });
        }

        // Run on the pinned connection. A concurrent
        // `cancel_backend` call can fire from another task here and
        // raise SQLITE_INTERRUPT, which sqlx surfaces as an error
        // we map through `from_execute`.
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_sqlite(q, &arg.value);
        }
        let rows_result = q
            .fetch_all(&mut *conn)
            .await
            .map_err(SqlError::from_execute);

        // Always clear the slot before returning — even on Err — so
        // a stale cancel never reaches a freed handle.
        self.release_handle(nonce, &slot);
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
        let raw_ptr = capture_raw_handle(&mut conn).await?;
        let (nonce, slot) = self.register_handle(raw_ptr);
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(rid, BackendId::Sqlite { handle: nonce });
        }

        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_sqlite(q, &arg.value);
        }
        let result = q.execute(&mut *conn).await.map_err(SqlError::from_execute);
        self.release_handle(nonce, &slot);
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
        // Look up the slot. Cloning the Arc out releases the dashmap
        // shard lock immediately so the cleanup path can proceed.
        let Some(slot) = self.handles.get(&nonce).map(|e| e.value().clone()) else {
            // Already cleaned up — the query finished between when
            // the caller observed the BackendId and when we got
            // here. No-op is the correct response.
            return Ok(());
        };
        let raw = slot.load(Ordering::Acquire);
        if raw == 0 {
            // Cleanup beat us to it (zeroed by `release_handle`).
            return Ok(());
        }
        // SAFETY: `sqlite3_interrupt` is documented as one of the
        // few SQLite C APIs safe to call from any thread regardless
        // of which thread holds the connection's lock. The pointer
        // remains valid as long as the slot's atomic content is
        // non-zero — `release_handle` zeros it before dropping the
        // map entry, so any non-zero load means the pinned
        // connection is still live.
        #[allow(unsafe_code)]
        unsafe {
            libsqlite3_sys::sqlite3_interrupt(raw as *mut libsqlite3_sys::sqlite3);
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

/// Lock the connection long enough to read its raw `sqlite3*`
/// pointer, then release the lock. The raw pointer remains valid as
/// long as the connection is alive — sqlx does not invalidate it on
/// ordinary use, only on connection drop.
async fn capture_raw_handle(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
) -> Result<usize, SqlError> {
    let mut handle = conn.lock_handle().await.map_err(SqlError::from_execute)?;
    let raw = handle.as_raw_handle().as_ptr() as usize;
    Ok(raw)
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

    /// Recursive CTE that counts to 1B. SQLite's vdbe loop checks
    /// `sqlite3_interrupt` between steps so the cancel raises a
    /// SQLITE_INTERRUPT error promptly.
    const SLOW_QUERY: &str = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1000000000) \
         SELECT count(*) FROM n";

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
