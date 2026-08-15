//! MySQL / MariaDB driver adapter.
//!
//! Both engines share sqlx's `MySql` driver. The MariaDB URL scheme
//! (`mariadb://`) is accepted by [`super::super::config::SqlBackendConfig::validate`]
//! and normalized to this driver.

use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use serde_json::{Map, Value};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow};
use sqlx::{Column, Either, Executor, Row, TypeInfo};

use crate::driver::{ConnectCfg, ConnectOutcome, ExecCtx, PoolHandle, RowBatch, SqlDriver};
use crate::errors::SqlError;
use crate::in_flight::BackendId;
use crate::params::{BoundParam, PreparedStmt};
use crate::session::SessionVars;

/// Zero-sized driver type that routes to sqlx's MySQL backend.
pub struct MysqlDriver;

#[async_trait]
impl SqlDriver for MysqlDriver {
    fn kind(&self) -> &'static str {
        "mysql"
    }

    async fn connect(&self, cfg: &ConnectCfg) -> Result<ConnectOutcome, SqlError> {
        // MySQL on RDS IAM is a follow-up. Config validate
        // already rejects `auth:` blocks on non-Postgres drivers; this
        // assertion is defense in depth.
        if cfg.auth_provider.is_some() {
            return Err(SqlError::InvalidSpec(
                "auth: { ... } block is not yet supported for MySQL/MariaDB".into(),
            ));
        }
        // Some operators write `mariadb://…` — rewrite the scheme to
        // `mysql://` for sqlx which only recognizes that form.
        let normalized = if let Some(rest) = cfg.url.strip_prefix("mariadb://") {
            format!("mysql://{rest}")
        } else {
            cfg.url.clone()
        };
        // `from_str` parses any embedded credentials out of the URL
        // directly; the plugin does not layer on a separate password.
        let opts = MySqlConnectOptions::from_str(&normalized)
            .map_err(|e| SqlError::InvalidSpec(format!("mysql url: {e}")))?;
        let pool = MySqlPoolOptions::new()
            .max_connections(cfg.max_connections)
            .min_connections(cfg.min_idle)
            .acquire_timeout(Duration::from_millis(cfg.acquire_timeout_ms))
            .idle_timeout(Some(Duration::from_millis(cfg.idle_timeout_ms)))
            .max_lifetime(Some(Duration::from_millis(cfg.max_lifetime_ms)))
            .test_before_acquire(cfg.test_before_acquire)
            // Force utf8mb4 wire encoding on every freshly
            // checked-out / re-used connection. `SET NAMES utf8mb4`
            // sets character_set_{client,results,connection} in one
            // statement; the collation defaults to the server's
            // default for utf8mb4 (utf8mb4_0900_ai_ci on MySQL 8+,
            // utf8mb4_general_ci on MySQL 5.7 / older MariaDB), which
            // is what we want — operators picking a non-default
            // collation can still override via session_vars on a
            // per-binding basis. utf8mb4 is the only MySQL charset
            // that handles the full Unicode plane (4-byte chars like
            // emoji and many CJK ideographs); without this, columns
            // declared `utf8mb3` (the legacy 3-byte alias) would
            // silently drop supplementary-plane characters.
            //
            // Why `after_connect` rather than via the URL `?charset=`
            // option: operators commonly bring their own URL string
            // (often pasted from a deploy template) and we want a
            // policy that doesn't rely on what's in there. Running
            // the SET unconditionally on every new pool connection
            // makes the policy robust regardless of URL hygiene.
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("SET NAMES utf8mb4").execute(conn).await?;
                    Ok(())
                })
            })
            .connect_with(opts)
            .await
            .map_err(SqlError::Connect)?;
        Ok(ConnectOutcome {
            pool: PoolHandle::Mysql(pool),
            rotator: None,
        })
    }

    async fn execute(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<RowBatch, SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql driver invoked with non-mysql pool handle".into(),
                ));
            }
        };

        // Fast path: no session_vars → direct execute against the
        // pool, one round-trip.
        if session.is_empty() {
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_mysql(q, &arg.value);
            }
            let rows = q.fetch_all(pool).await.map_err(SqlError::from_execute)?;
            let columns = rows
                .first()
                .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                .unwrap_or_default();
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                out.push(row_to_json_mysql(row)?);
            }
            return Ok(RowBatch {
                columns,
                rows: out,
                rows_affected: None,
                truncated: false,
                has_more: false,
            });
        }

        // Slow path: pin one connection, set session @user_vars on it,
        // run the statement on the same conn, then null the @vars
        // before the conn returns to the pool. MySQL @user variables
        // are connection-local and outlive transactions, so explicit
        // teardown is required to keep them from leaking to the next
        // pooled checkout. Identifier safety was validated at config
        // parse time (`config::is_safe_sql_identifier` plus the
        // MySQL-only "no dots" rule) so the keys are safe to
        // inline into the SET statement.
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        for (k, v) in session.values.iter() {
            sqlx::query(&format!("SET @{k} = ?"))
                .bind(v)
                .execute(&mut *conn)
                .await
                .map_err(SqlError::from_execute)?;
        }
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_mysql(q, &arg.value);
        }
        let exec_result = q.fetch_all(&mut *conn).await;
        // Always null the @vars even if the main query failed — the
        // teardown must run before the conn goes back to the pool.
        for k in session.values.keys() {
            let _ = sqlx::query(&format!("SET @{k} = NULL"))
                .execute(&mut *conn)
                .await;
        }
        let rows = exec_result.map_err(SqlError::from_execute)?;
        let columns = rows
            .first()
            .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_json_mysql(row)?);
        }
        Ok(RowBatch {
            columns,
            rows: out,
            rows_affected: None,
            truncated: false,
            has_more: false,
        })
    }

    async fn execute_affected(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<u64, SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql driver invoked with non-mysql pool handle".into(),
                ));
            }
        };

        if session.is_empty() {
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_mysql(q, &arg.value);
            }
            let result = q.execute(pool).await.map_err(SqlError::from_execute)?;
            return Ok(result.rows_affected());
        }

        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        for (k, v) in session.values.iter() {
            sqlx::query(&format!("SET @{k} = ?"))
                .bind(v)
                .execute(&mut *conn)
                .await
                .map_err(SqlError::from_execute)?;
        }
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_mysql(q, &arg.value);
        }
        let exec_result = q.execute(&mut *conn).await;
        for k in session.values.keys() {
            let _ = sqlx::query(&format!("SET @{k} = NULL"))
                .execute(&mut *conn)
                .await;
        }
        let result = exec_result.map_err(SqlError::from_execute)?;
        Ok(result.rows_affected())
    }

    /// PID-capturing execute path. Mirrors the Postgres
    /// implementation: pin one pool connection, capture
    /// `CONNECTION_ID()` on it, populate the in-flight registry,
    /// then run the main query on the same connection so the id
    /// identifies the backend actually executing.
    ///
    /// Applies session_vars on the same pinned connection
    /// before the main query, then nulls them before returning the
    /// connection to the pool. The pinning needed for cancel
    /// tracking doubles as the right connection scope for @user
    /// variables (which are connection-local on MySQL and outlive
    /// transactions).
    async fn execute_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
        ctx: ExecCtx<'_>,
    ) -> Result<RowBatch, SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql driver invoked with non-mysql pool handle".into(),
                ));
            }
        };
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        let conn_id: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *conn)
            .await
            .map_err(SqlError::from_execute)?;
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(
                rid,
                BackendId::Mysql {
                    connection_id: conn_id,
                },
            );
        }
        for (k, v) in session.values.iter() {
            sqlx::query(&format!("SET @{k} = ?"))
                .bind(v)
                .execute(&mut *conn)
                .await
                .map_err(SqlError::from_execute)?;
        }
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_mysql(q, &arg.value);
        }
        let exec_result = q.fetch_all(&mut *conn).await;
        for k in session.values.keys() {
            let _ = sqlx::query(&format!("SET @{k} = NULL"))
                .execute(&mut *conn)
                .await;
        }
        let rows = exec_result.map_err(SqlError::from_execute)?;
        let columns = rows
            .first()
            .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_json_mysql(row)?);
        }
        Ok(RowBatch {
            columns,
            rows: out,
            rows_affected: None,
            truncated: false,
            has_more: false,
        })
    }

    async fn execute_affected_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
        ctx: ExecCtx<'_>,
    ) -> Result<u64, SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql driver invoked with non-mysql pool handle".into(),
                ));
            }
        };
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        let conn_id: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *conn)
            .await
            .map_err(SqlError::from_execute)?;
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(
                rid,
                BackendId::Mysql {
                    connection_id: conn_id,
                },
            );
        }
        for (k, v) in session.values.iter() {
            sqlx::query(&format!("SET @{k} = ?"))
                .bind(v)
                .execute(&mut *conn)
                .await
                .map_err(SqlError::from_execute)?;
        }
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_mysql(q, &arg.value);
        }
        let exec_result = q.execute(&mut *conn).await;
        for k in session.values.keys() {
            let _ = sqlx::query(&format!("SET @{k} = NULL"))
                .execute(&mut *conn)
                .await;
        }
        let result = exec_result.map_err(SqlError::from_execute)?;
        Ok(result.rows_affected())
    }

    /// Multi-result-set execute. MySQL stored procedures can
    /// emit multiple SELECT result sets per `CALL`; sqlx's
    /// `fetch_many()` surfaces those boundaries as
    /// `Either::Left(QueryResult)` interleaved between row items
    /// (`Either::Right(Row)`). Walk the stream, group rows that
    /// arrive between consecutive boundaries into separate sets, and
    /// drop empty trailing sets the server may emit for the final
    /// `OK` packet.
    ///
    /// Session vars apply on the same pinned connection just like
    /// the regular execute paths — a procedure that reads `@user`
    /// vars (e.g. `tenant_id` for row-level filtering) gets them.
    async fn execute_multi_result(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<Vec<Vec<Value>>, SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql driver invoked with non-mysql pool handle".into(),
                ));
            }
        };
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        for (k, v) in session.values.iter() {
            sqlx::query(&format!("SET @{k} = ?"))
                .bind(v)
                .execute(&mut *conn)
                .await
                .map_err(SqlError::from_execute)?;
        }

        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_mysql(q, &arg.value);
        }
        let mut sets: Vec<Vec<Value>> = Vec::new();
        let mut current: Vec<Value> = Vec::new();
        // `fetch_many` returns a stream of `Either<QueryResult, Row>`.
        // A `Left` marks the end of a result set (or the final
        // statement OK on a write); when we have rows pending, we
        // commit them as a finished set and start a fresh buffer.
        let stream_result: Result<(), SqlError> = async {
            let mut stream = (&mut *conn).fetch_many(q);
            while let Some(item) = stream.try_next().await.map_err(SqlError::from_execute)? {
                match item {
                    Either::Right(row) => {
                        current.push(row_to_json_mysql(&row)?);
                    }
                    Either::Left(_qr) => {
                        // Boundary between result sets. Stash any
                        // collected rows; ignore boundaries that
                        // close empty buffers (those mark CALL's
                        // statement-OK terminator after the rows
                        // were already sealed).
                        if !current.is_empty() {
                            sets.push(std::mem::take(&mut current));
                        }
                    }
                }
            }
            Ok(())
        }
        .await;
        // Drain any rows that arrived without a trailing boundary.
        if !current.is_empty() {
            sets.push(current);
        }
        for k in session.values.keys() {
            let _ = sqlx::query(&format!("SET @{k} = NULL"))
                .execute(&mut *conn)
                .await;
        }
        stream_result?;
        Ok(sets)
    }

    /// Cancel a MySQL backend via `KILL QUERY <id>` on a side
    /// connection. Unlike Postgres's `pg_cancel_backend` — which
    /// is strictly scoped to interrupting the currently-executing
    /// statement — MySQL's `KILL QUERY` terminates the in-flight
    /// query but leaves the connection usable for the next
    /// request. Requires the authenticated user to hold the MySQL
    /// `PROCESS` (or `CONNECTION_ADMIN`) privilege on recent
    /// MySQL versions. Operators whose pool role lacks that
    /// privilege get a transport error on cancel and the query
    /// proceeds to natural completion.
    async fn cancel_backend(
        &self,
        pool: &PoolHandle,
        backend_id: BackendId,
    ) -> Result<(), SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql cancel_backend invoked with non-mysql pool handle".into(),
                ));
            }
        };
        let connection_id = match backend_id {
            BackendId::Mysql { connection_id } => connection_id,
            other => {
                return Err(SqlError::InvalidSpec(format!(
                    "mysql cancel_backend: expected MySQL backend id, got {other:?}"
                )));
            }
        };
        // `KILL QUERY` takes an integer literal — sqlx binds the
        // value as a SQL expression regardless of prepared-stmt
        // machinery. Using `format!` here is safe because
        // `connection_id` is a `u64` we captured ourselves, not
        // operator or caller input.
        sqlx::query(&format!("KILL QUERY {connection_id}"))
            .execute(pool)
            .await
            .map_err(SqlError::from_execute)?;
        Ok(())
    }

    async fn health_check(&self, pool: &PoolHandle) -> Result<(), SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql health_check invoked with non-mysql pool handle".into(),
                ));
            }
        };
        sqlx::query("SELECT 1")
            .fetch_one(pool)
            .await
            .map(|_| ())
            .map_err(SqlError::from_execute)
    }

    /// Verify the pool user holds a grant that lets `KILL QUERY`
    /// terminate another connection's in-flight statement. MySQL
    /// 5.x accepts the global `PROCESS` privilege; MySQL 8+ also
    /// accepts the dynamic `CONNECTION_ADMIN` role. `ALL PRIVILEGES`
    /// (or `GRANT ALL ON *.*`) implies both. Without one of these,
    /// `cancel_request` raises an `Access denied` error and cancellation
    /// silently degrades to a no-op — the operator only finds out under
    /// load. Probe at registration so the failure mode surfaces at
    /// startup instead.
    async fn verify_cancel_privilege(&self, pool: &PoolHandle) -> Result<(), SqlError> {
        let pool = match pool {
            PoolHandle::Mysql(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "mysql verify_cancel_privilege invoked with non-mysql pool handle".into(),
                ));
            }
        };

        let grants: Vec<(String,)> = sqlx::query_as("SHOW GRANTS FOR CURRENT_USER")
            .fetch_all(pool)
            .await
            .map_err(SqlError::from_execute)?;

        if grants.iter().any(|(line,)| grant_line_implies_kill(line)) {
            return Ok(());
        }

        Err(SqlError::InvalidSpec(format!(
            "MySQL pool user lacks the PROCESS / CONNECTION_ADMIN privilege required \
             to cancel another connection's in-flight statement (KILL QUERY). \
             Grant one of these — `GRANT PROCESS ON *.* TO <user>@<host>` (MySQL 5.7+) \
             or `GRANT CONNECTION_ADMIN ON *.* TO <user>@<host>` (MySQL 8+) — or set \
             `pool.require_cancel_privilege: false` if cancel-on-timeout becoming a \
             no-op is intentional. Reported grants: {:?}",
            grants.into_iter().map(|(s,)| s).collect::<Vec<_>>()
        )))
    }
}

/// Return true when the GRANT line announces a privilege that lets
/// the holder run `KILL QUERY` against another connection. Match is
/// uppercased and tokenises the privilege list between `GRANT` and
/// `ON …` so we don't false-positive on a database / table named
/// `process` or a column called `connection_admin`.
fn grant_line_implies_kill(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    // MySQL emits each grant as `GRANT <priv>[, <priv>…] ON <scope> TO …`.
    // Slice out the privilege list portion.
    let priv_list = match upper.split_once(" ON ") {
        Some((before, _)) => before,
        None => upper.as_str(),
    };
    let priv_list = priv_list.trim_start_matches("GRANT").trim();

    // Split on commas and trim each entry to its canonical privilege
    // form. Multi-word tokens (`ALL PRIVILEGES`) survive because we
    // don't split on whitespace.
    priv_list
        .split(',')
        .map(|s| s.trim())
        .any(|tok| matches!(tok, "PROCESS" | "CONNECTION_ADMIN" | "ALL PRIVILEGES"))
}

/// Bind one JSON scalar to a MySQL prepared-statement argument.
pub(crate) fn bind_mysql<'q>(
    q: sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>,
    v: &'q Value,
) -> sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments> {
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
        Value::Array(_) | Value::Object(_) => q.bind(v.clone()),
    }
}

/// Decode a MySQL row into a JSON object keyed by column name.
pub(crate) fn row_to_json_mysql(row: &MySqlRow) -> Result<Value, SqlError> {
    let mut obj = Map::with_capacity(row.columns().len());
    for (i, col) in row.columns().iter().enumerate() {
        let name = col.name().to_string();
        let type_name = col.type_info().name();
        let value = decode_mysql_column(row, i, type_name).unwrap_or_else(|e| {
            tracing::warn!(
                column = %name,
                type = %type_name,
                error = %e,
                "mysql: column decode failed, emitting null"
            );
            Value::Null
        });
        obj.insert(name, value);
    }
    Ok(Value::Object(obj))
}

/// Best-effort decode of a MySQL column value.
fn decode_mysql_column(row: &MySqlRow, idx: usize, type_name: &str) -> Result<Value, String> {
    let upper = type_name.to_ascii_uppercase();
    let is_boolean = upper.contains("BOOLEAN") || upper == "TINYINT(1)";
    if is_boolean && let Ok(v) = row.try_get::<Option<bool>, _>(idx) {
        return Ok(v.map(Value::Bool).unwrap_or(Value::Null));
    }
    let is_integer = upper.starts_with("INT")
        || upper.starts_with("TINYINT")
        || upper.starts_with("SMALLINT")
        || upper.starts_with("MEDIUMINT")
        || upper.starts_with("BIGINT");
    if is_integer && let Ok(v) = row.try_get::<Option<i64>, _>(idx) {
        return Ok(v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null));
    }
    let is_float = upper == "FLOAT" || upper == "DOUBLE";
    if is_float && let Ok(v) = row.try_get::<Option<f64>, _>(idx) {
        return Ok(v
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    // NUMERIC / DECIMAL: emit as JSON string to preserve MySQL's
    // arbitrary-precision representation. See the Postgres
    // decoder for full rationale.
    let is_decimal = upper == "NUMERIC" || upper == "DECIMAL" || upper == "NEWDECIMAL";
    if is_decimal && let Ok(v) = row.try_get::<Option<rust_decimal::Decimal>, _>(idx) {
        return Ok(v
            .map(|d| Value::String(d.to_string()))
            .unwrap_or(Value::Null));
    }
    // JSON inlining contract. MySQL's `JSON` storage type
    // round-trips through sqlx's `Value` decoder as a structurally
    // inlined object/array/scalar, NOT a string-wrapped re-encoding.
    // The integration tests in `tests/mysql_basic.rs` pin this — do
    // NOT change to `Value::String(v.to_string())` under any
    // refactor, since that re-introduces the double-encoding bug.
    if upper == "JSON"
        && let Ok(v) = row.try_get::<Option<Value>, _>(idx)
    {
        return Ok(v.unwrap_or(Value::Null));
    }
    // DATETIME / TIMESTAMP. `%.6f` (always-6-digit fractional
    // seconds) gives stable microsecond-width output across rows.
    // MySQL's TIMESTAMP and DATETIME both support up to 6 digits of
    // fractional precision (`TIMESTAMP(6)`, `DATETIME(6)`). For
    // tables declared at a lower precision (e.g. `TIMESTAMP(3)`),
    // the trailing positions render as zeros — which is correct, the
    // value really does have zero-precision in those positions.
    let is_datetime = upper == "DATETIME" || upper == "TIMESTAMP";
    if is_datetime && let Ok(v) = row.try_get::<Option<chrono::NaiveDateTime>, _>(idx) {
        return Ok(v
            .map(|t| Value::String(t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()))
            .unwrap_or(Value::Null));
    }
    if upper == "DATE"
        && let Ok(v) = row.try_get::<Option<chrono::NaiveDate>, _>(idx)
    {
        return Ok(v
            .map(|d| Value::String(d.to_string()))
            .unwrap_or(Value::Null));
    }
    // TIME. MySQL's TIME range is `-838:59:59` to `838:59:59`
    // (a *duration*, not a wall-clock time), which `chrono::NaiveTime`
    // can't represent. The cleanest path: read whatever string MySQL
    // sends over the wire (`HH:MM:SS[.ffffff]` with optional leading
    // minus). The fractional precision on the wire matches the column
    // declaration (`TIME(6)` → 6 digits).
    if upper.starts_with("TIME")
        && upper != "TIMESTAMP"
        && upper != "DATETIME"
        && let Ok(v) = row.try_get::<Option<String>, _>(idx)
    {
        return Ok(v.map(Value::String).unwrap_or(Value::Null));
    }
    let is_binary = upper.contains("BLOB") || upper.contains("BINARY");
    if is_binary && let Ok(v) = row.try_get::<Option<Vec<u8>>, _>(idx) {
        return Ok(match v {
            Some(bytes) => {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                serde_json::json!({ "base64": b64 })
            }
            None => Value::Null,
        });
    }
    match row.try_get::<Option<String>, _>(idx) {
        Ok(Some(s)) => Ok(Value::String(s)),
        Ok(None) => Ok(Value::Null),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::grant_line_implies_kill;

    #[test]
    fn process_grant_implies_kill() {
        assert!(grant_line_implies_kill(
            "GRANT PROCESS ON *.* TO `mcpg`@`%`"
        ));
    }

    #[test]
    fn connection_admin_grant_implies_kill() {
        assert!(grant_line_implies_kill(
            "GRANT CONNECTION_ADMIN ON *.* TO `mcpg`@`%`"
        ));
    }

    #[test]
    fn all_privileges_implies_kill() {
        assert!(grant_line_implies_kill(
            "GRANT ALL PRIVILEGES ON *.* TO `mcpg`@`%`"
        ));
    }

    #[test]
    fn select_only_does_not_imply_kill() {
        assert!(!grant_line_implies_kill(
            "GRANT SELECT, INSERT, UPDATE ON `mcpg_test`.* TO `mcpg`@`%`"
        ));
    }

    #[test]
    fn process_alongside_other_grants() {
        assert!(grant_line_implies_kill(
            "GRANT SELECT, PROCESS, INSERT ON *.* TO `mcpg`@`%`"
        ));
        assert!(grant_line_implies_kill(
            "GRANT PROCESS,SELECT ON *.* TO `mcpg`@`%`"
        ));
    }

    #[test]
    fn database_named_process_does_not_false_positive() {
        // A DB literally called `process` should not satisfy the probe.
        assert!(!grant_line_implies_kill(
            "GRANT SELECT ON `process`.* TO `mcpg`@`%`"
        ));
    }

    #[test]
    fn lowercase_grant_is_uppercased_first() {
        // MySQL always emits uppercase, but be defensive against
        // someone feeding us a hand-crafted grant string.
        assert!(grant_line_implies_kill(
            "grant process on *.* to `mcpg`@`%`"
        ));
    }

    #[test]
    fn usage_grant_does_not_imply_kill() {
        // `USAGE` is the placeholder MySQL returns when a user has
        // no privileges (just the ability to connect).
        assert!(!grant_line_implies_kill("GRANT USAGE ON *.* TO `mcpg`@`%`"));
    }

    #[test]
    fn process_substring_in_other_priv_does_not_match() {
        // No real MySQL privilege contains "PROCESS" as a substring,
        // but defend against future renames.
        assert!(!grant_line_implies_kill(
            "GRANT POSTPROCESS_FOO ON *.* TO `mcpg`@`%`"
        ));
    }
}
