//! PostgreSQL driver adapter.
//!
//! Uses `sqlx::Pool<Postgres>` directly. Parameter values are bound as
//! JSON scalars; rows are decoded to JSON via the
//! `serde_json::Value` decode path that the `sqlx/json` feature
//! provides, with a fallback for non-JSON columns that go through
//! the `sqlx` column-by-column decode helpers.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Map, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::{Acquire, Column, Row, TypeInfo};

use crate::driver::{ConnectCfg, ConnectOutcome, ExecCtx, PoolHandle, RowBatch, SqlDriver};
use crate::errors::SqlError;
use crate::in_flight::BackendId;
use crate::params::{BoundParam, PreparedStmt};
use crate::session::SessionVars;

/// Zero-sized driver type that routes to sqlx's Postgres backend.
pub struct PostgresDriver;

#[async_trait]
impl SqlDriver for PostgresDriver {
    fn kind(&self) -> &'static str {
        "postgres"
    }

    async fn connect(&self, cfg: &ConnectCfg) -> Result<ConnectOutcome, SqlError> {
        // `from_str` parses any embedded credentials out of the URL
        // directly; the plugin does not layer on a separate password.
        let mut opts = PgConnectOptions::from_str(&cfg.url)
            .map_err(|e| SqlError::InvalidSpec(format!("postgres url: {e}")))?;
        // Force UTF-8 wire encoding on every pool connection.
        // The Postgres server may have been initdb'd with SQL_ASCII or
        // LATIN1 (legacy clusters); `client_encoding=UTF8` tells the
        // server to transcode rows to/from UTF-8 on the wire. Setting
        // it here means JSON serialization on the plugin side never
        // sees a non-UTF-8 byte sequence — the decoder's
        // `try_get::<String>` paths can rely on `from_utf8` succeeding
        // unconditionally. UTF-8 encoding is also the only encoding
        // that can carry every character `Value::String` admits, so
        // this prevents silent mojibake on multi-byte text columns.
        // INTERVAL + timestamp styles use the same connection options
        // channel: `IntervalStyle=iso_8601` makes the server canonicalize any
        // string-protocol INTERVAL output (used by the schema/describe
        // path, not the binary-protocol row decoder), and
        // `DateStyle=ISO,YMD` pins year-month-day ordering for any
        // legacy text-protocol timestamp parsing — `to_rfc3339()` on
        // chrono types already produces ISO 8601 from the binary
        // protocol so this is defense in depth on rare fallbacks.
        let mut conn_opts: Vec<(&'static str, String)> = vec![
            ("client_encoding", "UTF8".to_string()),
            ("DateStyle", "ISO,YMD".to_string()),
            ("IntervalStyle", "iso_8601".to_string()),
        ];
        // Server-side statement_timeout as a startup option on every
        // pool connection. Works in tandem with the
        // tokio::time::timeout in the plugin layer: the tokio timeout
        // cuts off the await client-side; statement_timeout tells
        // Postgres to stop doing work server-side. Either fires first;
        // both together avoid leaking DB CPU when a slow query is
        // abandoned.
        if let Some(ms) = cfg.statement_timeout_ms {
            conn_opts.push(("statement_timeout", format!("{ms}ms")));
        }
        opts = opts.options(conn_opts);

        // Cloud-auth path. Fetch the initial token, swap
        // it in as the password, and tell the auth provider which
        // host:port these tokens are bound to so subsequent
        // refreshes presign against the same endpoint. Cap the
        // pool's `max_lifetime` to `token_ttl - safety_margin` so
        // no live connection outlives its token.
        let rotator_cfg = crate::auth::rotator::RotatorConfig::default();
        let mut max_lifetime_ms = cfg.max_lifetime_ms;
        if let Some(provider) = &cfg.auth_provider {
            // Tell endpoint-aware providers (RDS IAM today; Aurora
            // failover when it lands) which host:port these tokens
            // authenticate against. The trait's default impl is a
            // no-op so endpoint-agnostic providers (Azure AD, GCP)
            // ignore it.
            let host = pg_host_from_url(&cfg.url).ok_or_else(|| {
                SqlError::InvalidSpec(format!(
                    "auth: {} — could not parse host out of `url`",
                    provider.scheme()
                ))
            })?;
            let port = pg_port_from_url(&cfg.url).unwrap_or(5432);
            provider
                .bind_endpoint(&host, port)
                .map_err(SqlError::from)?;
            let token = provider.fetch_token().await.map_err(SqlError::from)?;
            opts = opts.password(token.expose());
            // Cap the pool's max_lifetime so connections cycle
            // before the token they were authenticated with expires.
            // Operator's value wins only when it's stricter.
            if let Some(cap) = rotator_cfg.pool_max_lifetime_for(provider.token_ttl()) {
                let cap_ms = cap.as_millis() as u64;
                if max_lifetime_ms == 0 || cap_ms < max_lifetime_ms {
                    max_lifetime_ms = cap_ms;
                }
            }
        }

        let max_lifetime_opt = if max_lifetime_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(max_lifetime_ms))
        };
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .min_connections(cfg.min_idle)
            .acquire_timeout(Duration::from_millis(cfg.acquire_timeout_ms))
            .idle_timeout(Some(Duration::from_millis(cfg.idle_timeout_ms)))
            .max_lifetime(max_lifetime_opt)
            .test_before_acquire(cfg.test_before_acquire)
            .connect_with(opts.clone())
            .await
            .map_err(SqlError::Connect)?;

        // Spawn the rotator now that the pool is live + holding the
        // initial token. The closure captures `pool` (cheap clone of
        // the inner Arc) + `opts` and rebuilds the connect options
        // with each fresh token, then pushes them into the pool via
        // `set_connect_options`. Existing physical connections drain
        // at `max_lifetime`; new ones use the new password.
        let rotator = if let Some(provider) = &cfg.auth_provider {
            let pool_for_apply = pool.clone();
            let opts_template = opts;
            let apply = move |token: &crate::auth::SecretToken| {
                let pool = pool_for_apply.clone();
                let new_opts = opts_template.clone().password(token.expose());
                async move {
                    pool.set_connect_options(new_opts);
                    Ok(())
                }
            };
            Some(crate::auth::TokenRotator::spawn(
                Arc::clone(provider),
                apply,
                rotator_cfg,
            ))
        } else {
            None
        };

        Ok(ConnectOutcome {
            pool: PoolHandle::Postgres(pool),
            rotator,
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
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres driver invoked with non-postgres pool handle".into(),
                ));
            }
        };

        // Fast path: no session_vars → direct execute against pool,
        // one round trip.
        if session.is_empty() {
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_pg(q, &arg.value);
            }
            let rows = q.fetch_all(pool).await.map_err(SqlError::from_execute)?;
            let columns = rows
                .first()
                .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                .unwrap_or_default();
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                out.push(row_to_json_pg(row)?);
            }
            return Ok(RowBatch {
                columns,
                rows: out,
                rows_affected: None,
                truncated: false,
                has_more: false,
            });
        }

        // Session-vars path: wrap in a transaction and emit `SET LOCAL`
        // for each var so the assignment is scoped to this statement.
        // Identifier safety was validated at config parse time
        // (`config::is_safe_sql_identifier`); values are still bound
        // through sqlx, never interpolated.
        let mut tx = pool.begin().await.map_err(SqlError::from_execute)?;
        // `SET LOCAL <id> = $1` is rejected by Postgres — SET is a
        // utility command and doesn't accept bind parameters. Use the
        // `set_config(name, value, is_local)` function instead, which
        // is a regular SQL function and takes parameters normally.
        // `is_local = true` makes the assignment transaction-scoped
        // (equivalent to SET LOCAL).
        for (k, v) in session.values.iter() {
            sqlx::query("SELECT set_config($1, $2, true)")
                .bind(k)
                .bind(v)
                .execute(&mut *tx)
                .await
                .map_err(SqlError::from_execute)?;
        }

        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_pg(q, &arg.value);
        }
        let rows = q
            .fetch_all(&mut *tx)
            .await
            .map_err(SqlError::from_execute)?;

        let columns = rows
            .first()
            .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_json_pg(row)?);
        }

        tx.commit().await.map_err(SqlError::from_execute)?;

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
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres driver invoked with non-postgres pool handle".into(),
                ));
            }
        };

        if session.is_empty() {
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_pg(q, &arg.value);
            }
            let result = q.execute(pool).await.map_err(SqlError::from_execute)?;
            return Ok(result.rows_affected());
        }

        let mut tx = pool.begin().await.map_err(SqlError::from_execute)?;
        // `SET LOCAL <id> = $1` is rejected by Postgres — SET is a
        // utility command and doesn't accept bind parameters. Use the
        // `set_config(name, value, is_local)` function instead, which
        // is a regular SQL function and takes parameters normally.
        // `is_local = true` makes the assignment transaction-scoped
        // (equivalent to SET LOCAL).
        for (k, v) in session.values.iter() {
            sqlx::query("SELECT set_config($1, $2, true)")
                .bind(k)
                .bind(v)
                .execute(&mut *tx)
                .await
                .map_err(SqlError::from_execute)?;
        }
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_pg(q, &arg.value);
        }
        let result = q.execute(&mut *tx).await.map_err(SqlError::from_execute)?;
        tx.commit().await.map_err(SqlError::from_execute)?;
        Ok(result.rows_affected())
    }

    /// PID-capturing execute path. Acquires one pool
    /// connection, runs `SELECT pg_backend_pid()` on it, populates
    /// the in-flight registry, and then runs the main query on the
    /// *same* connection so the captured PID matches the backend
    /// actually executing. Without the pinning, a concurrent cancel
    /// would target a different backend and be a no-op.
    ///
    /// When `ctx.in_flight` or `ctx.request_id` is `None`, the
    /// method still pins the connection (harmless) and skips the
    /// registry update — useful for tests that don't care about
    /// cancel.
    async fn execute_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
        ctx: ExecCtx<'_>,
    ) -> Result<RowBatch, SqlError> {
        let pool = match pool {
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres driver invoked with non-postgres pool handle".into(),
                ));
            }
        };

        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;

        // Capture the backend PID on the pinned connection. Record
        // in the registry so the cancel side-channel can target it.
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await
            .map_err(SqlError::from_execute)?;
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(rid, BackendId::Postgres { pid });
        }

        // session_vars path: open a tx on the pinned connection so
        // SET LOCAL scoping works as before, but without acquiring
        // a second connection.
        if !session.is_empty() {
            let mut tx = conn.begin().await.map_err(SqlError::from_execute)?;
            for (k, v) in session.values.iter() {
                sqlx::query("SELECT set_config($1, $2, true)")
                    .bind(k)
                    .bind(v)
                    .execute(&mut *tx)
                    .await
                    .map_err(SqlError::from_execute)?;
            }
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_pg(q, &arg.value);
            }
            let rows = q
                .fetch_all(&mut *tx)
                .await
                .map_err(SqlError::from_execute)?;
            let columns = rows
                .first()
                .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                .unwrap_or_default();
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                out.push(row_to_json_pg(row)?);
            }
            tx.commit().await.map_err(SqlError::from_execute)?;
            return Ok(RowBatch {
                columns,
                rows: out,
                rows_affected: None,
                truncated: false,
                has_more: false,
            });
        }

        // Fast path: no session_vars.
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_pg(q, &arg.value);
        }
        let rows = q
            .fetch_all(&mut *conn)
            .await
            .map_err(SqlError::from_execute)?;
        let columns = rows
            .first()
            .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_json_pg(row)?);
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
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres driver invoked with non-postgres pool handle".into(),
                ));
            }
        };
        let mut conn = pool.acquire().await.map_err(SqlError::from_execute)?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await
            .map_err(SqlError::from_execute)?;
        if let (Some(registry), Some(rid)) = (ctx.in_flight, ctx.request_id) {
            registry.set_backend_id(rid, BackendId::Postgres { pid });
        }
        if !session.is_empty() {
            let mut tx = conn.begin().await.map_err(SqlError::from_execute)?;
            for (k, v) in session.values.iter() {
                sqlx::query("SELECT set_config($1, $2, true)")
                    .bind(k)
                    .bind(v)
                    .execute(&mut *tx)
                    .await
                    .map_err(SqlError::from_execute)?;
            }
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_pg(q, &arg.value);
            }
            let result = q.execute(&mut *tx).await.map_err(SqlError::from_execute)?;
            tx.commit().await.map_err(SqlError::from_execute)?;
            return Ok(result.rows_affected());
        }
        let mut q = sqlx::query(&stmt.sql);
        for arg in args {
            q = bind_pg(q, &arg.value);
        }
        let result = q
            .execute(&mut *conn)
            .await
            .map_err(SqlError::from_execute)?;
        Ok(result.rows_affected())
    }

    async fn cancel_backend(
        &self,
        pool: &PoolHandle,
        backend_id: BackendId,
    ) -> Result<(), SqlError> {
        let pool = match pool {
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres cancel_backend invoked with non-postgres pool handle".into(),
                ));
            }
        };
        let pid = match backend_id {
            BackendId::Postgres { pid } => pid,
            other => {
                return Err(SqlError::InvalidSpec(format!(
                    "postgres cancel_backend: expected Postgres backend id, got {other:?}"
                )));
            }
        };
        // `pg_cancel_backend` can be called from any connection; it
        // SIGINTs the target PID. A short-lived pool acquire is fine —
        // the signal is delivered by the server, not correlated to
        // the caller's connection.
        sqlx::query("SELECT pg_cancel_backend($1)")
            .bind(pid)
            .execute(pool)
            .await
            .map_err(SqlError::from_execute)?;
        Ok(())
    }

    async fn health_check(&self, pool: &PoolHandle) -> Result<(), SqlError> {
        let pool = match pool {
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres health_check invoked with non-postgres pool handle".into(),
                ));
            }
        };
        sqlx::query("SELECT 1")
            .fetch_one(pool)
            .await
            .map(|_| ())
            .map_err(SqlError::from_execute)
    }

    /// Postgres input-schema derivation. Uses sqlx's
    /// `Executor::describe` to obtain a `Vec<PgTypeInfo>` for the
    /// statement's placeholders, then delegates to
    /// [`crate::schema::input_schema_from_pg_params`] to map each
    /// type name onto a JSON Schema fragment.
    ///
    /// Returns `Ok(None)` when either the server returns no parameter
    /// info or `param_names.len()` does not match the parameter count
    /// — a safe fallback that lets the plugin defer to operator-
    /// supplied schema.
    async fn describe_parameters(
        &self,
        pool: &PoolHandle,
        sql: &str,
        param_names: &[String],
    ) -> Result<Option<serde_json::Value>, SqlError> {
        let pool = match pool {
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres describe_parameters invoked with non-postgres pool handle".into(),
                ));
            }
        };
        let described = sqlx::Executor::describe(pool, sql)
            .await
            .map_err(SqlError::from_execute)?;
        let Some(either) = described.parameters() else {
            return Ok(None);
        };
        let type_names: Vec<String> = match either {
            sqlx::Either::Left(pg_types) => pg_types.iter().map(|t| t.name().to_string()).collect(),
            sqlx::Either::Right(_) => return Ok(None),
        };
        Ok(crate::schema::input_schema_from_pg_params(
            param_names,
            &type_names,
        ))
    }

    async fn describe_columns(
        &self,
        pool: &PoolHandle,
        sql: &str,
        row_mode: crate::config::RowMode,
    ) -> Result<Option<serde_json::Value>, SqlError> {
        let pool = match pool {
            PoolHandle::Postgres(p) => p,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(SqlError::InvalidSpec(
                    "postgres describe_columns invoked with non-postgres pool handle".into(),
                ));
            }
        };
        let described = sqlx::Executor::describe(pool, sql)
            .await
            .map_err(SqlError::from_execute)?;
        let columns: Vec<crate::schema::OutputColumn> = described
            .columns
            .iter()
            .enumerate()
            .map(|(idx, col)| crate::schema::OutputColumn {
                name: col.name().to_string(),
                pg_type: col.type_info().name().to_string(),
                nullable: described.nullable(idx),
            })
            .collect();
        Ok(crate::schema::output_schema_from_pg_columns(
            &columns, row_mode,
        ))
    }
}

/// Bind one JSON scalar to a Postgres prepared-statement argument.
///
/// The coercion table is good enough for
/// common types; richer coverage (UUID format hints, base64 bytea) is
/// follow-on work. Unknown shapes fall back to a JSONB bind.
pub(crate) fn bind_pg<'q>(
    q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    v: &'q Value,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match v {
        Value::Null => q.bind(Option::<String>::None),
        Value::Bool(b) => q.bind(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                q.bind(i)
            } else if let Some(f) = n.as_f64() {
                q.bind(f)
            } else {
                // Arbitrary-precision integer outside i64 — fall back
                // to a string bind. Operator can cast on the DB side.
                q.bind(n.to_string())
            }
        }
        Value::String(s) => q.bind(s.clone()),
        // Arrays / objects bind as JSONB so they interop with Postgres
        // jsonb columns without bespoke handling.
        Value::Array(_) | Value::Object(_) => q.bind(v.clone()),
    }
}

/// Decode a Postgres row into a JSON object keyed by column name.
pub(crate) fn row_to_json_pg(row: &PgRow) -> Result<Value, SqlError> {
    let mut obj = Map::with_capacity(row.columns().len());
    for (i, col) in row.columns().iter().enumerate() {
        let name = col.name().to_string();
        let type_name = col.type_info().name();
        let value = decode_pg_column(row, i, type_name).unwrap_or_else(|e| {
            tracing::warn!(
                column = %name,
                type = %type_name,
                error = %e,
                "postgres: column decode failed, emitting null"
            );
            Value::Null
        });
        obj.insert(name, value);
    }
    Ok(Value::Object(obj))
}

/// Best-effort decode of a single Postgres column to a JSON value.
///
/// We try a short list of common types first. Anything unrecognized
/// attempts a string decode, then JSONB, then gives up and returns
/// null with a warning (handled by the caller).
fn decode_pg_column(row: &PgRow, idx: usize, type_name: &str) -> Result<Value, String> {
    // NULL check via option-based try_get first; if the column is
    // NULL, return JSON null regardless of declared type.
    if matches!(type_name, "BOOL" | "BOOLEAN") {
        return match row.try_get::<Option<bool>, _>(idx) {
            Ok(Some(v)) => Ok(Value::Bool(v)),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // Integer types must be decoded at their native width — sqlx is
    // strict, and decoding an INT4 as Option<i64> fails with a type
    // mismatch. Widen to i64 for JSON output after decode.
    if matches!(type_name, "INT2" | "SMALLINT") {
        return match row.try_get::<Option<i16>, _>(idx) {
            Ok(Some(v)) => Ok(Value::Number(i64::from(v).into())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    if matches!(type_name, "INT4" | "INTEGER") {
        return match row.try_get::<Option<i32>, _>(idx) {
            Ok(Some(v)) => Ok(Value::Number(i64::from(v).into())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    if matches!(type_name, "INT8" | "BIGINT") {
        return match row.try_get::<Option<i64>, _>(idx) {
            Ok(Some(v)) => Ok(Value::Number(v.into())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    if matches!(type_name, "FLOAT4" | "FLOAT8" | "REAL" | "DOUBLE PRECISION") {
        return match row.try_get::<Option<f64>, _>(idx) {
            Ok(Some(v)) => Ok(serde_json::Number::from_f64(v)
                .map(Value::Number)
                .unwrap_or(Value::Null)),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // NUMERIC / DECIMAL: decode as `rust_decimal::Decimal` and emit
    // a JSON string. Postgres NUMERIC is
    // arbitrary precision; serializing as `Value::Number` would
    // either require f64 (lossy — silently drops precision on money
    // columns) or i64 (only works for exact integers within range).
    // String preserves precision end-to-end; operators whose
    // `output_schema` expects `type: number` need to update to
    // `type: string` + `format: decimal` (see FUTURE work in
    // schema.rs `pg_type_to_json_schema("numeric")`).
    if matches!(type_name, "NUMERIC" | "DECIMAL") {
        return match row.try_get::<Option<rust_decimal::Decimal>, _>(idx) {
            Ok(Some(v)) => Ok(Value::String(v.to_string())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // JSON / JSONB inlining contract. sqlx's `Decode` impl for
    // `serde_json::Value` parses the column payload directly into a
    // `Value` (object / array / scalar), so what we hand back here is
    // structurally inlined into the response, not a string-wrapped
    // re-encoding. Tests in `tests/postgres_basic.rs` pin this — do
    // NOT change to `Value::String(v.to_string())` under any
    // refactor, since that would silently re-introduce the
    // double-encoding bug callers depend on the decoder to avoid.
    if matches!(type_name, "JSON" | "JSONB") {
        return match row.try_get::<Option<Value>, _>(idx) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    if matches!(type_name, "UUID") {
        return match row.try_get::<Option<uuid::Uuid>, _>(idx) {
            Ok(Some(v)) => Ok(Value::String(v.to_string())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // TIMESTAMPTZ. `to_rfc3339()` produces a stable ISO 8601
    // serialization with the offset (`+00:00`, never `Z`), and
    // `chrono::DateTime<Utc>` decodes the wire-format microseconds
    // verbatim from sqlx's binary protocol — there's no truncation
    // through this path. Sub-second precision is included only when
    // non-zero (chrono's default `to_rfc3339` behavior).
    if matches!(type_name, "TIMESTAMPTZ" | "TIMESTAMP WITH TIME ZONE") {
        return match row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(idx) {
            Ok(Some(v)) => Ok(Value::String(v.to_rfc3339())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // TIMESTAMP (naive). The format string uses `%.6f` (always
    // 6 fractional digits) rather than `%.f` (variable width) so the
    // serialization is stable across rows: callers that build a JSON
    // schema or hash the response on the consumer side don't need to
    // accept variable-width subseconds. Postgres TIMESTAMP has
    // microsecond precision, which is exactly 6 digits — perfect fit.
    if matches!(type_name, "TIMESTAMP" | "TIMESTAMP WITHOUT TIME ZONE") {
        return match row.try_get::<Option<chrono::NaiveDateTime>, _>(idx) {
            Ok(Some(v)) => Ok(Value::String(v.format("%Y-%m-%dT%H:%M:%S%.6f").to_string())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    if matches!(type_name, "DATE") {
        return match row.try_get::<Option<chrono::NaiveDate>, _>(idx) {
            Ok(Some(v)) => Ok(Value::String(v.to_string())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // TIME (naive, no timezone). Same `%.6f` rationale as
    // TIMESTAMP: stable 6-digit microsecond precision on every row.
    // Postgres TIME range is 00:00:00 to 24:00:00 (inclusive), which
    // chrono::NaiveTime accepts.
    if matches!(type_name, "TIME" | "TIME WITHOUT TIME ZONE") {
        return match row.try_get::<Option<chrono::NaiveTime>, _>(idx) {
            Ok(Some(v)) => Ok(Value::String(v.format("%H:%M:%S%.6f").to_string())),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // TIMETZ ("time with time zone") — chrono / sqlx don't have a
    // first-class type for it (it's a Postgres oddity that's
    // generally discouraged in favor of TIMESTAMPTZ). Falls through
    // to the string-fallback path with whatever Postgres returns.
    // INTERVAL. Postgres preserves the calendar/clock split
    // (months, days, microseconds as separate signed components) and
    // we faithfully reflect that via ISO 8601 duration syntax. See
    // `crate::driver::interval` for the conversion rules — including
    // the explicit handling of mixed-sign intervals (lossy fallback
    // with a tracing warn) and overflow safety on i32::MIN /
    // i64::MIN.
    if matches!(type_name, "INTERVAL") {
        use sqlx::postgres::types::PgInterval;
        return match row.try_get::<Option<PgInterval>, _>(idx) {
            Ok(Some(iv)) => Ok(Value::String(
                crate::driver::interval::pg_interval_to_iso8601(&iv),
            )),
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    if matches!(type_name, "BYTEA") {
        return match row.try_get::<Option<Vec<u8>>, _>(idx) {
            Ok(Some(v)) => {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&v);
                Ok(serde_json::json!({"base64": b64}))
            }
            Ok(None) => Ok(Value::Null),
            Err(e) => Err(e.to_string()),
        };
    }
    // Fallback: try string.
    match row.try_get::<Option<String>, _>(idx) {
        Ok(Some(v)) => Ok(Value::String(v)),
        Ok(None) => Ok(Value::Null),
        Err(e) => Err(e.to_string()),
    }
}

/// Pull `host` out of a `postgres://[user[:pass]@]host[:port]/db`
/// URL. Used by the cloud-auth path to tell the auth
/// provider which DB endpoint these tokens authenticate against.
/// Returns `None` only on truly malformed URLs — config validation
/// should have caught those long before this is called.
fn pg_host_from_url(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(str::to_owned)
}

/// Pull `port` out of a Postgres URL. Caller defaults to 5432 when
/// this returns `None`.
fn pg_port_from_url(url: &str) -> Option<u16> {
    url::Url::parse(url).ok()?.port()
}
