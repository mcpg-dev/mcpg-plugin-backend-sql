//! Transaction handles for pipeline-scoped atomic writes.
//!
//! Operators often need to run a sequence of statements inside one
//! database transaction — deduct inventory, record a charge, mark an
//! invoice paid — and get all-or-nothing semantics. Rolling that up
//! as a single multi-statement body defeats placeholder binding and
//! is rejected by `reject_multi_statement`; the answer is a
//! pipeline-level transaction scope.
//!
//! This module exposes the **plugin-side half** of that mechanism:
//! a [`SqlTxHandle`] that pins one pool connection, holds an open
//! sqlx transaction, and executes statements on that connection
//! until the caller calls [`SqlTxHandle::commit`] or
//! [`SqlTxHandle::rollback`]. The mcpg pipeline executor consumes
//! this API as a follow-up — once `type: sql_tx` lands in the
//! pipeline step config, it begins a handle, threads it through
//! nested `sql_exec` steps, and commits / rolls back on pipeline
//! outcome.
//!
//! # Guarantees
//!
//! - **Pinned connection.** Every statement submitted through the
//!   handle goes to the same pool connection for the tx's lifetime.
//!   sqlx's `Transaction<'static, DB>` owns the connection; the
//!   handle holds it in an `Arc<Mutex<Option<_>>>` so commit /
//!   rollback consume it exactly once.
//! - **At-most-once termination.** Calling `commit` or `rollback`
//!   after the handle is already closed returns `InvalidSpec`, not a
//!   panic.
//! - **Rollback on drop.** If the handle is dropped without
//!   `commit` / `rollback`, sqlx rolls the transaction back
//!   automatically when the underlying connection is returned to the
//!   pool. A warn-level log fires in that case so operators see the
//!   leak.
//!
//! # Scope
//!
//! This first cut covers **PostgreSQL** — the primary driver for
//! write-heavy workflows. MySQL (which requires `START TRANSACTION`
//! idioms for identical semantics) and SQLite will follow in the
//! same-shape driver expansions. The trait object approach means the
//! plugin API surface stays stable as engines are added.

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;
use tracing::warn;

use crate::config::DriverKind;
use crate::driver::RowBatch;
use crate::errors::SqlError;
use crate::params::{BoundParam, PreparedStmt};
use crate::session::SessionVars;

/// Trait object for a pinned, open transaction. The plugin returns
/// one from [`crate::SqlBackendPlugin::begin_transaction`]; callers
/// use it in place of `plugin.execute(...)` for statements that must
/// atomically succeed or roll back with the rest of the pipeline.
#[async_trait]
pub trait SqlTxHandle: Send + Sync {
    /// Which driver the underlying connection speaks.
    fn driver(&self) -> DriverKind;

    /// Submit a prepared statement on the pinned connection. Row
    /// shaping happens at the plugin layer just like a non-tx
    /// execute — this method returns the raw batch.
    async fn execute(
        &self,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<RowBatch, SqlError>;

    /// Submit for side-effects only (INSERT / UPDATE / DELETE). Same
    /// split as the non-tx path so `rows_affected` comes back from
    /// the server, not from a fetch_all scan.
    async fn execute_affected(
        &self,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<u64, SqlError>;

    /// Commit the transaction. Consumes the inner tx. Subsequent
    /// calls return `InvalidSpec("transaction already closed")`.
    async fn commit(&self) -> Result<(), SqlError>;

    /// Roll back the transaction. Same at-most-once contract as
    /// [`commit`].
    async fn rollback(&self) -> Result<(), SqlError>;

    /// True iff the handle has been committed or rolled back and
    /// further submissions will fail.
    fn is_closed(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Postgres implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "postgres")]
pub(crate) mod postgres {
    use super::*;
    use crate::driver::postgres::{bind_pg, row_to_json_pg};
    use sqlx::{Column, Row};

    /// Owned Postgres transaction. `state = None` once commit /
    /// rollback has consumed the inner `sqlx::Transaction`.
    pub struct PostgresTxHandle {
        inner: Mutex<Option<sqlx::Transaction<'static, sqlx::Postgres>>>,
    }

    impl PostgresTxHandle {
        pub fn new(tx: sqlx::Transaction<'static, sqlx::Postgres>) -> Self {
            Self {
                inner: Mutex::new(Some(tx)),
            }
        }

        /// Temporarily take the tx out of the mutex to execute on.
        /// sqlx's tx methods take `&mut Transaction`, and we need to
        /// cross the await boundary — so we pop it out, run, and put
        /// it back. The mutex is held only across the pop and put,
        /// never across the actual DB I/O.
        fn take(&self) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, SqlError> {
            self.inner
                .lock()
                .take()
                .ok_or_else(|| SqlError::InvalidSpec("transaction already closed".into()))
        }

        fn put(&self, tx: sqlx::Transaction<'static, sqlx::Postgres>) {
            *self.inner.lock() = Some(tx);
        }
    }

    impl Drop for PostgresTxHandle {
        fn drop(&mut self) {
            if self.inner.lock().is_some() {
                warn!(
                    "SqlTxHandle dropped without commit/rollback — sqlx will \
                     roll back when the connection returns to the pool"
                );
            }
        }
    }

    #[async_trait]
    impl SqlTxHandle for PostgresTxHandle {
        fn driver(&self) -> DriverKind {
            DriverKind::Postgres
        }

        async fn execute(
            &self,
            stmt: &PreparedStmt,
            args: &[BoundParam],
            session: &SessionVars,
        ) -> Result<RowBatch, SqlError> {
            let mut tx = self.take()?;
            // session_vars inside a tx: same `set_config(name, $1,
            // true)` idiom as the non-tx path. Tx-local by design —
            // `SET LOCAL` would also work but set_config accepts
            // bound params so we reuse.
            for (k, v) in session.values.iter() {
                let q_res = sqlx::query("SELECT set_config($1, $2, true)")
                    .bind(k)
                    .bind(v)
                    .execute(&mut *tx)
                    .await;
                if let Err(e) = q_res {
                    self.put(tx);
                    return Err(SqlError::from_execute(e));
                }
            }
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_pg(q, &arg.value);
            }
            let rows_res = q.fetch_all(&mut *tx).await;
            let rows = match rows_res {
                Ok(r) => r,
                Err(e) => {
                    self.put(tx);
                    return Err(SqlError::from_execute(e));
                }
            };
            let columns = rows
                .first()
                .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                .unwrap_or_default();
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                out.push(row_to_json_pg(row)?);
            }
            self.put(tx);
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
            stmt: &PreparedStmt,
            args: &[BoundParam],
            session: &SessionVars,
        ) -> Result<u64, SqlError> {
            let mut tx = self.take()?;
            for (k, v) in session.values.iter() {
                let q_res = sqlx::query("SELECT set_config($1, $2, true)")
                    .bind(k)
                    .bind(v)
                    .execute(&mut *tx)
                    .await;
                if let Err(e) = q_res {
                    self.put(tx);
                    return Err(SqlError::from_execute(e));
                }
            }
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_pg(q, &arg.value);
            }
            let result_res = q.execute(&mut *tx).await;
            match result_res {
                Ok(result) => {
                    let n = result.rows_affected();
                    self.put(tx);
                    Ok(n)
                }
                Err(e) => {
                    self.put(tx);
                    Err(SqlError::from_execute(e))
                }
            }
        }

        async fn commit(&self) -> Result<(), SqlError> {
            let tx = self.take()?;
            tx.commit().await.map_err(SqlError::from_execute)
        }

        async fn rollback(&self) -> Result<(), SqlError> {
            let tx = self.take()?;
            tx.rollback().await.map_err(SqlError::from_execute)
        }

        fn is_closed(&self) -> bool {
            self.inner.lock().is_none()
        }
    }
}

// ---------------------------------------------------------------------------
// MySQL / MariaDB implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "mysql")]
pub(crate) mod mysql {
    use super::*;
    use crate::driver::mysql::{bind_mysql, row_to_json_mysql};
    use sqlx::{Column, Row};

    /// Owned MySQL/MariaDB transaction. Same state machine as
    /// [`postgres::PostgresTxHandle`].
    pub struct MysqlTxHandle {
        inner: Mutex<Option<sqlx::Transaction<'static, sqlx::MySql>>>,
    }

    impl MysqlTxHandle {
        pub fn new(tx: sqlx::Transaction<'static, sqlx::MySql>) -> Self {
            Self {
                inner: Mutex::new(Some(tx)),
            }
        }

        fn take(&self) -> Result<sqlx::Transaction<'static, sqlx::MySql>, SqlError> {
            self.inner
                .lock()
                .take()
                .ok_or_else(|| SqlError::InvalidSpec("transaction already closed".into()))
        }

        fn put(&self, tx: sqlx::Transaction<'static, sqlx::MySql>) {
            *self.inner.lock() = Some(tx);
        }

        /// Apply session @user-vars on the pinned tx connection. Keys
        /// were validated at config parse time
        /// ([`config::is_safe_sql_identifier`] plus the
        /// MySQL-only "no dots" rule), so they are safe to
        /// inline into the SET text. Values flow through bind, never
        /// interpolated.
        async fn apply_session_vars(
            tx: &mut sqlx::Transaction<'static, sqlx::MySql>,
            session: &SessionVars,
        ) -> Result<(), SqlError> {
            for (k, v) in session.values.iter() {
                sqlx::query(&format!("SET @{k} = ?"))
                    .bind(v)
                    .execute(&mut **tx)
                    .await
                    .map_err(SqlError::from_execute)?;
            }
            Ok(())
        }

        /// Best-effort teardown: null every previously-set @user-var
        /// before commit / rollback so the connection returns to the
        /// pool clean. Errors are downgraded to `tracing::warn` since
        /// the primary outcome (commit success / rollback) is the
        /// caller's signal — failing teardown should not mask it.
        async fn clear_session_vars(
            tx: &mut sqlx::Transaction<'static, sqlx::MySql>,
            session: &SessionVars,
        ) {
            for k in session.values.keys() {
                if let Err(e) = sqlx::query(&format!("SET @{k} = NULL"))
                    .execute(&mut **tx)
                    .await
                {
                    warn!(
                        var = %k,
                        error = %e,
                        "MysqlTxHandle: failed to NULL session @var on teardown"
                    );
                }
            }
        }
    }

    impl Drop for MysqlTxHandle {
        fn drop(&mut self) {
            if self.inner.lock().is_some() {
                warn!(
                    "SqlTxHandle dropped without commit/rollback — sqlx will \
                     roll back when the connection returns to the pool"
                );
            }
        }
    }

    #[async_trait]
    impl SqlTxHandle for MysqlTxHandle {
        fn driver(&self) -> DriverKind {
            DriverKind::Mysql
        }

        async fn execute(
            &self,
            stmt: &PreparedStmt,
            args: &[BoundParam],
            session: &SessionVars,
        ) -> Result<RowBatch, SqlError> {
            let mut tx = self.take()?;
            if let Err(e) = Self::apply_session_vars(&mut tx, session).await {
                self.put(tx);
                return Err(e);
            }
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_mysql(q, &arg.value);
            }
            let rows_res = q.fetch_all(&mut *tx).await;
            // Always tear down the @vars set by this call before
            // returning, regardless of query outcome. MySQL @user
            // variables outlive transactions and would otherwise
            // leak into the next checkout of this pooled conn after
            // commit / rollback.
            Self::clear_session_vars(&mut tx, session).await;
            let rows = match rows_res {
                Ok(r) => r,
                Err(e) => {
                    self.put(tx);
                    return Err(SqlError::from_execute(e));
                }
            };
            let columns = rows
                .first()
                .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                .unwrap_or_default();
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                out.push(row_to_json_mysql(row)?);
            }
            self.put(tx);
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
            stmt: &PreparedStmt,
            args: &[BoundParam],
            session: &SessionVars,
        ) -> Result<u64, SqlError> {
            let mut tx = self.take()?;
            if let Err(e) = Self::apply_session_vars(&mut tx, session).await {
                self.put(tx);
                return Err(e);
            }
            let mut q = sqlx::query(&stmt.sql);
            for arg in args {
                q = bind_mysql(q, &arg.value);
            }
            let exec_res = q.execute(&mut *tx).await;
            Self::clear_session_vars(&mut tx, session).await;
            match exec_res {
                Ok(result) => {
                    let n = result.rows_affected();
                    self.put(tx);
                    Ok(n)
                }
                Err(e) => {
                    self.put(tx);
                    Err(SqlError::from_execute(e))
                }
            }
        }

        async fn commit(&self) -> Result<(), SqlError> {
            let tx = self.take()?;
            tx.commit().await.map_err(SqlError::from_execute)
        }

        async fn rollback(&self) -> Result<(), SqlError> {
            let tx = self.take()?;
            tx.rollback().await.map_err(SqlError::from_execute)
        }

        fn is_closed(&self) -> bool {
            self.inner.lock().is_none()
        }
    }
}

// ---------------------------------------------------------------------------
// SQLite implementation (useful for unit tests + local workflows)
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
pub(crate) mod sqlite {
    use super::*;
    use sqlx::{Column, Row};

    /// Owned SQLite transaction. Same state machine as
    /// [`postgres::PostgresTxHandle`].
    pub struct SqliteTxHandle {
        inner: Mutex<Option<sqlx::Transaction<'static, sqlx::Sqlite>>>,
    }

    impl SqliteTxHandle {
        pub fn new(tx: sqlx::Transaction<'static, sqlx::Sqlite>) -> Self {
            Self {
                inner: Mutex::new(Some(tx)),
            }
        }

        fn take(&self) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, SqlError> {
            self.inner
                .lock()
                .take()
                .ok_or_else(|| SqlError::InvalidSpec("transaction already closed".into()))
        }

        fn put(&self, tx: sqlx::Transaction<'static, sqlx::Sqlite>) {
            *self.inner.lock() = Some(tx);
        }
    }

    impl Drop for SqliteTxHandle {
        fn drop(&mut self) {
            if self.inner.lock().is_some() {
                warn!(
                    "SqlTxHandle dropped without commit/rollback — sqlx will \
                     roll back when the connection returns to the pool"
                );
            }
        }
    }

    fn bind_sqlite<'q>(
        mut q: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
        args: &'q [BoundParam],
    ) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
        for arg in args {
            q = match &arg.value {
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
                Value::Array(_) | Value::Object(_) => q.bind(arg.value.to_string()),
            };
        }
        q
    }

    #[async_trait]
    impl SqlTxHandle for SqliteTxHandle {
        fn driver(&self) -> DriverKind {
            DriverKind::Sqlite
        }

        async fn execute(
            &self,
            stmt: &PreparedStmt,
            args: &[BoundParam],
            _session: &SessionVars,
        ) -> Result<RowBatch, SqlError> {
            let mut tx = self.take()?;
            let q = sqlx::query(&stmt.sql);
            let q = bind_sqlite(q, args);
            let rows_res = q.fetch_all(&mut *tx).await;
            let rows = match rows_res {
                Ok(r) => r,
                Err(e) => {
                    self.put(tx);
                    return Err(SqlError::from_execute(e));
                }
            };
            // SQLite decoding is dynamic-type; for the tx path we
            // emit a minimal row shape (column name → value probed
            // via try_get<String>) — enough to support the end-to-end
            // tests without pulling the full decoder here.
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                let mut obj = serde_json::Map::new();
                for col in row.columns() {
                    // Integer first, then string fallback — matches
                    // the non-tx decoder's first two probes.
                    if let Ok(v) = row.try_get::<Option<i64>, _>(col.ordinal()) {
                        obj.insert(
                            col.name().to_owned(),
                            v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null),
                        );
                    } else if let Ok(v) = row.try_get::<Option<String>, _>(col.ordinal()) {
                        obj.insert(
                            col.name().to_owned(),
                            v.map(Value::String).unwrap_or(Value::Null),
                        );
                    } else {
                        obj.insert(col.name().to_owned(), Value::Null);
                    }
                }
                out.push(Value::Object(obj));
            }
            self.put(tx);
            Ok(RowBatch {
                columns: vec![],
                rows: out,
                rows_affected: None,
                truncated: false,
                has_more: false,
            })
        }

        async fn execute_affected(
            &self,
            stmt: &PreparedStmt,
            args: &[BoundParam],
            _session: &SessionVars,
        ) -> Result<u64, SqlError> {
            let mut tx = self.take()?;
            let q = sqlx::query(&stmt.sql);
            let q = bind_sqlite(q, args);
            let result_res = q.execute(&mut *tx).await;
            match result_res {
                Ok(r) => {
                    let n = r.rows_affected();
                    self.put(tx);
                    Ok(n)
                }
                Err(e) => {
                    self.put(tx);
                    Err(SqlError::from_execute(e))
                }
            }
        }

        async fn commit(&self) -> Result<(), SqlError> {
            let tx = self.take()?;
            tx.commit().await.map_err(SqlError::from_execute)
        }

        async fn rollback(&self) -> Result<(), SqlError> {
            let tx = self.take()?;
            tx.rollback().await.map_err(SqlError::from_execute)
        }

        fn is_closed(&self) -> bool {
            self.inner.lock().is_none()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (SQLite-backed — SQLite tx lifecycle is identical shape to
// Postgres and works in-process without a service).
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests {
    use super::*;
    use crate::params::PreparedStmt;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    async fn sqlite_pool() -> sqlx::SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect(":memory:")
            .await
            .expect("in-memory sqlite")
    }

    fn stmt(sql: &str) -> PreparedStmt {
        PreparedStmt {
            sql: sql.into(),
            param_order: vec![],
            driver: DriverKind::Sqlite,
        }
    }

    #[tokio::test]
    async fn commit_persists_writes() {
        let pool = sqlite_pool().await;
        sqlx::query("CREATE TABLE t (id INT)")
            .execute(&pool)
            .await
            .unwrap();

        let tx: sqlx::Transaction<'static, sqlx::Sqlite> = pool.begin().await.unwrap();
        let handle = Arc::new(sqlite::SqliteTxHandle::new(tx)) as Arc<dyn SqlTxHandle>;
        handle
            .execute_affected(
                &stmt("INSERT INTO t VALUES (1)"),
                &[],
                &SessionVars::default(),
            )
            .await
            .unwrap();
        handle.commit().await.unwrap();
        assert!(handle.is_closed());

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM t")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1, "committed row must be visible");
    }

    #[tokio::test]
    async fn rollback_discards_writes() {
        let pool = sqlite_pool().await;
        sqlx::query("CREATE TABLE t (id INT)")
            .execute(&pool)
            .await
            .unwrap();

        let tx = pool.begin().await.unwrap();
        let handle = Arc::new(sqlite::SqliteTxHandle::new(tx)) as Arc<dyn SqlTxHandle>;
        handle
            .execute_affected(
                &stmt("INSERT INTO t VALUES (1)"),
                &[],
                &SessionVars::default(),
            )
            .await
            .unwrap();
        handle.rollback().await.unwrap();
        assert!(handle.is_closed());

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM t")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "rolled-back row must NOT be visible");
    }

    #[tokio::test]
    async fn commit_after_close_is_invalid_spec() {
        let pool = sqlite_pool().await;
        let tx = pool.begin().await.unwrap();
        let handle = Arc::new(sqlite::SqliteTxHandle::new(tx)) as Arc<dyn SqlTxHandle>;
        handle.commit().await.unwrap();
        let err = handle.commit().await.unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(msg) if msg.contains("closed")));
    }

    #[tokio::test]
    async fn rollback_after_commit_is_invalid_spec() {
        let pool = sqlite_pool().await;
        let tx = pool.begin().await.unwrap();
        let handle = Arc::new(sqlite::SqliteTxHandle::new(tx)) as Arc<dyn SqlTxHandle>;
        handle.commit().await.unwrap();
        let err = handle.rollback().await.unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(_)));
    }

    #[tokio::test]
    async fn execute_after_close_is_invalid_spec() {
        let pool = sqlite_pool().await;
        let tx = pool.begin().await.unwrap();
        let handle = Arc::new(sqlite::SqliteTxHandle::new(tx)) as Arc<dyn SqlTxHandle>;
        handle.commit().await.unwrap();
        let err = handle
            .execute_affected(&stmt("SELECT 1"), &[], &SessionVars::default())
            .await
            .unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(_)));
    }

    #[tokio::test]
    async fn drop_without_commit_rolls_back() {
        // sqlx's Transaction rolls back on Drop when connection
        // returns to the pool. We verify end-state: writes made on
        // an abandoned handle are not visible afterward.
        let pool = sqlite_pool().await;
        sqlx::query("CREATE TABLE t (id INT)")
            .execute(&pool)
            .await
            .unwrap();
        {
            let tx = pool.begin().await.unwrap();
            let handle = Arc::new(sqlite::SqliteTxHandle::new(tx)) as Arc<dyn SqlTxHandle>;
            handle
                .execute_affected(
                    &stmt("INSERT INTO t VALUES (42)"),
                    &[],
                    &SessionVars::default(),
                )
                .await
                .unwrap();
            // handle drops here without commit/rollback
        }
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM t")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "abandoned tx must not persist writes");
    }
}
