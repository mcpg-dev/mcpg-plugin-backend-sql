//! `SqlDriver` trait and driver registry.
//!
//! The trait is engine-agnostic; concrete implementations live in the
//! sibling modules gated on their crate-level features, covering
//! Postgres, MySQL/MariaDB, and SQLite. Streaming / cursor methods are
//! follow-on work; only `execute` is required today.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::config::{DriverKind, SqlBackendConfig};
use crate::errors::SqlError;
use crate::in_flight::InFlightRegistry;
use crate::params::{BoundParam, PreparedStmt};
use crate::session::SessionVars;

/// Per-call context passed through to the driver so it can populate
/// the in-flight registry with a driver-level identifier for
/// targeted cancel.
///
/// Carries the request id (as a key back into the registry) and a
/// shared reference to the registry itself. The driver calls
/// `registry.set_backend_id(request_id, BackendId::…)` after it
/// acquires a connection and resolves the id.
///
/// Default-constructed contexts are no-ops — useful for tests and
/// for driver paths that don't participate in cancel (SQLite has no
/// concept of backend id; MySQL will get a `connection_id` impl
/// alongside its cancel story).
#[derive(Default)]
pub struct ExecCtx<'a> {
    /// Gateway-assigned request id; used as the registry key.
    pub request_id: Option<&'a str>,
    /// Shared registry for backend-id population.
    pub in_flight: Option<&'a InFlightRegistry>,
}

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "postgres")]
// Used by `decode_pg_column` to convert Postgres `INTERVAL`
// values into ISO 8601 duration strings.
pub(crate) mod interval;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "sqlite")]
pub mod sqlite;

/// Connection config derived from a validated [`SqlBackendConfig`].
///
/// Carries the pool knobs and the connection URL. The URL embeds any
/// credential material directly — the gateway-level interpolator has
/// already expanded `${env.VAR}` (and future `vault:…` / `aws-sm:…`
/// schemes) before the spec reaches the plugin, so this struct holds
/// the literal string the driver consumes.
#[derive(Clone)]
pub struct ConnectCfg {
    /// Connection URL with any credentials embedded.
    pub url: String,
    /// Max connections in the pool.
    pub max_connections: u32,
    /// Minimum idle connections.
    pub min_idle: u32,
    /// Acquire timeout, ms.
    pub acquire_timeout_ms: u64,
    /// Idle eviction timeout, ms.
    pub idle_timeout_ms: u64,
    /// Max connection lifetime, ms.
    pub max_lifetime_ms: u64,
    /// Whether to ping connection before hand-out.
    pub test_before_acquire: bool,
    /// Server-side statement timeout in milliseconds.
    /// Applied as a connection-level GUC (Postgres only) so every
    /// query run on the pool's connections is capped DB-side — the
    /// tokio timeout remains as an outer client-side deadline.
    pub statement_timeout_ms: Option<u64>,
    /// Optional cloud-DB auth provider. When set, the
    /// driver fetches a fresh token via the provider and substitutes
    /// it for the URL's password before opening pool connections; a
    /// background [`crate::auth::TokenRotator`] is spawned to refresh
    /// the token on schedule. `None` keeps the legacy
    /// "URL holds the password" path.
    pub auth_provider: Option<Arc<dyn crate::auth::AuthProvider>>,
}

impl std::fmt::Debug for ConnectCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectCfg")
            .field("url", &"<redacted>")
            .field("max_connections", &self.max_connections)
            .field("min_idle", &self.min_idle)
            .field("acquire_timeout_ms", &self.acquire_timeout_ms)
            .field("idle_timeout_ms", &self.idle_timeout_ms)
            .field("max_lifetime_ms", &self.max_lifetime_ms)
            .field("test_before_acquire", &self.test_before_acquire)
            .field("statement_timeout_ms", &self.statement_timeout_ms)
            .field(
                "auth_provider",
                &self.auth_provider.as_ref().map(|p| p.scheme()),
            )
            .finish()
    }
}

impl ConnectCfg {
    /// Derive a [`ConnectCfg`] from the operator config.
    ///
    /// `auth_provider` is left as `None`; constructors that have built
    /// a provider attach it via [`Self::with_auth_provider`].
    pub fn from_config(cfg: &SqlBackendConfig) -> Self {
        Self {
            url: cfg.url.clone(),
            max_connections: cfg.pool.max_connections,
            min_idle: cfg.pool.min_idle,
            acquire_timeout_ms: cfg.pool.acquire_timeout_ms,
            idle_timeout_ms: cfg.pool.idle_timeout_ms,
            max_lifetime_ms: cfg.pool.max_lifetime_ms,
            test_before_acquire: cfg.pool.test_before_acquire,
            statement_timeout_ms: cfg.query.timeout_ms,
            auth_provider: None,
        }
    }

    /// Attach an auth provider. Used by the pool builder when the
    /// operator config carries an `auth:` block.
    #[must_use]
    pub fn with_auth_provider(mut self, p: Arc<dyn crate::auth::AuthProvider>) -> Self {
        self.auth_provider = Some(p);
        self
    }
}

/// A pool handle held by a registered profile. Each variant is gated
/// on its driver's feature flag.
#[derive(Clone)]
pub enum PoolHandle {
    /// PostgreSQL pool.
    #[cfg(feature = "postgres")]
    Postgres(sqlx::Pool<sqlx::Postgres>),
    /// MySQL / MariaDB pool.
    #[cfg(feature = "mysql")]
    Mysql(sqlx::Pool<sqlx::MySql>),
    /// SQLite pool.
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::Pool<sqlx::Sqlite>),
}

impl std::fmt::Debug for PoolHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "postgres")]
            PoolHandle::Postgres(_) => f.debug_tuple("PoolHandle::Postgres").finish(),
            #[cfg(feature = "mysql")]
            PoolHandle::Mysql(_) => f.debug_tuple("PoolHandle::Mysql").finish(),
            #[cfg(feature = "sqlite")]
            PoolHandle::Sqlite(_) => f.debug_tuple("PoolHandle::Sqlite").finish(),
        }
    }
}

/// A single batch of rows returned to the plugin layer.
///
/// Whole result sets are returned in one [`RowBatch`]; the
/// `has_more` flag is reserved for a future cursor mode.
#[derive(Debug, Clone, Default)]
pub struct RowBatch {
    /// Ordered column names of the result set, if any.
    pub columns: Vec<String>,
    /// Rows as JSON objects keyed by column name.
    pub rows: Vec<Value>,
    /// Number of rows affected for INSERT/UPDATE/DELETE statements;
    /// `None` for SELECTs.
    pub rows_affected: Option<u64>,
    /// True if the driver had more rows than `max_rows` allowed us
    /// to keep.
    pub truncated: bool,
    /// Cursor hint reserved for future cursor mode — always false today.
    pub has_more: bool,
}

/// Result of [`SqlDriver::connect`]: the pool handle plus any
/// driver-spawned background tasks the caller must keep alive for
/// the pool's lifetime.
///
/// `rotator` is `Some` only on cloud-auth pools — the
/// driver consulted the [`crate::auth::AuthProvider`] for an initial
/// token and started a refresh task. The caller (plugin's profile
/// runtime) holds the `Arc` for the profile's lifetime; dropping it
/// cancels the refresher.
pub struct ConnectOutcome {
    /// The connection pool, ready for `execute`.
    pub pool: PoolHandle,
    /// Token-rotator handle when the driver spawned one. `None` for
    /// the static-cred path (URL-embedded password / `cred://`).
    pub rotator: Option<Arc<crate::auth::TokenRotator>>,
}

/// Engine-specific operations the SQL binding relies on.
#[async_trait]
pub trait SqlDriver: Send + Sync {
    /// The driver kind label used for metrics and logging.
    fn kind(&self) -> &'static str;

    /// Build a pool from a parsed URL + auth + pool knobs.
    ///
    /// On cloud-auth bindings (`cfg.auth_provider` is `Some`), the
    /// driver fetches an initial token, substitutes it for the URL's
    /// password, opens the pool, then spawns a [`crate::auth::TokenRotator`]
    /// to refresh on schedule. The rotator is returned in the
    /// [`ConnectOutcome`] so the caller can pin its lifetime.
    async fn connect(&self, cfg: &ConnectCfg) -> Result<ConnectOutcome, SqlError>;

    /// Prepare + run a statement, returning one batch of rows.
    ///
    /// A future cursor-backed fetch_more for `row_mode: stream` will
    /// extend this; for now callers get the full batch or a
    /// truncated slice up to `max_rows`.
    async fn execute(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<RowBatch, SqlError>;

    /// Variant of [`execute`] that accepts an [`ExecCtx`] so the
    /// driver can pin a connection, capture its backend identifier,
    /// and populate the in-flight registry with a key suitable for
    /// targeted cancel. Default implementation forwards
    /// to [`execute`] — drivers opting into cancel support override.
    async fn execute_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
        _ctx: ExecCtx<'_>,
    ) -> Result<RowBatch, SqlError> {
        self.execute(pool, stmt, args, session).await
    }

    /// Run a statement for its side-effects only, returning the number
    /// of affected rows. The plugin calls this instead of [`execute`]
    /// when `row_mode == AffectedRows`, because sqlx's `fetch_all` does
    /// not surface the server-reported `rows_affected` count — that
    /// only comes back through the `execute`-style submission path.
    async fn execute_affected(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
    ) -> Result<u64, SqlError>;

    /// Variant of [`execute_affected`] with an [`ExecCtx`]. Same
    /// default-forward behavior as [`execute_with_ctx`].
    async fn execute_affected_with_ctx(
        &self,
        pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        session: &SessionVars,
        _ctx: ExecCtx<'_>,
    ) -> Result<u64, SqlError> {
        self.execute_affected(pool, stmt, args, session).await
    }

    /// Multi-result-set execute. Drives the procedure call
    /// through a streaming sqlx executor that surfaces result-set
    /// boundaries — the driver groups rows between boundaries into
    /// separate `Vec<Value>`s and returns the whole list.
    ///
    /// Default impl returns `InvalidSpec` so engines without a
    /// multi-result-set protocol path fail loudly. Config validation
    /// (`row_mode: result_sets` rejected on Postgres/SQLite) makes
    /// this dispatchable only on MySQL/MariaDB in practice — this
    /// runtime guard is defense in depth for misconfigured drivers.
    async fn execute_multi_result(
        &self,
        _pool: &PoolHandle,
        _stmt: &PreparedStmt,
        _args: &[BoundParam],
        _session: &SessionVars,
    ) -> Result<Vec<Vec<Value>>, SqlError> {
        Err(SqlError::InvalidSpec(format!(
            "row_mode: result_sets is not supported by the '{}' driver",
            self.kind()
        )))
    }

    /// Dispatch a driver-level cancel for an in-flight request.
    /// `backend_id` is what the registry stored for
    /// the request; the driver decodes the variant and issues the
    /// engine-appropriate cancel (`pg_cancel_backend`, `KILL QUERY`,
    /// `sqlite3_interrupt`). Default impl returns `InvalidSpec`
    /// so drivers without a cancel story fail explicitly.
    async fn cancel_backend(
        &self,
        _pool: &PoolHandle,
        _backend_id: crate::in_flight::BackendId,
    ) -> Result<(), SqlError> {
        Err(SqlError::InvalidSpec(
            "driver-level cancel is not yet supported for this engine".into(),
        ))
    }

    /// Lightweight liveness check against the pool. Used by upcoming
    /// circuit-breaker and pool-health telemetry paths.
    async fn health_check(&self, pool: &PoolHandle) -> Result<(), SqlError>;

    /// Verify the pool user has the privilege the driver needs to
    /// execute a targeted cancel (`pg_cancel_backend`, `KILL QUERY`,
    /// etc.). Default impl is a no-op (`Ok(())`) — drivers that need
    /// a specific grant override and probe the server-reported grants.
    ///
    /// Called once at profile registration when
    /// `cfg.pool.require_cancel_privilege` is true. A failure here is
    /// converted into [`SqlError::InvalidSpec`] by the driver impl so
    /// the binding refuses to register, instead of silently degrading
    /// cancel-on-timeout to a no-op once a query times out under load.
    async fn verify_cancel_privilege(&self, _pool: &PoolHandle) -> Result<(), SqlError> {
        Ok(())
    }

    /// Describe the prepared statement's parameters and map each type
    /// to a JSON Schema fragment, zipped against `param_names`.
    /// Returns `None` when the driver does not support metadata
    /// introspection (default) or when the server did not return
    /// parameter info. The plugin layer merges the result with
    /// operator-supplied schema — a `None` here falls back cleanly.
    ///
    /// Wired for PostgreSQL; MySQL and SQLite default to
    /// `None` until prepared-statement metadata support lands.
    async fn describe_parameters(
        &self,
        _pool: &PoolHandle,
        _sql: &str,
        _param_names: &[String],
    ) -> Result<Option<serde_json::Value>, SqlError> {
        Ok(None)
    }

    /// Describe the prepared statement's result columns and build a
    /// JSON Schema fragment shaped per `row_mode`. Returns
    /// `None` when the driver can't introspect columns or when the
    /// statement returns none (writes, procedures with no result).
    ///
    /// Wired for PostgreSQL; other engines inherit the
    /// default `None` until their `Executor::describe` support
    /// matures.
    async fn describe_columns(
        &self,
        _pool: &PoolHandle,
        _sql: &str,
        _row_mode: crate::config::RowMode,
    ) -> Result<Option<serde_json::Value>, SqlError> {
        Ok(None)
    }
}

/// Build the driver registry from the active feature flags.
///
/// Returns an `Arc<dyn SqlDriver>` per enabled driver, keyed by
/// [`DriverKind`]. Missing drivers (feature off) produce an
/// `InvalidSpec` at profile registration when a binding names them.
pub fn build_registry() -> std::collections::HashMap<DriverKind, Arc<dyn SqlDriver>> {
    let mut m: std::collections::HashMap<DriverKind, Arc<dyn SqlDriver>> =
        std::collections::HashMap::new();
    #[cfg(feature = "postgres")]
    {
        m.insert(DriverKind::Postgres, Arc::new(postgres::PostgresDriver));
    }
    #[cfg(feature = "mysql")]
    {
        let mysql: Arc<dyn SqlDriver> = Arc::new(mysql::MysqlDriver);
        m.insert(DriverKind::Mysql, mysql.clone());
        m.insert(DriverKind::Mariadb, mysql);
    }
    #[cfg(feature = "sqlite")]
    {
        m.insert(DriverKind::Sqlite, Arc::new(sqlite::SqliteDriver::new()));
    }
    m
}
