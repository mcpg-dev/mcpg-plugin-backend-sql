//! Serde configuration structures for `[bindings.sql.*]` blocks.
//!
//! `deny_unknown_fields` is set on every struct so
//! operator typos fail fast at config-parse time.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::errors::SqlError;

/// SQL driver kind. Corresponds to the compile-time feature flag that
/// enables the concrete driver impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverKind {
    /// PostgreSQL (and wire-compatible engines — CockroachDB, Yugabyte).
    Postgres,
    /// MySQL and MariaDB (same sqlx driver).
    Mysql,
    /// MariaDB alias — accepted at config parse time, normalized to `Mysql`.
    Mariadb,
    /// SQLite, in-process / file-backed.
    Sqlite,
}

impl DriverKind {
    /// String label used in metric/label fields.
    pub fn as_str(self) -> &'static str {
        match self {
            DriverKind::Postgres => "postgres",
            DriverKind::Mysql => "mysql",
            DriverKind::Mariadb => "mariadb",
            DriverKind::Sqlite => "sqlite",
        }
    }
}

/// Per-binding transaction isolation level.
///
/// Applied via `SET TRANSACTION ISOLATION LEVEL …` immediately after
/// `BEGIN` inside [`crate::SqlBackendPlugin::begin_transaction`], so it
/// scopes only to the `sql_tx` pipeline-step transaction (not to plain
/// auto-commit `execute()` calls). Default is the engine's default
/// (`READ COMMITTED` on Postgres / MySQL, fully serializable on SQLite).
///
/// SQLite is **always** serializable in practice — declaring anything
/// other than `Serializable` on a SQLite binding is a config typo and
/// fails validation rather than silently mapping to no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// Default for Postgres + MySQL/MariaDB. Each statement sees a
    /// snapshot taken at statement start.
    ReadCommitted,
    /// Postgres + MySQL — snapshot taken at the first read inside the
    /// transaction. Default on MySQL InnoDB.
    RepeatableRead,
    /// Strongest level. Postgres + MySQL emulate via SSI / locks; SQLite
    /// is always serializable.
    Serializable,
}

impl IsolationLevel {
    /// Engine-portable SQL fragment the runtime issues right after
    /// `BEGIN`. Empty string = no-op (for engines / levels that can't
    /// tighten via SQL — none today, but reserved for future drivers).
    pub fn sql_fragment(self) -> &'static str {
        match self {
            IsolationLevel::ReadCommitted => "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            IsolationLevel::RepeatableRead => "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
            IsolationLevel::Serializable => "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        }
    }
}

/// Top-level SQL binding configuration (the contents of `[bindings.sql]`).
///
/// The connection URL is the **sole** credential surface. Operators
/// embed secrets directly in the URL and use the gateway's string
/// interpolator (`${env.VAR}` at config-load time, future `vault:…` /
/// `aws-sm:…` schemes via plugin-provided resolvers) to keep secret
/// material out of the YAML. Scheme-specific credential resolvers
/// used to live on this config (`password_env` / `password_file` /
/// `password_ref`) and have been removed — that responsibility is a
/// gateway-wide concern, not a per-plugin one.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlBackendConfig {
    /// Driver kind selector. Must match the scheme of `url`.
    pub driver: DriverKind,
    /// Connection URL including any password component. Callers are
    /// responsible for routing secrets through the gateway
    /// interpolator (e.g. `postgres://app:${env.PW}@db/orders`) so
    /// cleartext never lands in the YAML source.
    pub url: String,
    /// Pool sizing and timeouts.
    #[serde(default)]
    pub pool: PoolConfig,
    /// Injected unconditionally by the host's dynamic-registration path
    /// (`gateway.server.allow_private_backends`). Accepted so the strict
    /// spec does not refuse the host contract, and deliberately unused:
    /// databases legitimately live on private addresses, so the SSRF
    /// egress toggle does not gate SQL connections.
    #[serde(default)]
    pub allow_private_backends: bool,
    /// The query/procedure this binding invokes. A query block is
    /// required; pure-wait configurations are not yet supported.
    pub query: QueryShape,
    /// Optional identity-bound session variables. Stored and reflected
    /// back to callers; full `SET LOCAL` runtime support is follow-on work.
    #[serde(default)]
    pub session_vars: BTreeMap<String, String>,
    /// Optional schema-derivation config. Empty → off.
    #[serde(default)]
    pub schema: crate::schema::SchemaConfig,
    /// Optional per-binding circuit breaker. Absent →
    /// breaker disabled; every call reaches the driver. Present →
    /// tracks consecutive failures and short-circuits with fast
    /// `Transport` errors while the DB is unhealthy.
    #[serde(default)]
    pub circuit_breaker: Option<crate::breaker::CircuitBreakerConfig>,
    /// Optional listing query for `resources/list`. On a
    /// `kind: resource_template` binding this runs at list time to
    /// enumerate concrete URIs. The query selects columns matching
    /// the MCP `Resource` descriptor shape (`uri`, `name?`,
    /// `description?`, `mime_type?`); pagination is applied
    /// server-side via the declared `mode`.
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,
    /// Optional fire-and-wait await block. When present the
    /// binding behaves as a "call this, then block until condition
    /// holds" operation: the trigger SQL (if any) fires once, then
    /// the check SQL is polled on `poll_interval_ms` until the CEL
    /// `predicate` evaluates true against the check's row or
    /// `timeout_ms` expires.
    #[serde(default)]
    pub r#await: Option<AwaitConfig>,
    /// Optional transaction isolation level applied at the
    /// start of every `sql_tx` pipeline step that targets this
    /// binding. `None` keeps the engine default. Has no effect on
    /// auto-commit `execute()` calls.
    #[serde(default)]
    pub isolation_level: Option<IsolationLevel>,
    /// Optional response cache. When `enabled: true`, the
    /// plugin opportunistically calls `BackendHost::cache_get` /
    /// `cache_put` around the query — the gateway's per-binding
    /// `BackendConfig.cache:` chooses the actual
    /// backend. With no backend wired the calls are no-ops and the
    /// path is unchanged. Validation rejects cache on row modes
    /// that aren't read-shaped (`affected_rows`, `stream`,
    /// `result_sets`) or on procedure bodies — caching anything
    /// with side effects or unbounded structural shape is unsafe.
    #[serde(default)]
    pub cache: Option<CacheSpec>,
    /// Optional cost / billing-telemetry spec. When
    /// declared, the plugin computes the actual charge after each
    /// successful execute and emits structured metrics + tracing
    /// events on `mcpg::sql::cost`. On error paths it emits a
    /// refund signal so downstream billing reconcilers can credit
    /// back the charge. The four payment plugins
    /// (`dev.mcpg.payment.{mpp,x402,ucp,acp}`) are gateway-side
    /// dispatch gates and are unaffected by this block; they keep
    /// gating per-call charges via `_meta` credentials. The
    /// `cost:` block here is the binding-side **billing
    /// telemetry** that lets per-row / per-byte / per-query
    /// shapes participate in the same accounting pipeline.
    #[serde(default)]
    pub cost: Option<CostSpec>,
    /// Cloud-DB token auth. When present, the plugin's
    /// driver layer ignores any password embedded in `url` and
    /// instead consults the configured [`AuthProvider`] for a fresh
    /// token before opening each pool connection. The provider is
    /// rotated by a background task at `token_ttl - safety_margin`
    /// so existing connections drain naturally before their token
    /// expires (the pool's `max_lifetime` is capped to match).
    ///
    /// Mutually exclusive with `${cred://…}` credential tokens inside
    /// `url` — validation rejects that combination at config-load
    /// time. Static-password URLs remain a third valid option (no
    /// `auth` block, no `${cred://…}` tokens); operators choose
    /// exactly one credential surface per binding. (A bare `cred://…`
    /// is inert — not a credential surface — so it does not conflict.)
    #[serde(default)]
    pub auth: Option<crate::auth::AuthConfig>,
}

/// Per-binding response-cache opt-in.
///
/// The gateway-side `BackendConfig.cache:`
/// already controls backend selection per binding; this block is the
/// SQL-plugin-side switch that says "for this profile, please
/// attempt cache lookup/write." Splitting concerns this way keeps
/// the SQL binding from accidentally caching a write.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CacheSpec {
    /// Master switch. `false` (default) keeps the path silent.
    #[serde(default)]
    pub enabled: bool,
    /// Per-entry TTL hint. `0` is treated as "no expiry" (still
    /// bounded by the gateway's LRU byte cap). Defaults to 60 s —
    /// short enough for most read-only OLTP work, long enough that
    /// repeated calls within a single agent loop hit the cache.
    #[serde(default = "default_cache_ttl_seconds")]
    pub ttl_seconds: u64,
    /// Optional invalidation strategy. When set, the binding
    /// spawns a watcher at `register_profile` time that bumps an
    /// internal version stamp whenever the watch source reports a
    /// change. The version is mixed into cache keys, so a bump
    /// makes every prior entry naturally miss without enumerating
    /// them in the host's cache backend.
    #[serde(default)]
    pub invalidate_on: Option<CacheInvalidateOn>,
}

/// Cache-invalidation strategy.
///
/// Today only `watch` is supported. The watcher is internal to the
/// SQL binding plugin: it shares the binding's connection details
/// (driver / url / pool) and runs a simple tracking query on a
/// fixed interval. On any cursor change the watcher bumps an
/// `AtomicU64` version that participates in cache-key composition,
/// so all old keys become unreachable in one atomic step.
///
/// Cluster correctness: each gateway instance keeps its own
/// version stamp. Caches are local to each instance, so divergent
/// versions across instances do not cause stale reads — they just
/// mean each instance re-warms independently.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CacheInvalidateOn {
    /// Periodic tracking query whose scalar result is compared
    /// across polls. On change the cache version is bumped.
    Watch {
        /// Tracking SQL — must be a SELECT returning a single
        /// scalar. Typical: `SELECT MAX(updated_at) FROM t` or
        /// `SELECT COUNT(*) FROM t`. Multi-statement bodies and
        /// privileged DDL are rejected at validate.
        sql: String,
        /// Polling interval in ms. Defaults to 1000; floor is
        /// [`crate::watch::MIN_INTERVAL_MS`] (100). Faster than the
        /// floor is nearly always a misconfiguration (DB pressure
        /// with no practical signal-latency win).
        #[serde(default = "default_invalidate_interval_ms")]
        interval_ms: u64,
    },
}

fn default_cache_ttl_seconds() -> u64 {
    60
}

fn default_invalidate_interval_ms() -> u64 {
    1_000
}

impl Default for CacheSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: default_cache_ttl_seconds(),
            invalidate_on: None,
        }
    }
}

/// Per-binding cost / billing telemetry spec.
///
/// Operators declare `cost:` on a SQL binding to opt that binding
/// into the billing-telemetry pipeline. After each successful
/// execute, the SQL plugin computes the actual charge based on
/// `unit` (per-call / per-row / per-byte / per-query) and emits:
///
/// * `mcpg_sql_cost_total{binding,driver,unit,currency}` — counter
///   in micro-units of the configured currency (so 1 USD ↦ 1_000_000)
/// * `mcpg_sql_call_cost{binding,driver,currency,unit}` — histogram
///   of per-call decimal amounts
/// * `tracing::info!(target: "mcpg::sql::cost", …)` — structured
///   audit-grade event with the full charge context
///
/// On error paths (timeout / transport / breaker / cancellation) the
/// plugin emits `mcpg_sql_cost_refunded_total{binding,driver,
/// currency,reason}` — the refund accounting signal that downstream
/// billing reconcilers consume to credit back any pre-charged amount
/// captured by the gateway-side payment plugins.
///
/// The amount is expressed as a decimal **string** so operators
/// don't lose precision on currencies with > 6 fractional digits
/// (USDC) or >> 1.0 amounts (BTC). Validation accepts any string
/// that parses as a non-negative finite f64.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CostSpec {
    /// Billing unit. Determines how the resolved base rate is
    /// amplified: PerCall / PerQuery → flat; PerRow → × `len(rows)`;
    /// PerByte → × `payload_bytes`.
    pub unit: CostUnit,
    /// Static decimal amount (string for precision). Mutually
    /// exclusive with [`Self::expression`]; exactly one MUST be set.
    /// Examples: `"0.10"`, `"0.000001"`, `"100"`. Negative values
    /// and non-finite values are rejected at validate.
    #[serde(default)]
    pub amount: Option<String>,
    /// CEL expression for dynamic pricing. Variables: `arguments`
    /// (the caller's tool args object). The expression must
    /// evaluate to a number (or a string that parses as one).
    /// Mutually exclusive with [`Self::amount`].
    #[serde(default)]
    pub expression: Option<String>,
    /// Currency code. Free-form string, defaults to `"USD"`. The
    /// SQL plugin treats this as an opaque label — currency
    /// conversion / FX is the operator's responsibility upstream.
    /// ISO 4217 codes (USD, EUR, …) and crypto codes (USDC, BTC,
    /// ETH, …) both work.
    #[serde(default = "default_cost_currency")]
    pub currency: String,
    /// Optional **per-call** cap. When the computed charge exceeds
    /// this, the call is **refused** with `InvalidSpec` — defensive
    /// against runaway costs from misconfigured CEL or extremely
    /// large row sets. Same string-decimal shape as `amount`.
    #[serde(default)]
    pub max_per_call: Option<String>,
}

/// Cost amplification unit.
///
/// `PerQuery` is a stylistic alias for `PerCall` so operators can
/// pick whichever name matches their mental model — both produce
/// flat per-execution charges with no dependence on result size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostUnit {
    /// Flat charge per `execute()` call.
    PerCall,
    /// Charge × number of returned rows. For `row_mode: scalar`
    /// this is always `1` (one scalar = one row); for `single`
    /// this is `0` (empty) or `1` (one row); for `many` /
    /// `result_sets` it tracks the actual count.
    PerRow,
    /// Charge × payload bytes (length of the serialized JSON
    /// response body). Captures egress-style billing.
    PerByte,
    /// Alias of [`Self::PerCall`]. Some operators prefer "query"
    /// when the binding represents a logical SQL query rather
    /// than a single tool invocation.
    PerQuery,
}

impl CostUnit {
    /// Stable label used in metric tags + audit fields. Lowercase
    /// snake_case, matches the `serde(rename_all)` shape so YAML
    /// values round-trip identically.
    pub fn as_str(&self) -> &'static str {
        match self {
            CostUnit::PerCall => "per_call",
            CostUnit::PerRow => "per_row",
            CostUnit::PerByte => "per_byte",
            CostUnit::PerQuery => "per_query",
        }
    }
}

fn default_cost_currency() -> String {
    "USD".into()
}

impl CostSpec {
    pub(crate) fn validate(&self) -> Result<(), SqlError> {
        match (self.amount.as_deref(), self.expression.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(SqlError::InvalidSpec(
                    "cost spec must set exactly one of `amount` or `expression`, not both".into(),
                ));
            }
            (None, None) => {
                return Err(SqlError::InvalidSpec(
                    "cost spec must set exactly one of `amount` or `expression`".into(),
                ));
            }
            (Some(amt), None) => {
                crate::cost::parse_decimal_amount(amt, "cost.amount")?;
            }
            (None, Some(expr)) => {
                if expr.trim().is_empty() {
                    return Err(SqlError::InvalidSpec(
                        "cost.expression must not be empty".into(),
                    ));
                }
                cel::Program::compile(expr).map_err(|e| {
                    SqlError::InvalidSpec(format!("cost.expression does not compile as CEL: {e}"))
                })?;
            }
        }
        if self.currency.trim().is_empty() {
            return Err(SqlError::InvalidSpec(
                "cost.currency must not be empty".into(),
            ));
        }
        // Currency labels are operator-controlled metric tags —
        // reject any character that would be problematic in a
        // Prometheus label value (newlines, control chars). We
        // intentionally do NOT enforce ISO 4217 because crypto
        // codes (USDC, ETH, …) and operator-internal codes are
        // legitimate.
        if self
            .currency
            .chars()
            .any(|c| c.is_control() || c == '\n' || c == '\t')
        {
            return Err(SqlError::InvalidSpec(format!(
                "cost.currency '{}' contains control characters",
                self.currency,
            )));
        }
        if let Some(cap) = self.max_per_call.as_deref() {
            crate::cost::parse_decimal_amount(cap, "cost.max_per_call")?;
        }
        Ok(())
    }
}

impl CacheInvalidateOn {
    pub(crate) fn validate(&self) -> Result<(), SqlError> {
        match self {
            CacheInvalidateOn::Watch { sql, interval_ms } => {
                if sql.trim().is_empty() {
                    return Err(SqlError::InvalidSpec(
                        "cache.invalidate_on.sql must not be empty".into(),
                    ));
                }
                reject_multi_statement(sql)?;
                reject_privileged_ddl(sql)?;
                if *interval_ms < 100 {
                    return Err(SqlError::InvalidSpec(format!(
                        "cache.invalidate_on.interval_ms ({interval_ms} ms) is below the 100 ms floor"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Fire-and-wait configuration.
///
/// Common use cases:
/// - "Submit job, wait for it to be done": trigger = INSERT into
///   jobs, check = SELECT status FROM jobs WHERE id = :id,
///   predicate = `row.status == "done"`.
/// - "Kick a refresh, wait for cache to update": trigger = INSERT
///   into refresh_queue, check = SELECT updated_at FROM cache WHERE
///   key = :k, predicate = `row.updated_at > arg_since`.
///
/// The check query receives the same `params` as the top-level
/// query, plus the trigger's result is available in CEL under the
/// name `trigger` if the trigger had any.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AwaitConfig {
    /// Optional trigger statement fired once before polling starts.
    /// Often an INSERT / UPDATE that kicks off the work the check
    /// is waiting on.
    #[serde(default)]
    pub trigger: Option<AwaitStep>,
    /// Poll statement whose result feeds the CEL predicate.
    /// Typically a SELECT returning a single row of status columns.
    pub check: AwaitStep,
    /// CEL expression evaluated against the check row. When the
    /// expression returns `true`, the binding returns the check
    /// row to the caller and stops polling.
    pub predicate: String,
    /// Re-poll interval, ms. Floor 100 ms to prevent DB-storm.
    #[serde(default = "default_await_poll_ms")]
    pub poll_interval_ms: u64,
    /// Total wait budget, ms. The binding surfaces a `Timeout`
    /// error when the deadline passes without the predicate
    /// turning true.
    #[serde(default = "default_await_timeout_ms")]
    pub timeout_ms: u64,
}

/// One step inside an await block — trigger or check.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AwaitStep {
    /// SQL body. Same placeholder rules as the top-level query.
    pub sql: String,
    /// Ordered placeholder names bound from the call's arguments.
    #[serde(default)]
    pub params: Vec<String>,
}

fn default_await_poll_ms() -> u64 {
    1_000
}

fn default_await_timeout_ms() -> u64 {
    60_000
}

impl AwaitConfig {
    /// Validate shape-level invariants. CEL compilation happens at
    /// `register_profile` time where the plugin holds the CEL
    /// engine handle; here we check only the declarative shape.
    pub fn validate(&self) -> Result<(), SqlError> {
        if self.check.sql.trim().is_empty() {
            return Err(SqlError::InvalidSpec(
                "await.check.sql must not be empty".into(),
            ));
        }
        reject_multi_statement(&self.check.sql)?;
        reject_privileged_ddl(&self.check.sql)?;
        if let Some(trig) = &self.trigger {
            if trig.sql.trim().is_empty() {
                return Err(SqlError::InvalidSpec(
                    "await.trigger.sql must not be empty when trigger is declared".into(),
                ));
            }
            reject_multi_statement(&trig.sql)?;
            reject_privileged_ddl(&trig.sql)?;
        }
        if self.predicate.trim().is_empty() {
            return Err(SqlError::InvalidSpec(
                "await.predicate must be a non-empty CEL expression".into(),
            ));
        }
        if self.poll_interval_ms < 100 {
            return Err(SqlError::InvalidSpec(format!(
                "await.poll_interval_ms ({}) must be >= 100",
                self.poll_interval_ms
            )));
        }
        if self.timeout_ms == 0 {
            return Err(SqlError::InvalidSpec("await.timeout_ms must be > 0".into()));
        }
        if self.timeout_ms < self.poll_interval_ms {
            return Err(SqlError::InvalidSpec(format!(
                "await.timeout_ms ({}) must be >= poll_interval_ms ({})",
                self.timeout_ms, self.poll_interval_ms
            )));
        }
        Ok(())
    }
}

/// Listing-query config. The SQL body selects rows shaped
/// as MCP `Resource` descriptors; the plugin packages them into a
/// paginated list.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ListQueryConfig {
    /// SELECT statement that returns one row per enumerable
    /// resource. Required columns: `uri`. Optional columns:
    /// `name`, `description`, `mime_type`.
    pub sql: String,
    /// Pagination mode — `keyset` or `offset`.
    #[serde(default)]
    pub mode: ListQueryMode,
    /// Column the keyset cursor tracks (typically `id` or
    /// `updated_at`). Required for `mode: keyset`. Ignored for
    /// `mode: offset`.
    #[serde(default)]
    pub cursor_column: Option<String>,
    /// Rows per page. Hard cap at 1000 to bound worst-case
    /// latency on large tables.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

/// Pagination strategy for `list_query`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListQueryMode {
    /// `WHERE cursor_column > :cursor ORDER BY cursor_column LIMIT N`.
    /// Scales with table size; use this for anything large.
    #[default]
    Keyset,
    /// `LIMIT N OFFSET :offset`. Simple but O(offset) on the DB
    /// side; use only when the listing is small and bounded.
    Offset,
}

fn default_list_page_size() -> u64 {
    100
}

impl ListQueryConfig {
    /// Validate bounds + mode coherence.
    pub fn validate(&self) -> Result<(), SqlError> {
        if self.sql.trim().is_empty() {
            return Err(SqlError::InvalidSpec(
                "list_query.sql must not be empty".into(),
            ));
        }
        reject_multi_statement(&self.sql)?;
        reject_privileged_ddl(&self.sql)?;
        if self.page_size == 0 || self.page_size > 1_000 {
            return Err(SqlError::InvalidSpec(format!(
                "list_query.page_size ({}) must be in 1..=1000",
                self.page_size
            )));
        }
        if self.mode == ListQueryMode::Keyset {
            let col = self.cursor_column.as_deref().unwrap_or("").trim();
            if col.is_empty() {
                return Err(SqlError::InvalidSpec(
                    "list_query.cursor_column is required for mode: keyset".into(),
                ));
            }
            if !is_safe_sql_identifier(col) {
                return Err(SqlError::InvalidSpec(format!(
                    "list_query.cursor_column '{col}' is not a safe SQL identifier"
                )));
            }
        }
        Ok(())
    }
}

/// Connection pool knobs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// Hard cap on the pool size.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Minimum idle connections to keep warm.
    #[serde(default = "default_min_idle")]
    pub min_idle: u32,
    /// Wait budget for acquiring a connection from the pool.
    #[serde(default = "default_acquire_timeout_ms")]
    pub acquire_timeout_ms: u64,
    /// Evict idle connections older than this.
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Hard cap on a single connection's lifetime.
    #[serde(default = "default_max_lifetime_ms")]
    pub max_lifetime_ms: u64,
    /// Whether to ping the connection before handing it out.
    #[serde(default = "default_test_before_acquire")]
    pub test_before_acquire: bool,
    /// Whether to verify the pool user has the privileges required for
    /// driver-level cancel before accepting registration.
    /// Currently meaningful for MySQL / MariaDB (`PROCESS` or
    /// `CONNECTION_ADMIN` is required to send `KILL QUERY` against
    /// another connection); other drivers no-op the probe and always
    /// pass. Default `true` so silent cancel-becomes-no-op degradation
    /// surfaces at startup. Set `false` for pool roles that
    /// intentionally lack the privilege.
    #[serde(default = "default_require_cancel_privilege")]
    pub require_cancel_privilege: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            min_idle: default_min_idle(),
            acquire_timeout_ms: default_acquire_timeout_ms(),
            idle_timeout_ms: default_idle_timeout_ms(),
            max_lifetime_ms: default_max_lifetime_ms(),
            test_before_acquire: default_test_before_acquire(),
            require_cancel_privilege: default_require_cancel_privilege(),
        }
    }
}

fn default_max_connections() -> u32 {
    10
}
fn default_min_idle() -> u32 {
    0
}
fn default_acquire_timeout_ms() -> u64 {
    5_000
}
fn default_idle_timeout_ms() -> u64 {
    300_000
}
fn default_max_lifetime_ms() -> u64 {
    1_800_000
}
fn default_test_before_acquire() -> bool {
    true
}
fn default_require_cancel_privilege() -> bool {
    true
}

/// Mutually exclusive query body — exactly one of `sql`, `procedure`,
/// `sql_file`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum QueryBody {
    /// Inline SQL text with named/positional placeholders.
    Sql {
        /// Raw SQL statement, one statement per profile.
        sql: String,
    },
    /// Named stored procedure/function invocation.
    Procedure {
        /// Schema-qualified procedure name (e.g. `orders.get_summary`).
        procedure: String,
    },
    /// Path to a `.sql` file resolved at registration time.
    SqlFile {
        /// Filesystem path to a single-statement `.sql` file.
        sql_file: PathBuf,
    },
}

/// How the result rows are shaped for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowMode {
    /// Return a single row (or JSON `null` if no rows).
    Single,
    /// Return a JSON array of rows, truncated at `max_rows`.
    Many,
    /// Return the first column of the first row as a scalar.
    Scalar,
    /// Return `{"rows_affected": N}` for write statements.
    AffectedRows,
    /// Wrap rows as an MCP `resources/read` response payload —
    /// `{"contents": [{"uri": ..., "text"|"blob": ..., "mimeType"?: ...}]}`.
    ///
    /// Used on `kind: "resource"` / `kind: "resource_template"` SQL
    /// bindings so operators don't hand-write engine-specific JSON
    /// aggregation (Postgres `json_build_object`, MySQL
    /// `JSON_OBJECT`, …). The query SELECTs columns named `uri`,
    /// `text` (or `blob`), and optionally `mime_type`; the plugin
    /// assembles the contract shape the gateway's resource decoder
    /// expects.
    ResourceContents,
    /// Streaming shape. Response payload is
    /// `{"rows": [...], "next_cursor": <opt>, "truncated": <bool>}`
    /// so clients can iterate a large result set across multiple
    /// tool calls.
    ///
    /// Current semantics: returns the first `max_rows` rows along
    /// with `next_cursor: null` and `truncated: true` whenever rows
    /// were actually dropped. Server-side cursor continuation
    /// (`DECLARE CURSOR` on Postgres, fetch_more on follow-up calls)
    /// lands in a later slice — the response shape is stable so
    /// clients can code against it now.
    Stream,
    /// Multi-result-set shape. Response payload is
    /// `{"result_sets": [[<row>, …], [<row>, …], …]}` — an array of
    /// row arrays, one per result set the procedure yielded.
    ///
    /// Required pairing: `query.body` must be `Procedure { … }` —
    /// stored procedures are the only call shape that can yield
    /// multiple result sets. The driver matrix supports this on
    /// MySQL / MariaDB only; Postgres + SQLite reject it at config
    /// validate (Postgres functions / procedures return at most one
    /// set; SQLite has no procedure concept).
    ///
    /// Per-result-set truncation is **not** applied in this shape —
    /// `max_rows` is checked against the total row count across all
    /// sets and the response carries a `truncated: true` field at
    /// the wrapper level when the caller asked for fewer total rows
    /// than the procedure produced.
    ResultSets,
}

/// Query shape — the body plus param/rowmode/limit knobs.
///
/// `deny_unknown_fields` is intentionally not applied here because the
/// struct uses `#[serde(flatten)]` for the untagged [`QueryBody`]
/// enum — serde rejects that combination. Individual query-body
/// variants enforce their own field names via the untagged match.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueryShape {
    /// Exactly one of `sql`, `procedure`, `sql_file` (captured via
    /// `#[serde(flatten)]` against the untagged [`QueryBody`] enum).
    #[serde(flatten)]
    pub body: QueryBody,
    /// Ordered list of tool argument names that bind to the query's
    /// placeholders.
    #[serde(default)]
    pub params: Vec<String>,
    /// CEL-computed parameters. Compiled at registration and
    /// evaluated against the call's arguments at execute time, with
    /// results injected into the args map before placeholder binding.
    #[serde(default)]
    pub param_exprs: BTreeMap<String, String>,
    /// Row shape selector.
    pub row_mode: RowMode,
    /// Hard cap on returned row count (defaults to `1000`).
    #[serde(default = "default_max_rows")]
    pub max_rows: u64,
    /// Per-call timeout in ms. `None` → use the driver default.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Tag the query as read-only; enforced as `read_only` transaction
    /// mode where the driver supports it.
    #[serde(default)]
    pub read_only: bool,
    /// Emit an in-flight progress heartbeat every N ms while the query
    /// is running. `None` disables heartbeats (the default). The
    /// plugin logs a `tracing` event and bumps the
    /// `mcpg_sql_progress_heartbeats_total` counter on each tick — the
    /// mechanism is wired so that progressToken-bearing MCP requests
    /// can be fanned out to the client as soon as the plugin API grows
    /// a progress sink on [`BackendRequest`].
    #[serde(default)]
    pub progress_heartbeat_ms: Option<u64>,
    /// Stream-cursor configuration. Required when
    /// `row_mode: stream`; rejected for other row modes. Declares
    /// the keyset columns the plugin uses to encode an opaque
    /// `next_cursor` token, plus optional initial values bound to
    /// the `:_after_<col>` placeholders on the first page. See
    /// [`crate::stream::StreamConfig`] for the schema.
    #[serde(default)]
    pub stream: Option<crate::stream::StreamConfig>,
}

fn default_max_rows() -> u64 {
    1_000
}

impl SqlBackendConfig {
    /// Validate the static contents of the config. Called after serde
    /// has populated the struct but before the plugin begins any I/O.
    ///
    /// Enforces: valid URL with the right scheme for the declared
    /// driver; positive pool sizes; heartbeat floor; safe session-var
    /// identifiers. Passwords may appear in the URL — the gateway
    /// interpolator is expected to have expanded `${env.*}` before the
    /// spec reaches this validator, so literal secrets never live in
    /// YAML source.
    pub fn validate(&self) -> Result<(), SqlError> {
        let parsed = url::Url::parse(&self.url)
            .map_err(|e| SqlError::InvalidSpec(format!("url parse failed: {e}")))?;

        // Driver / scheme match — Postgres accepts both `postgres` and
        // `postgresql`; MySQL accepts both `mysql` and `mariadb`.
        let scheme = parsed.scheme();
        match self.driver {
            DriverKind::Postgres => {
                if scheme != "postgres" && scheme != "postgresql" {
                    return Err(SqlError::InvalidSpec(format!(
                        "driver=postgres expects url scheme 'postgres' or 'postgresql', got '{scheme}'"
                    )));
                }
            }
            DriverKind::Mysql | DriverKind::Mariadb => {
                if scheme != "mysql" && scheme != "mariadb" {
                    return Err(SqlError::InvalidSpec(format!(
                        "driver=mysql expects url scheme 'mysql' or 'mariadb', got '{scheme}'"
                    )));
                }
            }
            DriverKind::Sqlite => {
                if scheme != "sqlite" {
                    return Err(SqlError::InvalidSpec(format!(
                        "driver=sqlite expects url scheme 'sqlite', got '{scheme}'"
                    )));
                }
            }
        }

        // Auth-block sanity. Validate the auth's own
        // shape, then cross-check with URL credential surface so
        // operators don't accidentally combine static passwords +
        // dynamic tokens (only the most-derived would ever apply,
        // silently ignoring the other — bad).
        if let Some(auth) = &self.auth {
            auth.validate().map_err(SqlError::from)?;
            // The auth block currently targets only Postgres
            // because RDS IAM is the only landed scheme and
            // RDS-IAM-on-MySQL is a follow-up. Rejecting up front
            // keeps operators from configuring a no-op block.
            match self.driver {
                DriverKind::Postgres => {}
                DriverKind::Mysql | DriverKind::Mariadb | DriverKind::Sqlite => {
                    return Err(SqlError::InvalidSpec(format!(
                        "auth: {{ kind: {} }} requires driver: postgres in this build; \
                         MySQL/MariaDB on RDS is not yet supported, SQLite cannot be \
                         IAM-authed",
                        auth.scheme(),
                    )));
                }
            }
            // The URL must NOT carry an embedded password when an
            // auth provider is wired — that's two credential
            // surfaces and the runtime would silently pick whichever
            // string-substitution path ran last. Reject at validate.
            if !parsed.password().unwrap_or("").is_empty() {
                return Err(SqlError::InvalidSpec(
                    "auth: { ... } block is mutually exclusive with a password embedded \
                     in `url`. Drop the `:password@` segment; the auth provider \
                     supplies the password at connect time."
                        .into(),
                ));
            }
            // `${cred://…}` tokens in the URL are also a separate
            // credential surface (per-caller dynamic creds). Two
            // dynamic surfaces is a misconfiguration — reject. A bare
            // `cred://…` is inert (travels verbatim, never resolved),
            // so it is not counted here.
            if !mcpg_plugin_protocol::credential::cred_tokens(&self.url).is_empty() {
                return Err(SqlError::InvalidSpec(
                    "auth: { ... } block is mutually exclusive with `${cred://…}` tokens \
                     in `url`. Pick one: cloud-IAM auth, or per-caller dynamic creds."
                        .into(),
                ));
            }
        }

        if self.pool.max_connections == 0 {
            return Err(SqlError::InvalidSpec(
                "pool.max_connections must be > 0".into(),
            ));
        }
        if self.pool.min_idle > self.pool.max_connections {
            return Err(SqlError::InvalidSpec(
                "pool.min_idle must be <= pool.max_connections".into(),
            ));
        }

        // Stream mode requires `stream:` config (cursor_columns +
        // optional bootstrap values); other row modes must NOT carry
        // it — `stream:` on a non-stream binding is a config typo
        // worth catching at validate time so it doesn't silently
        // become a no-op at runtime.
        match &self.query.row_mode {
            RowMode::Stream => {
                let stream_cfg = self.query.stream.as_ref().ok_or_else(|| {
                    SqlError::InvalidSpec(
                        "row_mode: stream requires a `stream:` block declaring \
                         cursor_columns"
                            .into(),
                    )
                })?;
                stream_cfg.validate()?;

                // Operator-authored SQL must reference each
                // `:_after_<col>` placeholder so the plugin can bind
                // last-row values on continuation. Skip for sql_file
                // — file contents are loaded later in
                // `prepare_stmt`; the same check runs there.
                if let QueryBody::Sql { sql } = &self.query.body {
                    for ph in stream_cfg.placeholder_names() {
                        if !sql.contains(&format!(":{ph}")) {
                            return Err(SqlError::InvalidSpec(format!(
                                "row_mode: stream — query.sql must reference \
                                 placeholder `:{ph}` (one per declared \
                                 stream.cursor_columns column). The plugin \
                                 binds last-row keyset values to these \
                                 placeholders for continuation calls."
                            )));
                        }
                    }
                }
            }
            RowMode::Single
            | RowMode::Many
            | RowMode::Scalar
            | RowMode::AffectedRows
            | RowMode::ResourceContents
            | RowMode::ResultSets => {
                if self.query.stream.is_some() {
                    return Err(SqlError::InvalidSpec(
                        "query.stream is only valid when row_mode is `stream` \
                         — remove the block or set row_mode: stream."
                            .into(),
                    ));
                }
            }
        }

        // result_sets requires a procedure body and is only
        // supported on engines that surface multi-result-set output
        // through their driver protocol. MySQL/MariaDB CALL
        // procedures fit; Postgres procedures / functions return a
        // single result set; SQLite has no procedure concept at
        // all.
        if matches!(self.query.row_mode, RowMode::ResultSets) {
            if !matches!(&self.query.body, QueryBody::Procedure { .. }) {
                return Err(SqlError::InvalidSpec(
                    "row_mode: result_sets requires `query.procedure` — \
                     only stored procedures yield multiple result sets. \
                     Switch to `row_mode: many` for SELECTs that return \
                     a single set."
                        .into(),
                ));
            }
            match self.driver {
                DriverKind::Mysql | DriverKind::Mariadb => {}
                DriverKind::Postgres => {
                    return Err(SqlError::InvalidSpec(
                        "row_mode: result_sets is not supported on \
                         Postgres — `CALL <proc>` returns at most one \
                         result set. Use `row_mode: many` instead."
                            .into(),
                    ));
                }
                DriverKind::Sqlite => {
                    return Err(SqlError::InvalidSpec(
                        "row_mode: result_sets is not supported on \
                         SQLite — the engine has no stored-procedure \
                         concept. Use `row_mode: many` for SELECTs."
                            .into(),
                    ));
                }
            }
        }

        if let Some(ms) = self.query.progress_heartbeat_ms {
            // 50 ms floor — heartbeats faster than that flood logs and
            // metrics without adding signal. A typical setting is
            // 1_000–5_000 ms, well above the floor.
            if ms < 50 {
                return Err(SqlError::InvalidSpec(format!(
                    "query.progress_heartbeat_ms ({ms} ms) is below the 50 ms floor"
                )));
            }
        }

        // Circuit breaker — validate thresholds if present.
        if let Some(cb) = &self.circuit_breaker {
            cb.validate()?;
        }

        // list_query — validate shape if present.
        if let Some(lq) = &self.list_query {
            lq.validate()?;
        }

        // await — validate shape if present. CEL predicate
        // compilation runs at `register_profile` time where the
        // plugin holds the cel::Program engine.
        if let Some(aw) = &self.r#await {
            aw.validate()?;
        }

        // Cache safety — only enable on read-shaped row_modes
        // and never on procedure bodies. Caching anything that has
        // side effects (write statements, procedures with `OUT`
        // params or implicit transactions) would silently serve
        // stale state to callers and never re-execute the
        // side-effecting work.
        if let Some(cache) = &self.cache
            && cache.enabled
        {
            match self.query.row_mode {
                RowMode::Single | RowMode::Many | RowMode::Scalar | RowMode::ResourceContents => {}
                RowMode::AffectedRows => {
                    return Err(SqlError::InvalidSpec(
                        "cache.enabled is invalid for row_mode: affected_rows — \
                         caching a write statement would silently skip its side \
                         effect on hits."
                            .into(),
                    ));
                }
                RowMode::Stream => {
                    return Err(SqlError::InvalidSpec(
                        "cache.enabled is invalid for row_mode: stream — \
                         streaming responses are paged via keyset cursor and \
                         each page would need its own cache entry; not yet \
                         supported."
                            .into(),
                    ));
                }
                RowMode::ResultSets => {
                    return Err(SqlError::InvalidSpec(
                        "cache.enabled is invalid for row_mode: result_sets — \
                         stored procedures may have side effects (OUT params, \
                         implicit transactions) that must run every call."
                            .into(),
                    ));
                }
            }
            if matches!(self.query.body, QueryBody::Procedure { .. }) {
                return Err(SqlError::InvalidSpec(
                    "cache.enabled is invalid when query.body is a procedure — \
                     procedures may have side effects that must run every call."
                        .into(),
                ));
            }
            // ttl_seconds == 0 is the explicit operator choice for
            // "no expiry, evict only via LRU byte cap." That's a
            // valid setting, so we don't reject it here.
            if let Some(inv) = &cache.invalidate_on {
                inv.validate()?;
            }
        }

        // Cost / billing telemetry — validate amount / expr /
        // currency / cap shape if present. Cost is observation-only
        // (no row-mode coupling), so we don't gate it on the row
        // mode the way cache is.
        if let Some(cost_cfg) = &self.cost {
            cost_cfg.validate()?;
        }

        // `session_vars` keys are inlined into the engine's session-var
        // SET command at execute time (Postgres `set_config(...)`,
        // MySQL `SET @<key> = ?`) — they cannot be parameter-bound
        // because SQL does not parameterize identifiers. Validate each
        // key to reject anything that could break out of the identifier
        // position.
        for key in self.session_vars.keys() {
            if !is_safe_sql_identifier(key) {
                return Err(SqlError::InvalidSpec(format!(
                    "session_vars: '{key}' is not a safe SQL identifier \
                     (allowed: ASCII letters, digits, `_`, `.`)"
                )));
            }
        }

        // Driver compatibility for session_vars:
        // - Postgres / MySQL / MariaDB: full support (Postgres uses
        //   `SELECT set_config(name, value, true)` for tx-local scope;
        //   MySQL/MariaDB use `SET @<name> = ?` user variables on a
        //   pinned connection, reset to NULL when the connection
        //   returns to the pool).
        // - MySQL/MariaDB additionally rejects dotted names because
        //   user-variable identifiers cannot contain `.`. Operators
        //   typically use `app.tenant_id` style on Postgres; for
        //   MySQL we make them rename to `app_tenant_id` so the
        //   user-var name is unambiguous.
        // - SQLite: SQLite has no engine-level session-variable
        //   concept (no `SET LOCAL`, no user variables — `PRAGMA` is
        //   connection-scoped, not transaction-scoped). Rather than
        //   silently dropping the operator's intent, reject the
        //   binding outright with a clear error.
        if !self.session_vars.is_empty() {
            match self.driver {
                DriverKind::Postgres => {}
                DriverKind::Mysql | DriverKind::Mariadb => {
                    for key in self.session_vars.keys() {
                        if key.contains('.') {
                            return Err(SqlError::InvalidSpec(format!(
                                "session_vars: '{key}' contains '.', which is not \
                                 valid in a MySQL/MariaDB user-variable name. \
                                 Rename to '{}' (replace dots with underscores).",
                                key.replace('.', "_")
                            )));
                        }
                    }
                }
                DriverKind::Sqlite => {
                    return Err(SqlError::InvalidSpec(
                        "session_vars: SQLite has no transaction-scoped \
                         session-variable concept (no SET LOCAL, no user \
                         variables). Remove `session_vars` or switch the \
                         binding to Postgres / MySQL."
                            .into(),
                    ));
                }
            }
        }

        // --- SQL injection defenses (P11.x hardening) -----------------
        //
        // Parameter *values* are always bound via prepared statements
        // (sqlx `$1`/`?`), so they cannot tamper with the statement
        // structure. The remaining injection surfaces are config-side
        // strings that the plugin inlines into the query text rather
        // than binding:
        //
        // 1. `query.procedure` is embedded as `CALL <procedure>(...)`.
        //    If an attacker controlled this (via compromised config or
        //    a misconfigured templating pipeline), they could break
        //    out of the CALL. Enforce the same identifier safety we
        //    use for session_vars keys — dotted names allowed so
        //    `schema.proc_name` keeps working.
        //
        // 2. `query.sql` and `query.sql_file` are operator-trusted by
        //    design (operators declare SQL intentionally), but a multi-
        //    statement body defeats placeholder binding *and* is the
        //    classic stacked-query SQLi vector. Reject unquoted `;`
        //    separators — single-statement bodies only. Multi-step
        //    work belongs in `kind: pipeline` with `sql_tx`.
        match &self.query.body {
            QueryBody::Procedure { procedure } => {
                if !is_safe_sql_identifier(procedure) {
                    return Err(SqlError::InvalidSpec(format!(
                        "query.procedure: '{procedure}' is not a safe SQL identifier \
                         (allowed: ASCII letters, digits, `_`, `.`). Embedded as \
                         `CALL <procedure>(...)` — binding a non-identifier would \
                         corrupt the statement structure."
                    )));
                }
            }
            QueryBody::Sql { sql } => {
                reject_multi_statement(sql)?;
                reject_privileged_ddl(sql)?;
            }
            // `sql_file` is read + validated at register_profile time
            // (see SqlBackendPlugin::prepare_stmt) — the same multi-
            // statement check runs there, since the file contents
            // aren't available here.
            QueryBody::SqlFile { .. } => {}
        }

        if let Some(level) = self.isolation_level
            && matches!(self.driver, DriverKind::Sqlite)
            && !matches!(level, IsolationLevel::Serializable)
        {
            return Err(SqlError::InvalidSpec(format!(
                "isolation_level={level:?}: SQLite is always serializable; \
                 drop the field or set it to 'serializable'",
            )));
        }

        Ok(())
    }
}

/// Reject SQL bodies containing more than one statement. A single
/// trailing `;` is allowed (operators end statements out of habit);
/// anything else earns an `InvalidSpec`.
///
/// The scan is quote-aware — `;` inside a `'...'` or `"..."` literal
/// doesn't count, matching the tokenization the placeholder rewrite
/// uses. PostgreSQL dollar-quoted strings (`$tag$...$tag$`) are not
/// special-cased; bindings using them should switch to `sql_file`.
pub(crate) fn reject_multi_statement(sql: &str) -> Result<(), SqlError> {
    let bytes = sql.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut last_semi: Option<usize> = None;
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b';' if !in_single && !in_double => {
                if last_semi.is_some() {
                    // Two unquoted semicolons at the top level is
                    // definitively multi-statement, regardless of
                    // what sits between them.
                    return Err(SqlError::InvalidSpec(format!(
                        "query.sql contains multiple statements (unquoted `;` at byte {i}); \
                         split the work into pipeline steps or use `kind: pipeline` + \
                         `sql_tx` for atomic multi-step work"
                    )));
                }
                last_semi = Some(i);
            }
            _ => {}
        }
    }
    // One semicolon is OK if only whitespace follows. Anything else
    // after it is a second statement.
    if let Some(prev) = last_semi {
        let tail = &sql[prev + 1..];
        if tail.trim().chars().any(|ch| !ch.is_whitespace()) {
            return Err(SqlError::InvalidSpec(format!(
                "query.sql contains content after trailing `;` (byte {prev}); \
                 single-statement bodies only"
            )));
        }
    }
    Ok(())
}

/// Return true if `s` is a safe SQL identifier for inline use — ASCII
/// letters / digits / underscore, with dots allowed for namespaced
/// settings like `app.current_tenant` (Postgres GUC convention).
///
/// The value going into `SET LOCAL <id> = $1` *is* parameter-bound, so
/// this check is purely about the identifier side of the statement.
pub(crate) fn is_safe_sql_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Reject privileged DDL (role / grant / user management) at config
/// parse.
///
/// The SQL binding is intended for application-scoped data access,
/// not schema/role administration. An operator accidentally (or
/// maliciously) including a statement like `GRANT ALL ON t TO PUBLIC`
/// in a tool binding silently escalates privileges the next time the
/// tool fires. Rejecting at config parse turns that into a loud
/// startup failure. Operators who genuinely need privileged DDL must
/// configure it on a separately-scoped admin binding reachable only
/// by high-trust principals (gated via `governance.minimum_trust =
/// "verified"` + allowlist CEL).
///
/// Checks the **first statement keyword** after skipping leading
/// whitespace and SQL comments (`-- ...` to EOL, `/* ... */`
/// non-nested). The scan is conservative — unusual forms (dollar-
/// quoted strings, dynamic SQL via `EXECUTE format(...)`) aren't
/// special-cased; operators using them should factor the query into
/// a stored procedure and expose that via `QueryBody::Procedure`.
pub(crate) fn reject_privileged_ddl(sql: &str) -> Result<(), SqlError> {
    let trimmed = strip_leading_whitespace_and_comments(sql);
    let first_token = trimmed
        .split(|c: char| !c.is_ascii_alphabetic() && c != '_')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if first_token.is_empty() {
        return Ok(());
    }
    // Reject the classic auth-DDL leading keywords outright. These
    // forms never have a legitimate place in an application-scoped
    // binding.
    let blocked_leading: &[&str] = &["GRANT", "REVOKE"];
    if blocked_leading.contains(&first_token.as_str()) {
        return Err(SqlError::InvalidSpec(format!(
            "query.sql leads with privileged DDL keyword `{first_token}`. \
             Auth/role management must live in a separately-scoped admin \
             binding — not a tool-accessible SQL binding."
        )));
    }
    // For CREATE / ALTER / DROP, the discriminator is the *second*
    // word: `CREATE USER`, `ALTER ROLE`, `DROP DATABASE` are blocked;
    // `CREATE TABLE`, `ALTER INDEX`, `DROP INDEX` are application-
    // level and pass through. This keeps schema migrations possible
    // while blocking privilege escalation.
    if matches!(first_token.as_str(), "CREATE" | "ALTER" | "DROP") {
        let rest = &trimmed[first_token.len()..];
        let rest_trimmed = strip_leading_whitespace_and_comments(rest);
        let second_token = rest_trimmed
            .split(|c: char| !c.is_ascii_alphabetic() && c != '_')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let blocked_second: &[&str] = &["USER", "ROLE", "DATABASE", "GROUP"];
        if blocked_second.contains(&second_token.as_str()) {
            return Err(SqlError::InvalidSpec(format!(
                "query.sql starts with privileged DDL `{first_token} {second_token}`. \
                 Role / user / database management must live in a separately-scoped \
                 admin binding — not a tool-accessible SQL binding."
            )));
        }
    }
    Ok(())
}

/// Skip leading whitespace, `-- ...` line comments, and `/* ... */`
/// block comments (non-nested). Used by [`reject_privileged_ddl`] so
/// `-- admin override\nGRANT …` doesn't slip past the guard.
fn strip_leading_whitespace_and_comments(s: &str) -> &str {
    let mut rest = s;
    loop {
        let next = rest.trim_start();
        if let Some(after_line) = next.strip_prefix("--") {
            // Drop to end of line.
            if let Some(nl_pos) = after_line.find('\n') {
                rest = &after_line[nl_pos + 1..];
            } else {
                return "";
            }
            continue;
        }
        if let Some(after_open) = next.strip_prefix("/*") {
            if let Some(close_pos) = after_open.find("*/") {
                rest = &after_open[close_pos + 2..];
            } else {
                // Unclosed block comment — leave the scan where we
                // are; the caller's other checks surface any real
                // parse issue.
                return "";
            }
            continue;
        }
        return next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(url: &str, driver: DriverKind) -> SqlBackendConfig {
        SqlBackendConfig {
            driver,
            url: url.into(),
            pool: PoolConfig::default(),
            allow_private_backends: false,
            query: QueryShape {
                body: QueryBody::Sql {
                    sql: "SELECT 1".into(),
                },
                params: vec![],
                param_exprs: BTreeMap::new(),
                row_mode: RowMode::Scalar,
                max_rows: 1,
                timeout_ms: None,
                read_only: true,
                progress_heartbeat_ms: None,
                stream: None,
            },
            session_vars: BTreeMap::new(),
            schema: crate::schema::SchemaConfig::default(),
            circuit_breaker: None,
            list_query: None,
            r#await: None,
            isolation_level: None,
            cache: None,
            cost: None,
            auth: None,
        }
    }

    #[test]
    fn validate_accepts_password_in_url() {
        // Passwords in the URL are fine — operators route them through
        // the gateway interpolator (`${env.PW}`) before the spec
        // reaches the plugin, so no literal secret lives in YAML.
        let cfg = minimal("postgres://u:secret@host/db", DriverKind::Postgres);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_accepts_postgresql_scheme() {
        let cfg = minimal("postgresql://u@host/db", DriverKind::Postgres);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_scheme_mismatch() {
        let cfg = minimal("mysql://u@host/db", DriverKind::Postgres);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_allows_sqlite_memory() {
        let cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_requires_pool_positive() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.pool.max_connections = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_progress_heartbeat_below_floor() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.progress_heartbeat_ms = Some(10);
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("heartbeat")));
    }

    #[test]
    fn validate_accepts_progress_heartbeat_at_and_above_floor() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.progress_heartbeat_ms = Some(50);
        assert!(cfg.validate().is_ok());
        cfg.query.progress_heartbeat_ms = Some(5_000);
        assert!(cfg.validate().is_ok());
    }

    // ------------------------------------------------------------------
    // stream config validation
    // ------------------------------------------------------------------

    fn stream_cfg(cols: &[&str]) -> crate::stream::StreamConfig {
        crate::stream::StreamConfig {
            cursor_columns: cols.iter().map(|s| (*s).into()).collect(),
            initial: serde_json::Map::new(),
            signing_key: None,
        }
    }

    #[test]
    fn validate_stream_requires_stream_block() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::Sql {
            sql: "SELECT id FROM t ORDER BY id LIMIT 100".into(),
        };
        // No `stream:` block — must fail.
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("requires a `stream:` block"), "got: {msg}");
    }

    #[test]
    fn validate_stream_requires_after_placeholder() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::Sql {
            // Missing `:_after_id` placeholder.
            sql: "SELECT id FROM t ORDER BY id LIMIT 100".into(),
        };
        cfg.query.stream = Some(stream_cfg(&["id"]));
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(":_after_id"), "got: {msg}");
    }

    #[test]
    fn validate_stream_accepts_well_formed_sql_with_placeholder() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::Sql {
            sql: "SELECT id, name FROM t WHERE id > :_after_id \
                  ORDER BY id LIMIT :max_rows"
                .into(),
        };
        cfg.query.stream = Some(stream_cfg(&["id"]));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_stream_accepts_composite_key_with_all_placeholders() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::Sql {
            sql: "SELECT id, created_at FROM t \
                  WHERE (created_at, id) > (:_after_created_at, :_after_id) \
                  ORDER BY created_at, id LIMIT 100"
                .into(),
        };
        cfg.query.stream = Some(stream_cfg(&["created_at", "id"]));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_stream_rejects_partial_placeholders() {
        // Operator declared two cursor columns but the SQL only
        // references one placeholder — should fail loudly.
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::Sql {
            sql: "SELECT id, created_at FROM t \
                  WHERE created_at > :_after_created_at \
                  ORDER BY created_at LIMIT 100"
                .into(),
        };
        cfg.query.stream = Some(stream_cfg(&["created_at", "id"]));
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(":_after_id"), "got: {msg}");
    }

    #[test]
    fn validate_non_stream_rejects_stream_block() {
        // `stream:` on a non-stream binding is a config typo —
        // catch it early.
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Many;
        cfg.query.stream = Some(stream_cfg(&["id"]));
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("only valid when row_mode is `stream`"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_stream_rejects_invalid_inner_config() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::Sql {
            sql: "SELECT 1 WHERE 1 = :_after_x".into(),
        };
        // Empty cursor_columns — inner StreamConfig::validate should
        // fire from inside the parent validator.
        cfg.query.stream = Some(crate::stream::StreamConfig {
            cursor_columns: vec![],
            initial: serde_json::Map::new(),
            signing_key: None,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_stream_skips_placeholder_check_for_sql_file() {
        // `sql_file` is loaded later in prepare_stmt; the
        // placeholder check runs there. validate() at parse time
        // accepts the body so file-based bindings don't fail
        // before the file is even read.
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.row_mode = RowMode::Stream;
        cfg.query.body = QueryBody::SqlFile {
            sql_file: "/tmp/q.sql".into(),
        };
        cfg.query.stream = Some(stream_cfg(&["id"]));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn query_body_accepts_each_shape() {
        let s: QueryBody = serde_json::from_value(serde_json::json!({"sql": "SELECT 1"})).unwrap();
        assert!(matches!(s, QueryBody::Sql { .. }));
        let p: QueryBody = serde_json::from_value(serde_json::json!({"procedure": "x.y"})).unwrap();
        assert!(matches!(p, QueryBody::Procedure { .. }));
        let f: QueryBody =
            serde_json::from_value(serde_json::json!({"sql_file": "/tmp/q.sql"})).unwrap();
        assert!(matches!(f, QueryBody::SqlFile { .. }));
    }

    // ------------------------------------------------------------------
    // SQL injection defenses
    // ------------------------------------------------------------------

    fn with_procedure(name: &str) -> SqlBackendConfig {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.body = QueryBody::Procedure {
            procedure: name.to_string(),
        };
        cfg
    }

    #[test]
    fn validate_accepts_dotted_procedure_name() {
        let cfg = with_procedure("schema.get_customer");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_procedure_with_injection_payload() {
        // If an attacker controlled cfg.query.procedure (compromised
        // config, broken templating, etc.), they could embed
        // stacked-query SQL. The config validator catches it before
        // the plugin builds the CALL statement.
        let cfg = with_procedure("get_customer; DROP TABLE users;--");
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, SqlError::InvalidSpec(msg) if msg.contains("procedure") && msg.contains("safe SQL identifier"))
        );
    }

    #[test]
    fn validate_rejects_procedure_with_spaces() {
        let cfg = with_procedure("get customer");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_procedure() {
        let cfg = with_procedure("");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_multi_statement_allows_single_statement() {
        assert!(reject_multi_statement("SELECT 1").is_ok());
        assert!(reject_multi_statement("SELECT 1;").is_ok());
        assert!(reject_multi_statement("SELECT 1;  \n  ").is_ok());
    }

    #[test]
    fn reject_multi_statement_rejects_stacked_query() {
        let err = reject_multi_statement("SELECT 1; DROP TABLE users").unwrap_err();
        assert!(
            matches!(err, SqlError::InvalidSpec(msg) if msg.contains("multiple statements") || msg.contains("trailing"))
        );
    }

    #[test]
    fn reject_multi_statement_tolerates_semicolons_in_string_literals() {
        // A `;` inside a quoted string isn't a statement separator.
        assert!(reject_multi_statement("SELECT 'a; b' AS txt").is_ok());
        assert!(reject_multi_statement("SELECT \"col;name\" FROM t").is_ok());
    }

    #[test]
    fn validate_rejects_multi_statement_sql_body() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.body = QueryBody::Sql {
            sql: "SELECT 1; SELECT 2".into(),
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(_)));
    }

    // ------------------------------------------------------------------
    // Privileged DDL guard
    // ------------------------------------------------------------------

    #[test]
    fn reject_privileged_ddl_blocks_grant_revoke() {
        let err = reject_privileged_ddl("GRANT ALL ON orders TO public").unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("GRANT")));
        let err = reject_privileged_ddl("REVOKE ALL ON orders FROM public").unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("REVOKE")));
    }

    #[test]
    fn reject_privileged_ddl_blocks_role_user_db_ddl() {
        let blocked = &[
            "CREATE USER evil WITH PASSWORD 'p'",
            "alter user admin set password='p'",
            "DROP USER victim",
            "CREATE ROLE admin",
            "ALTER ROLE admin SUPERUSER",
            "DROP ROLE admin",
            "CREATE DATABASE evil",
            "DROP DATABASE victim",
            "CREATE GROUP evil",
        ];
        for s in blocked {
            let err = reject_privileged_ddl(s).unwrap_err();
            assert!(
                matches!(&err, SqlError::InvalidSpec(m) if m.contains("privileged DDL")),
                "expected rejection for `{s}`, got {err:?}"
            );
        }
    }

    #[test]
    fn reject_privileged_ddl_allows_application_ddl() {
        // CREATE/ALTER/DROP of regular object types is not a
        // privilege-escalation vector — operators who need schema
        // migrations inside a binding keep working.
        let allowed = &[
            "CREATE TABLE orders (id INT)",
            "ALTER TABLE orders ADD COLUMN total INT",
            "DROP TABLE orders",
            "CREATE INDEX idx_orders ON orders(id)",
            "CREATE VIEW v_orders AS SELECT * FROM orders",
            "SELECT * FROM orders",
            "INSERT INTO orders VALUES (1)",
            "UPDATE orders SET total = 0 WHERE id = 1",
            "DELETE FROM orders WHERE id = 1",
        ];
        for s in allowed {
            assert!(
                reject_privileged_ddl(s).is_ok(),
                "expected ok for `{s}`, got error"
            );
        }
    }

    #[test]
    fn reject_privileged_ddl_strips_leading_comments() {
        // Malicious actor might hide a GRANT behind a comment. The
        // guard strips leading `-- …` and `/* … */` before looking
        // at the first keyword.
        let hidden = "-- innocent-looking comment\nGRANT ALL ON orders TO public";
        let err = reject_privileged_ddl(hidden).unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("GRANT")));

        let hidden = "/* hidden */ DROP ROLE admin";
        let err = reject_privileged_ddl(hidden).unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("DROP ROLE")));
    }

    #[test]
    fn reject_privileged_ddl_allows_empty_and_whitespace() {
        assert!(reject_privileged_ddl("").is_ok());
        assert!(reject_privileged_ddl("   \n\t  ").is_ok());
        // An unclosed block comment returns early with Ok — the
        // multi-statement / sqlx layers will surface the actual
        // parse issue downstream.
        assert!(reject_privileged_ddl("/* unclosed").is_ok());
    }

    #[test]
    fn reject_privileged_ddl_is_case_insensitive() {
        assert!(reject_privileged_ddl("grant all on t to public").is_err());
        assert!(reject_privileged_ddl("Grant all on t to public").is_err());
    }

    #[test]
    fn validate_rejects_ddl_in_sql_body() {
        let mut cfg = minimal("sqlite::memory:", DriverKind::Sqlite);
        cfg.query.body = QueryBody::Sql {
            sql: "GRANT ALL ON orders TO public".into(),
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("privileged DDL")));
    }

    // ------------------------------------------------------------------
    // list_query validation
    // ------------------------------------------------------------------

    fn list_cfg(sql: &str, mode: ListQueryMode) -> ListQueryConfig {
        ListQueryConfig {
            sql: sql.into(),
            mode,
            cursor_column: if mode == ListQueryMode::Keyset {
                Some("id".into())
            } else {
                None
            },
            page_size: 100,
        }
    }

    // ---- await validation ---------------------------------

    fn await_cfg(trigger_sql: Option<&str>, check_sql: &str, predicate: &str) -> AwaitConfig {
        AwaitConfig {
            trigger: trigger_sql.map(|s| AwaitStep {
                sql: s.to_owned(),
                params: vec![],
            }),
            check: AwaitStep {
                sql: check_sql.to_owned(),
                params: vec![],
            },
            predicate: predicate.to_owned(),
            poll_interval_ms: 1_000,
            timeout_ms: 60_000,
        }
    }

    #[test]
    fn await_accepts_minimal_valid_config() {
        let cfg = await_cfg(
            None,
            "SELECT status FROM jobs WHERE id = :id",
            "row.status == \"done\"",
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn await_rejects_empty_check_sql() {
        let mut cfg = await_cfg(None, "SELECT 1", "true");
        cfg.check.sql = "".into();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("await.check.sql must not be empty")
        );
    }

    #[test]
    fn await_rejects_empty_predicate() {
        let mut cfg = await_cfg(None, "SELECT 1", "true");
        cfg.predicate = "".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("await.predicate"));
    }

    #[test]
    fn await_rejects_poll_below_floor() {
        let mut cfg = await_cfg(None, "SELECT 1", "true");
        cfg.poll_interval_ms = 50;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("poll_interval_ms"));
    }

    #[test]
    fn await_rejects_timeout_below_poll() {
        let mut cfg = await_cfg(None, "SELECT 1", "true");
        cfg.poll_interval_ms = 5_000;
        cfg.timeout_ms = 1_000;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn await_rejects_empty_trigger_when_present() {
        let mut cfg = await_cfg(Some("SELECT 1"), "SELECT 1", "true");
        cfg.trigger.as_mut().unwrap().sql = "".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("trigger.sql"));
    }

    #[test]
    fn list_query_keyset_default_accepts_valid_config() {
        let c = list_cfg(
            "SELECT uri, name FROM docs WHERE id > :cursor",
            ListQueryMode::Keyset,
        );
        assert!(c.validate().is_ok());
    }

    #[test]
    fn list_query_offset_mode_doesnt_require_cursor_column() {
        let c = ListQueryConfig {
            sql: "SELECT uri FROM docs".into(),
            mode: ListQueryMode::Offset,
            cursor_column: None,
            page_size: 50,
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn list_query_keyset_requires_cursor_column() {
        let c = ListQueryConfig {
            sql: "SELECT uri FROM docs".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: None,
            page_size: 100,
        };
        let err = c.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("cursor_column")));
    }

    #[test]
    fn list_query_rejects_unsafe_cursor_column() {
        let c = ListQueryConfig {
            sql: "SELECT uri FROM docs".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: Some("id; DROP TABLE".into()),
            page_size: 100,
        };
        let err = c.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("cursor_column")));
    }

    #[test]
    fn list_query_rejects_empty_sql() {
        let c = list_cfg("", ListQueryMode::Offset);
        let err = c.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("must not be empty")));
    }

    #[test]
    fn list_query_rejects_page_size_out_of_range() {
        let mut c = list_cfg("SELECT uri FROM docs", ListQueryMode::Offset);
        c.page_size = 0;
        assert!(c.validate().is_err());
        c.page_size = 10_000;
        assert!(c.validate().is_err());
    }

    #[test]
    fn list_query_rejects_multi_statement_body() {
        let c = list_cfg(
            "SELECT uri FROM docs; DROP TABLE docs",
            ListQueryMode::Offset,
        );
        let err = c.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(_)));
    }

    #[test]
    fn list_query_rejects_privileged_ddl_body() {
        let c = list_cfg("GRANT ALL ON docs TO public", ListQueryMode::Offset);
        let err = c.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("privileged DDL")));
    }

    // --- isolation_level config -------------------------------------

    #[test]
    fn isolation_level_sql_fragments_are_engine_portable() {
        assert_eq!(
            IsolationLevel::ReadCommitted.sql_fragment(),
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
        );
        assert_eq!(
            IsolationLevel::RepeatableRead.sql_fragment(),
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
        );
        assert_eq!(
            IsolationLevel::Serializable.sql_fragment(),
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
        );
    }

    #[test]
    fn validate_rejects_sqlite_with_non_serializable_isolation() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.isolation_level = Some(IsolationLevel::ReadCommitted);
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("SQLite is always serializable")),
            "expected SQLite-only-serializable error, got: {err:?}"
        );

        c.isolation_level = Some(IsolationLevel::RepeatableRead);
        let err = c.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(_)));
    }

    #[test]
    fn validate_accepts_sqlite_with_serializable_isolation() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.isolation_level = Some(IsolationLevel::Serializable);
        c.validate().expect("sqlite + serializable is fine");

        c.isolation_level = None;
        c.validate().expect("sqlite + no isolation is fine");
    }

    #[test]
    fn validate_accepts_postgres_with_any_isolation_level() {
        let url = "postgres://u:p@host/db";
        for level in [
            IsolationLevel::ReadCommitted,
            IsolationLevel::RepeatableRead,
            IsolationLevel::Serializable,
        ] {
            let mut c = minimal(url, DriverKind::Postgres);
            c.isolation_level = Some(level);
            c.validate()
                .unwrap_or_else(|e| panic!("postgres should accept {level:?}: {e}"));
        }
    }

    // --- session_vars driver compatibility -------------------------

    #[test]
    fn validate_rejects_session_vars_on_sqlite() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.session_vars.insert("tenant_id".into(), "42".into());
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("SQLite has no transaction-scoped")),
            "expected SQLite-no-session-vars error, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_dotted_session_var_keys_on_mysql() {
        for driver in [DriverKind::Mysql, DriverKind::Mariadb] {
            let mut c = minimal("mysql://u:p@host/db", driver);
            c.session_vars.insert("app.tenant_id".into(), "42".into());
            let err = c.validate().unwrap_err();
            assert!(
                matches!(&err, SqlError::InvalidSpec(m)
                    if m.contains("user-variable name") && m.contains("app_tenant_id")),
                "expected dotted-key rejection on {driver:?}, got: {err:?}"
            );
        }
    }

    #[test]
    fn validate_accepts_underscore_session_var_keys_on_mysql() {
        let mut c = minimal("mysql://u:p@host/db", DriverKind::Mysql);
        c.session_vars.insert("app_tenant_id".into(), "42".into());
        c.validate().expect("mysql + underscore key is fine");
    }

    #[test]
    fn validate_accepts_dotted_session_var_keys_on_postgres() {
        let mut c = minimal("postgres://u:p@host/db", DriverKind::Postgres);
        c.session_vars.insert("app.tenant_id".into(), "42".into());
        c.validate()
            .expect("postgres + dotted key is fine — set_config uses GUC names");
    }

    // --- result_sets row mode --------------------------------------

    fn proc_minimal(url: &str, driver: DriverKind) -> SqlBackendConfig {
        let mut c = minimal(url, driver);
        c.query.body = QueryBody::Procedure {
            procedure: "report_proc".into(),
        };
        c.query.params = vec![];
        c.query.row_mode = RowMode::ResultSets;
        c
    }

    #[test]
    fn validate_accepts_result_sets_on_mysql_with_procedure() {
        for driver in [DriverKind::Mysql, DriverKind::Mariadb] {
            let c = proc_minimal("mysql://u:p@host/db", driver);
            c.validate()
                .unwrap_or_else(|e| panic!("{driver:?} + procedure + result_sets: {e}"));
        }
    }

    #[test]
    fn validate_rejects_result_sets_on_postgres() {
        let c = proc_minimal("postgres://u:p@host/db", DriverKind::Postgres);
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("not supported on") && m.contains("Postgres")),
            "expected Postgres rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_result_sets_on_sqlite() {
        let c = proc_minimal("sqlite::memory:", DriverKind::Sqlite);
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("SQLite")),
            "expected SQLite rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_result_sets_on_mysql_without_procedure() {
        let mut c = minimal("mysql://u:p@host/db", DriverKind::Mysql);
        c.query.row_mode = RowMode::ResultSets;
        // body is QueryBody::Sql from minimal()
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("requires `query.procedure`")),
            "expected procedure-required rejection, got: {err:?}"
        );
    }

    // cache validation matrix.

    #[test]
    fn validate_accepts_cache_on_select_many() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::Many;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: None,
        });
        c.validate().expect("cache on row_mode: many is allowed");
    }

    #[test]
    fn validate_rejects_cache_on_affected_rows() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::AffectedRows;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("affected_rows")),
            "expected affected_rows rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cache_on_stream() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::Stream;
        c.query.stream = Some(stream_cfg(&["id"]));
        // Patch the SQL so the stream validator is happy on its own
        // axis; we want the cache rejection, not a different one.
        c.query.body = QueryBody::Sql {
            sql: "SELECT id FROM t WHERE (id) > (:_after_id) ORDER BY id".into(),
        };
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("stream")),
            "expected stream rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cache_on_procedure_body() {
        let mut c = proc_minimal("mysql://u:p@host/db", DriverKind::Mysql);
        c.query.row_mode = RowMode::Many;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("procedure")),
            "expected procedure rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_allows_cache_disabled_on_any_row_mode() {
        // `cache: { enabled: false }` is the operator nudging "no
        // cache for this binding" — the validator must pass even
        // on rows that wouldn't be cache-safe with `enabled: true`.
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::AffectedRows;
        c.cache = Some(CacheSpec {
            enabled: false,
            ttl_seconds: 30,
            invalidate_on: None,
        });
        c.validate()
            .expect("disabled cache on any row_mode is allowed");
    }

    // invalidate-on-watch validation matrix.

    #[test]
    fn validate_accepts_cache_invalidate_on_watch() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::Many;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: Some(CacheInvalidateOn::Watch {
                sql: "SELECT MAX(updated_at) FROM t".into(),
                interval_ms: 500,
            }),
        });
        c.validate()
            .expect("watch tracking SQL on enabled cache is allowed");
    }

    #[test]
    fn validate_rejects_invalidate_watch_with_empty_sql() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::Many;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: Some(CacheInvalidateOn::Watch {
                sql: "  ".into(),
                interval_ms: 500,
            }),
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("must not be empty")),
            "expected empty-sql rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_invalidate_watch_below_floor() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::Many;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: Some(CacheInvalidateOn::Watch {
                sql: "SELECT 1".into(),
                interval_ms: 50,
            }),
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("100 ms floor")),
            "expected interval-floor rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_invalidate_watch_with_multi_statement() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.query.row_mode = RowMode::Many;
        c.cache = Some(CacheSpec {
            enabled: true,
            ttl_seconds: 30,
            invalidate_on: Some(CacheInvalidateOn::Watch {
                sql: "SELECT 1; DROP TABLE t".into(),
                interval_ms: 500,
            }),
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(_)),
            "expected multi-statement rejection, got: {err:?}"
        );
    }

    // ---- cost spec validation ---------------------------------

    #[test]
    fn validate_accepts_cost_with_flat_amount() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerCall,
            amount: Some("0.10".into()),
            expression: None,
            currency: "USD".into(),
            max_per_call: None,
        });
        c.validate().expect("flat per_call cost is valid");
    }

    #[test]
    fn validate_accepts_cost_with_cel_expression() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerRow,
            amount: None,
            expression: Some("0.001".into()),
            currency: "USD".into(),
            max_per_call: Some("10.0".into()),
        });
        c.validate().expect("CEL expression cost is valid");
    }

    #[test]
    fn validate_rejects_cost_with_both_amount_and_expression() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerCall,
            amount: Some("0.10".into()),
            expression: Some("0.20".into()),
            currency: "USD".into(),
            max_per_call: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("exactly one")),
            "expected exactly-one rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cost_with_neither_amount_nor_expression() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerCall,
            amount: None,
            expression: None,
            currency: "USD".into(),
            max_per_call: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("exactly one")),
            "expected exactly-one rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cost_with_negative_amount() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerCall,
            amount: Some("-1.0".into()),
            expression: None,
            currency: "USD".into(),
            max_per_call: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("non-negative")),
            "expected negative-amount rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cost_with_empty_currency() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerCall,
            amount: Some("0.10".into()),
            expression: None,
            currency: "  ".into(),
            max_per_call: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("currency")),
            "expected currency rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cost_with_invalid_cel_expression() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerCall,
            amount: None,
            expression: Some("@@@invalid".into()),
            currency: "USD".into(),
            max_per_call: None,
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("CEL")),
            "expected CEL compile rejection, got: {err:?}"
        );
    }

    #[test]
    fn validate_rejects_cost_with_invalid_max_per_call() {
        let mut c = minimal("sqlite::memory:", DriverKind::Sqlite);
        c.cost = Some(CostSpec {
            unit: CostUnit::PerRow,
            amount: Some("0.001".into()),
            expression: None,
            currency: "USD".into(),
            max_per_call: Some("not-a-number".into()),
        });
        let err = c.validate().unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("max_per_call")),
            "expected max_per_call rejection, got: {err:?}"
        );
    }
}
