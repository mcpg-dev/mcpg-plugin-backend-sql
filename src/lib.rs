//! SQL database binding plugin for mcpg.
//!
//! Implements [`BackendPlugin`] for `kind: "sql"`, dispatching
//! operator-defined queries or stored-procedure calls to Postgres,
//! MySQL/MariaDB, or SQLite. The core path is synchronous
//! request/response calls returning [`BackendResponse`] payloads;
//! `await` blocks, `sql_tx` pipeline steps, streaming cursors, watch
//! strategies, and schema introspection layer on top of that core.
//!
//! Operator config flows in through [`SqlBackendConfig`] (the
//! contents of `[bindings.sql]`). The plugin owns a [`DashMap`] of
//! per-binding runtimes, each holding the driver handle and the
//! prepared statement for that binding's query.
//!
//! Request payloads are interpreted as the JSON-encoded tool argument
//! object. The response payload is the JSON-encoded result of the
//! query, shaped per `row_mode`.

// SQLite cancel requires one `unsafe` FFI call to
// `libsqlite3_sys::sqlite3_interrupt` — that one call is documented
// as thread-safe and is the only way to interrupt an in-flight
// SQLite query without a server-side side-channel. Outside the
// sqlite feature we still forbid unsafe code globally.
#![cfg_attr(not(feature = "sqlite"), forbid(unsafe_code))]
#![cfg_attr(feature = "sqlite", deny(unsafe_code))]
#![warn(missing_docs)]

pub mod auth;
pub mod breaker;
pub(crate) mod cache;
pub mod config;
pub(crate) mod cost;
pub mod driver;
pub mod errors;
pub mod in_flight;
pub(crate) mod metrics;
pub mod param_exprs;
pub mod params;
pub mod pool;
pub mod redact;
pub mod schema;
pub mod session;
pub mod stream;
pub mod transaction;
pub mod watch;
#[cfg(feature = "postgres")]
pub mod watch_pg_listen;

/// cdylib sync bridge + `declare_plugin!` export. Additive: the gateway
/// keeps using the static `new()` + `set_host_handle` path. The
/// `mcpg_plugin_register` FFI symbol is gated
/// behind the `cdylib-export` feature inside the macro expansion. Public so
/// the wrapper types + macro-generated entity modules are part of the
/// crate's public surface (mirrors the nats / openai pilots) — this also
/// keeps the wrappers from tripping `dead_code` on the default rlib build
/// where neither `cdylib-export` nor `static-firstparty` references them.
///
/// Gated on `postgres` because the `postgres_listen_notify` watch entity
/// depends on the `watch_pg_listen` module (itself postgres-gated); the
/// cdylib is always built with default features (postgres on).
#[cfg(feature = "postgres")]
pub mod cdylib;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::credential::{CredRef, cred_tokens, substitute_cred_tokens};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendInvocationContext, BackendPlugin, BackendRequest, BackendResponse,
    ListedResource, PluginManifest, ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use serde_json::Value;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::metrics::CallStatus;

pub use crate::breaker::{CircuitBreakerConfig, CircuitSnapshot, CircuitState};
pub use crate::config::{DriverKind, PoolConfig, QueryBody, QueryShape, RowMode, SqlBackendConfig};
pub use crate::driver::{PoolHandle, RowBatch, SqlDriver};
pub use crate::errors::SqlError;
pub use crate::in_flight::{BackendId, InFlightRegistry, InFlightSnapshot};
pub use crate::params::{BoundParam, PreparedStmt};
pub use crate::session::SessionVars;
pub use crate::transaction::SqlTxHandle;

// ---------------------------------------------------------------------------
// Profile runtime
// ---------------------------------------------------------------------------

/// Per-binding runtime state held in the plugin's map.
///
/// Constructed once at `register_profile` time and cloned cheaply on
/// every `execute` — each field is either an `Arc` or a small owned
/// value.
struct ProfileRuntime {
    driver_kind: DriverKind,
    driver: Arc<dyn SqlDriver>,
    /// Static-cred pool — built once at `register_profile` time
    /// from the spec's URL with no per-call substitution. Used by
    /// system-initiated paths (await runtime, watch fetcher, list,
    /// transactions, cancel) and by every call when the profile
    /// has no `${cred://…}` token in its URL or session_vars.
    /// Also stored under `static_digest()` in `pool_registry` so
    /// the per-cred path's first lookup hits the same pool when
    /// resolution returns no substitutions.
    pool: PoolHandle,
    /// Per-credential pool cache. Used by the dynamic
    /// `cred://` path; static-cred profiles only ever touch the
    /// static-digest entry. Cheap to clone (Arc inside).
    pool_registry: Arc<crate::pool::PoolRegistry>,
    /// Snapshot of the operator's `SqlBackendConfig` — kept on the
    /// runtime so the per-call resolver can re-walk the URL +
    /// session_vars values for `${cred://…}` token substitution.
    /// Arc'd so the per-call snapshot is a cheap clone, not a deep
    /// config rebuild.
    cfg: Arc<crate::config::SqlBackendConfig>,
    /// True when the profile's URL or session_vars contain at
    /// least one `${cred://…}` credential token. Static-cred
    /// profiles short-circuit per-cred resolution entirely (the
    /// static `pool` field is the only one ever used) — the registry
    /// never grows beyond its single static-digest entry. A bare
    /// `cred://…` (not wrapped in `${}`) does not set this flag.
    has_cred_refs: bool,
    /// Revocation subscription guard. Held for the
    /// lifetime of the `ProfileRuntime`. The subscription is
    /// installed at `register_profile` time on the gateway's
    /// credential cache and routes per-(plugin_id, target)
    /// invalidation events to `pool_registry.evict_for(...)`.
    /// `Arc<_>` so the canonical entry in `profiles` and any
    /// per-call clones share one subscription — the subscriber
    /// drops only when the profile is unregistered.
    _revocation_sub: Arc<mcpg_plugin_protocol::CredentialRevocationSubscription>,
    /// Secret-rotation subscription guard. Held for the
    /// lifetime of the `ProfileRuntime`; routes URI-scoped rotation
    /// events to `pool_registry.evict_for_secret(...)` whenever a
    /// `vault://` URI baked into this profile rotates.
    _rotation_sub: Arc<mcpg_plugin_protocol::SecretRotationSubscription>,
    /// Idle-pool sweeper guard. When the last
    /// `ProfileRuntime` clone drops, the inner DropGuard cancels
    /// the spawned sweeper task. Static-cred profiles still own a
    /// guard — the sweeper just finds nothing to evict every tick.
    _idle_sweeper: Arc<crate::pool::IdleSweeper>,
    /// Cloud-auth token rotator handle. Present only when
    /// the binding declared an `auth: { kind: rds_iam | … }` block —
    /// the driver's `connect()` impl spawned a background refresher
    /// and returned this handle. Holding it pins the refresher's
    /// lifetime to the profile runtime's; teardown drops the Arc
    /// and the rotator's [`tokio_util::sync::DropGuard`] cancels
    /// the spawned task.
    _auth_rotator: Option<Arc<crate::auth::TokenRotator>>,
    stmt: PreparedStmt,
    row_mode: RowMode,
    max_rows: u64,
    timeout: Duration,
    session_vars: SessionVars,
    /// When `Some(interval)`, a background task emits a progress
    /// heartbeat (tracing event + metrics counter) every `interval`
    /// while [`SqlBackendPlugin::execute_inner`] is running.
    progress_heartbeat: Option<Duration>,
    /// JSON Schema derived from the prepared statement's parameter
    /// metadata. `None` when derivation is off or the driver
    /// did not return parameter types. The host reads this via
    /// [`SqlBackendPlugin::input_schema`] and merges it with
    /// operator-supplied schema at tool-list time.
    input_schema: Option<Value>,
    /// JSON Schema derived from the prepared statement's output
    /// columns. Shape depends on `row_mode`. `None` when
    /// derivation is off, the statement returns no rows, or the
    /// driver can't introspect columns.
    output_schema: Option<Value>,
    /// Compiled `param_exprs` entries. Empty when the operator
    /// declared none. Evaluated against the call's arguments at
    /// execute time; results are injected into the args map under
    /// their declared names before placeholder binding runs.
    param_exprs: Arc<Vec<param_exprs::ParamExpr>>,
    /// Per-binding circuit breaker. `None` when the
    /// operator omitted the `circuit_breaker` block — every call
    /// reaches the driver without fast-fail.
    breaker: Option<Arc<breaker::CircuitBreaker>>,
    /// Prepared statement + operator config for `resources/list`
    /// enumeration. `None` when the binding has no
    /// `list_query` block.
    list: Option<(PreparedStmt, crate::config::ListQueryConfig)>,
    /// Compiled `await:` block: prepared trigger stmt (if
    /// any), prepared check stmt, compiled CEL predicate, and the
    /// raw config for poll_interval / timeout. `None` when the
    /// binding has no await block — the normal execute path runs
    /// instead.
    await_rt: Option<AwaitRuntime>,
    /// Stream-cursor runtime. `Some` when the binding's
    /// `query.row_mode` is `Stream` and a `stream:` block was
    /// validated. Carries the operator's cursor_columns + initial
    /// values + the cursor signing key (taken from the resolved
    /// `signing_key` value if set, otherwise generated per-process).
    stream_rt: Option<StreamRuntime>,
    /// Per-binding transaction isolation level. `None` keeps
    /// the engine default; `Some` triggers a `SET TRANSACTION
    /// ISOLATION LEVEL …` after BEGIN inside `begin_transaction`.
    isolation_level: Option<crate::config::IsolationLevel>,
    /// Per-binding response cache opt-in. `None` keeps the
    /// path silent (no `cache_get` / `cache_put` calls). `Some`
    /// engages the cache lookup before the driver runs and stores
    /// successful results on the way out. Backend selection lives
    /// on the gateway-side `BackendConfig.cache:` — when no backend
    /// is wired the host's defaults turn the calls into no-ops.
    cache: Option<crate::config::CacheSpec>,
    /// Cache-invalidation watcher. `Some` when the binding
    /// declared `cache.invalidate_on`. Carries an `AtomicU64`
    /// version stamp + a drop-guarded background task that polls a
    /// tracking query and bumps the version on each change. The
    /// version mixes into cache keys (`cache::build_cache_key`),
    /// so a bump makes every prior entry naturally miss.
    cache_invalidator: Option<Arc<crate::cache::CacheInvalidator>>,
    /// Compiled cost / billing-telemetry spec. `Some` when
    /// the operator declared `cost:` on the binding. The plugin
    /// computes the per-call charge on success and emits a refund
    /// signal on every error path. None means "no cost telemetry"
    /// — the binding still works, just doesn't participate in the
    /// SQL billing pipeline.
    cost: Option<crate::cost::BackendCost>,
    /// `BackendHost` handed to us at `register_profile` time.
    /// Threaded through to `execute_inner_impl` so the cache path
    /// can call `cache_get` / `cache_put`. `None` only in the
    /// degenerate case where the plugin was registered with a
    /// `noop_backend_host()` (test harness); the cache code keys
    /// on `cache.is_some()` so the absence of a host is moot
    /// outside test paths.
    host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
}

/// Runtime side of [`crate::stream::StreamConfig`]: the operator's
/// declared shape plus the resolved signing key the plugin uses to
/// mint and verify cursor tokens.
#[derive(Debug, Clone)]
struct StreamRuntime {
    cfg: crate::stream::StreamConfig,
    key: crate::stream::CursorSigningKey,
}

/// Compiled representation of a [`config::AwaitConfig`]. Built once
/// at `register_profile` time so the runtime poll loop is
/// bind-only: no CEL re-parse, no placeholder rewrite per tick.
struct AwaitRuntime {
    cfg: crate::config::AwaitConfig,
    trigger_stmt: Option<PreparedStmt>,
    check_stmt: PreparedStmt,
    predicate: Arc<cel::Program>,
}

impl Clone for AwaitRuntime {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            trigger_stmt: self.trigger_stmt.clone(),
            check_stmt: self.check_stmt.clone(),
            predicate: Arc::clone(&self.predicate),
        }
    }
}

impl Clone for ProfileRuntime {
    fn clone(&self) -> Self {
        Self {
            driver_kind: self.driver_kind,
            driver: Arc::clone(&self.driver),
            pool: self.pool.clone(),
            pool_registry: Arc::clone(&self.pool_registry),
            cfg: Arc::clone(&self.cfg),
            has_cred_refs: self.has_cred_refs,
            _revocation_sub: Arc::clone(&self._revocation_sub),
            _rotation_sub: Arc::clone(&self._rotation_sub),
            _idle_sweeper: Arc::clone(&self._idle_sweeper),
            _auth_rotator: self._auth_rotator.as_ref().map(Arc::clone),
            stmt: self.stmt.clone(),
            row_mode: self.row_mode,
            max_rows: self.max_rows,
            timeout: self.timeout,
            session_vars: self.session_vars.clone(),
            progress_heartbeat: self.progress_heartbeat,
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
            param_exprs: Arc::clone(&self.param_exprs),
            breaker: self.breaker.as_ref().map(Arc::clone),
            list: self.list.clone(),
            await_rt: self.await_rt.clone(),
            stream_rt: self.stream_rt.clone(),
            isolation_level: self.isolation_level,
            cache: self.cache.clone(),
            cache_invalidator: self.cache_invalidator.as_ref().map(Arc::clone),
            cost: self.cost.clone(),
            host: Arc::clone(&self.host),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/// Default per-query timeout when the profile doesn't set one.
const DEFAULT_QUERY_TIMEOUT_MS: u64 = 5_000;

/// Cache-entry header length. One byte for the truncated
/// flag (0/1), then the response payload bytes follow. Chosen over
/// JSON-wrapping the payload so the cache hot path is a direct
/// `Bytes` slice, not a parse step.
const CACHE_HEADER_LEN: usize = 1;

/// Internal ceiling on how long `shutdown()` will wait for
/// in-flight calls to drain before forcing pool close. Defense in
/// depth: the gateway already wraps `shutdown()` in
/// `shutdown_all_with_timeout`, so this only fires when the gateway
/// budget is unusually large or absent. 30s matches typical Kubernetes
/// `terminationGracePeriodSeconds` defaults.
const SHUTDOWN_INTERNAL_CAP: Duration = Duration::from_secs(30);

/// Polling interval while waiting for `in_flight.len() == 0` during
/// drain. Short enough that a normal-load shutdown finishes within
/// one tick of the last in-flight call completing; long enough that
/// the spin doesn't dominate CPU on a stuck plugin.
const SHUTDOWN_DRAIN_POLL: Duration = Duration::from_millis(50);

/// Plugin manifest for the binding-sql plugin.
fn manifest() -> PluginManifest {
    firstparty_manifest! {
        id: "dev.mcpg.backend.sql",
        name: "SQL Binding",
        class: Backend,
    }
}

/// Bounded outcome label for the unified
/// host-handle metric pair. The set MUST stay closed so the host
/// metrics-rs recorder doesn't blow up on cardinality. Adding a new
/// `BackendError` variant forces a new arm here at compile time.
fn host_outcome_label(result: &Result<BackendResponse, BackendError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(BackendError::Timeout { .. }) => "timeout",
        Err(BackendError::Transport { .. }) => "transport",
        Err(BackendError::InvalidSpec { .. }) => "invalid_spec",
        Err(BackendError::ProfileNotFound { .. }) => "profile_not_found",
    }
}

/// Bounded set of dotted audit-event action
/// names emitted on notable SQL backend failures. Returns `None`
/// for success and for operator-class errors (`InvalidSpec`,
/// `ProfileNotFound`) — those are config drift / bugs, not
/// forensically-interesting events. Driver-class failures
/// (`Timeout`, `Transport`) emit an audit event so operators can
/// reconstruct connection-pool exhaustion / statement timeouts /
/// auth failures after the fact.
fn audit_action_for(result: &Result<BackendResponse, BackendError>) -> Option<&'static str> {
    match result {
        Ok(_) => None,
        // `Timeout` covers per-statement / pool-checkout / await-loop
        // timeouts uniformly. Operators see them as `query_timeout`
        // in audit search regardless of which layer raised.
        Err(BackendError::Timeout { .. }) => Some("dev.mcpg.backend.sql.query_timeout"),
        // `Transport` covers connection refused, broker closed,
        // pool exhaustion, driver-level retryable failures. One
        // dotted name keeps the audit-search facet bounded.
        Err(BackendError::Transport { .. }) => Some("dev.mcpg.backend.sql.query_failed"),
        // Operator-class errors are not audit-emitted — they would
        // fire identically on every retry of a misconfigured
        // binding, drowning the audit log in duplicates of the same
        // boot-time config bug.
        Err(BackendError::InvalidSpec { .. }) | Err(BackendError::ProfileNotFound { .. }) => None,
    }
}

/// Best-effort RFC 3339 timestamp for audit
/// event `occurred_at`. The plugin already depends on `chrono` for
/// SQL row coercion; use that here so the timestamp is calendar-
/// correct (audit sinks sort lexicographically by `occurred_at`).
fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Synthetic identity for audit events emitted
/// on inbound requests that carry no caller attribution (system-
/// initiated paths: watch-engine refresh, await-loop tick, admin
/// cancel). Audit sinks treat `kind = "system"` specially so these
/// events are easy to filter out of caller-attributed dashboards.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.sql".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

/// `BackendPlugin` implementation for `kind: "sql"`.
///
/// Holds one [`ProfileRuntime`] per registered binding; a shared
/// [`DashMap`] lets us read the profile lock-free on the hot path
/// and modify it (during hot reload) with fine-grained locking.
pub struct SqlBackendPlugin {
    manifest: PluginManifest,
    profiles: DashMap<String, ProfileRuntime>,
    drivers: HashMap<DriverKind, Arc<dyn SqlDriver>>,
    in_flight: Arc<InFlightRegistry>,
    /// Drain flag flipped to `true` by `shutdown()`. While set,
    /// `execute()` and `register_profile()` short-circuit with a
    /// `Transport` error so SIGTERM-during-traffic deterministically
    /// drains rather than racing new work against teardown.
    draining: AtomicBool,
    /// Woken by `shutdown()` so await-loop polls (which sleep
    /// for `poll_interval_ms` between check queries) bail immediately
    /// instead of waiting out their tick budget. Held in an `Arc` so
    /// `execute_await_loop` can take a clone for its `select!` arm.
    drain_notify: Arc<Notify>,
    /// The unified host surface. Installed once
    /// at boot by the gateway via [`SqlBackendPlugin::set_host_handle`]
    /// before any `execute()` traffic flows. When `None` (test
    /// harnesses that construct the plugin without wiring a host),
    /// the per-call HostHandle observability triad short-circuits to
    /// no-ops and the plugin's existing internal `tracing::span!` /
    /// `metrics::*` calls carry the load.
    ///
    /// Coexistence with the per-`ProfileRuntime` `host:
    /// Arc<dyn BackendHost>` is intentional — `BackendHost` is the
    /// re-entrant-dispatch trait (cache_get / cache_put, credential
    /// revocation, secret rotation); `HostHandle` is the unified
    /// observability + secret / config surface. The two are
    /// orthogonal and both stay wired.
    host_handle: OnceLock<HostHandle>,
}

impl std::fmt::Debug for SqlBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlBackendPlugin")
            .field("id", &self.manifest.id)
            .field("profiles", &self.profiles.len())
            .field(
                "drivers",
                &self.drivers.keys().map(|k| k.as_str()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for SqlBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// True when `cfg.url` or any value in `cfg.session_vars` carries a
/// `${cred://…}` credential token. Operators with no per-caller
/// credential surface stay on the static-cred fast path; this
/// function is the gate that decides which path each request takes.
///
/// Only the standardized `${cred://issuer/target}` token form counts:
/// a BARE `cred://…` (not wrapped in `${}`) is NOT a credential
/// reference — it travels verbatim into the connection string /
/// session var and keeps the profile on the static path.
fn config_has_cred_refs(cfg: &crate::config::SqlBackendConfig) -> bool {
    if !cred_tokens(&cfg.url).is_empty() {
        return true;
    }
    cfg.session_vars
        .iter()
        .any(|(_k, v)| !cred_tokens(v).is_empty())
}

/// Per-call credential resolution: collects the `${cred://…}` tokens
/// the operator baked into the URL + session_vars values, asks the
/// host to resolve those inner URIs per caller identity, substitutes
/// each token with its resolved value, and returns the resolved
/// bundle (URL, session-vars overrides) + the BLAKE3 digest the
/// [`PoolRegistry`] keys on, plus the list of `(plugin_id, target)`
/// pairs the resolver visited (for revocation routing).
///
/// Only the standardized `${cred://issuer/target}` token form resolves.
/// The snapshot handed to the host carries ONLY the inner cred URIs
/// pulled from those tokens (config-origin BY CONSTRUCTION via
/// [`cred_tokens`]) — never the raw config strings — so a bare
/// `cred://…` anywhere in `cfg.url` / `cfg.session_vars` is never
/// resolved and travels verbatim. (This crate has no request-arg
/// templating either, so caller data can't reach the snapshot at all.)
///
/// On profiles with no `${cred://…}` tokens this is never called —
/// the static path uses `runtime.pool` directly with
/// `static_digest()` semantics.
async fn resolve_creds_for(
    runtime: &ProfileRuntime,
    request: &mcpg_plugin_protocol::BackendRequest,
    backend_name: &str,
) -> Result<ResolvedCreds, BackendError> {
    let cfg = &runtime.cfg;
    // Collect the inner `cred://…` URIs from every `${cred://…}` token
    // in the URL + session-vars VALUES (not keys — keys are operator-
    // defined identifiers that never carry secrets). `cred_tokens`
    // ignores bare `cred://…`, so only the wrapped token form is ever
    // a credential reference. Dedup so the host resolves each unique
    // URI once even when it appears in multiple fields.
    let mut cred_uris: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for uri in cred_tokens(&cfg.url) {
        cred_uris.insert(uri);
    }
    // Track which session-vars values carry a token — only those can
    // differ per caller, so only they join the digest below.
    let mut session_vars_keys = Vec::with_capacity(cfg.session_vars.len());
    for (k, v) in cfg.session_vars.iter() {
        let tokens = cred_tokens(v);
        if !tokens.is_empty() {
            session_vars_keys.push(k.clone());
            for uri in tokens {
                cred_uris.insert(uri);
            }
        }
    }

    // Build a snapshot containing ONLY the inner cred URIs (mapped to
    // themselves) and ask the host to resolve them in one call. The
    // resolver substitutes each `cred://…` string it finds, per caller
    // identity, leaving `uri → resolved value` in the snapshot.
    let mut snapshot = serde_json::Map::new();
    for uri in &cred_uris {
        snapshot.insert(uri.clone(), Value::String(uri.clone()));
    }
    let mut snapshot = Value::Object(snapshot);
    // The host re-uses the BackendInvocationContext shape for
    // bookkeeping. We don't have a real BackendInvocationContext
    // here — execute_inner_impl is the call site, not host
    // re-entry — so synthesise a shallow context tagged with the
    // current request's identity + ids. The host only inspects
    // `identity` and `parent_request_id` on this path.
    let mut host_ctx = mcpg_plugin_protocol::BackendInvocationContext::root(
        request.request_id.clone(),
        request.session_id.clone(),
        backend_name.to_owned(),
    );
    host_ctx.identity = request.identity.clone();
    runtime
        .host
        .resolve_credentials(&host_ctx, &mut snapshot)
        .await
        .map_err(|e| match e {
            mcpg_plugin_protocol::BackendHostError::Backend { cause, .. } => cause,
            other => BackendError::Transport {
                message: format!("credential resolution: {other}"),
            },
        })?;

    // Read back the `uri → resolved value` map the host left in the
    // snapshot.
    let obj = snapshot
        .as_object()
        .ok_or_else(|| BackendError::Transport {
            message: "credential resolver mutated snapshot to non-object".into(),
        })?;
    let cred_map: std::collections::HashMap<String, String> = obj
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect();

    // Substitute each `${cred://…}` token with its resolved value.
    // Bare `cred://…` is left verbatim by `substitute_cred_tokens`.
    let resolved_url = substitute_cred_tokens(&cfg.url, &cred_map);
    let mut resolved_session_vars: BTreeMap<String, String> = cfg.session_vars.clone();
    for key in &session_vars_keys {
        if let Some(v) = cfg.session_vars.get(key) {
            resolved_session_vars.insert(key.clone(), substitute_cred_tokens(v, &cred_map));
        }
    }

    // Compute the digest pairs from the resolved bundle. URL is
    // always included; resolved session-vars values join in keyed
    // by `session_vars.<key>` so two callers whose only difference
    // is a session-var value get distinct digests.
    let mut digest_pairs: Vec<(String, String)> = Vec::with_capacity(1 + session_vars_keys.len());
    digest_pairs.push(("url".to_owned(), resolved_url.clone()));
    for key in &session_vars_keys {
        if let Some(v) = resolved_session_vars.get(key) {
            digest_pairs.push((format!("session_vars.{key}"), v.clone()));
        }
    }
    let digest = crate::pool::digest_credential_bundle(&digest_pairs);

    // Cred-keys are the (plugin_id, target) pairs that contributed
    // to the resolved bundle, for revocation routing. Derived from
    // the same `${cred://…}` tokens (config-origin), so bare
    // `cred://…` never produces a routing key.
    let mut cred_keys = Vec::new();
    if let Some(refs) = collect_cred_refs(&cfg.url) {
        cred_keys.extend(refs);
    }
    for v in cfg.session_vars.values() {
        if let Some(refs) = collect_cred_refs(v) {
            cred_keys.extend(refs);
        }
    }
    cred_keys.sort();
    cred_keys.dedup();

    Ok(ResolvedCreds {
        url: resolved_url,
        session_vars: resolved_session_vars,
        digest,
        cred_keys,
    })
}

/// Per-call resolved credential bundle. Built by
/// [`resolve_creds_for`] and consumed by the pool registry +
/// session-var apply path.
struct ResolvedCreds {
    url: String,
    session_vars: BTreeMap<String, String>,
    digest: crate::pool::CredDigest,
    cred_keys: Vec<(String, String)>,
}

/// Extract `(plugin_id, target)` pairs from every `${cred://…}`
/// credential token in `s`, for revocation routing. Returns None
/// when the string carries no token — callers skip the alloc on the
/// common no-cred path.
///
/// Only the wrapped token form counts: a bare `cred://…` (not inside
/// `${}`) is not a credential reference and produces no routing key,
/// matching [`resolve_creds_for`]'s resolution rule. The `#part`
/// fragment is dropped — the registry keys on `(plugin_id, target)`,
/// not on which part each consumer selected.
fn collect_cred_refs(s: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for uri in cred_tokens(s) {
        if let Some(cref) = CredRef::parse(&uri) {
            out.push((cref.plugin_id, cref.target));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

#[cfg(test)]
mod cred_ref_extraction_tests {
    use super::collect_cred_refs;

    #[test]
    fn finds_simple_cred_token() {
        let v = collect_cred_refs("${cred://vault-pg/orders}").unwrap();
        assert_eq!(v, vec![("vault-pg".into(), "orders".into())]);
    }

    #[test]
    fn strips_part_suffix() {
        let v = collect_cred_refs("${cred://vault-pg/orders#username}").unwrap();
        assert_eq!(v, vec![("vault-pg".into(), "orders".into())]);
    }

    #[test]
    fn extracts_from_postgres_url() {
        let url = "postgres://${cred://vault-pg/orders#username}:${cred://vault-pg/orders#password}@db.example.com:5432/orders";
        let v = collect_cred_refs(url).unwrap();
        assert_eq!(v.len(), 2);
        // both refs map to the same (plugin, target) pair after
        // part-stripping.
        assert_eq!(v[0], ("vault-pg".into(), "orders".into()));
        assert_eq!(v[1], ("vault-pg".into(), "orders".into()));
    }

    #[test]
    fn returns_none_when_no_cred_token() {
        assert!(collect_cred_refs("postgres://u:p@h/db").is_none());
    }

    #[test]
    fn bare_cred_uri_is_not_a_token() {
        // A BARE `cred://…` (not wrapped in `${}`) is not a credential
        // reference under the standardized grammar — it produces no
        // routing key and travels verbatim.
        assert!(collect_cred_refs("postgres://cred://vault-pg/orders@h/db").is_none());
        assert!(collect_cred_refs("cred://vault-pg/orders").is_none());
    }
}

impl SqlBackendPlugin {
    /// Construct a plugin with the default driver registry (Postgres,
    /// MySQL/MariaDB, SQLite — whichever features are enabled).
    pub fn new() -> Self {
        Self {
            manifest: manifest(),
            profiles: DashMap::new(),
            drivers: driver::build_registry(),
            in_flight: Arc::new(InFlightRegistry::new()),
            draining: AtomicBool::new(false),
            drain_notify: Arc::new(Notify::new()),
            host_handle: OnceLock::new(),
        }
    }

    /// Construct a plugin with a custom driver registry. Tests use
    /// this to inject in-memory doubles.
    pub fn with_drivers(drivers: HashMap<DriverKind, Arc<dyn SqlDriver>>) -> Self {
        Self {
            manifest: manifest(),
            profiles: DashMap::new(),
            drivers,
            in_flight: Arc::new(InFlightRegistry::new()),
            draining: AtomicBool::new(false),
            drain_notify: Arc::new(Notify::new()),
            host_handle: OnceLock::new(),
        }
    }

    /// Install the unified [`HostHandle`] surface
    /// for per-call observability. The gateway calls this exactly
    /// once at boot, after constructing the plugin via
    /// [`SqlBackendPlugin::new`] but before any `execute()` traffic
    /// is dispatched, threading a handle built from the late-bound
    /// `HostServices` via [`HostHandle::from_services`].
    ///
    /// Idempotent — a second call is silently a no-op so test
    /// harnesses that construct the plugin without a host can still
    /// call this safely from a reload path. The returned `bool`
    /// indicates whether the handle was installed (`true`) or the
    /// slot was already occupied (`false`).
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host
    /// surface, if any. Returns `None` in test harnesses that
    /// constructed the plugin via [`SqlBackendPlugin::new`] /
    /// [`SqlBackendPlugin::with_drivers`] without calling
    /// [`SqlBackendPlugin::set_host_handle`]. Callers MUST treat
    /// `None` as "skip the host triad" — the plugin's internal
    /// `tracing::span!` + `metrics::*` calls remain wired and
    /// carry the load through the triad-floor sinks.
    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// True once `shutdown()` has been called. Exposed for
    /// admin tooling and tests; runtime hot-path callers use the
    /// internal short-circuits in `execute()` / `register_profile()`.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Snapshot the in-flight call registry. Each entry captures
    /// binding name, driver, age, and (once populated by the driver)
    /// the backend identifier used for future targeted cancel.
    /// Admin tooling surfaces slow-query dumps through this.
    pub fn in_flight_snapshot(&self) -> Vec<InFlightSnapshot> {
        self.in_flight.snapshot()
    }

    /// Current circuit-breaker state for a registered binding.
    /// `None` when the binding isn't registered or has no breaker
    /// configured. Admin tooling / health endpoints read this.
    pub fn circuit_snapshot(&self, backend_name: &str) -> Option<breaker::CircuitSnapshot> {
        self.profiles
            .get(backend_name)?
            .breaker
            .as_ref()
            .map(|b| b.snapshot())
    }

    /// Cancel an in-flight SQL request. Reads the
    /// driver-level backend identifier the registry captured for
    /// `request_id` and asks the driver to abort it via its native
    /// side-channel (Postgres: `pg_cancel_backend`). Returns
    /// `ProfileNotFound` if the registry has no matching entry
    /// (request finished, wrong id, or the driver hasn't yet
    /// populated the backend id — cancel is a best-effort
    /// operation under that race).
    pub async fn cancel_request(&self, request_id: &str) -> Result<(), SqlError> {
        let snap: Vec<_> = self
            .in_flight
            .snapshot()
            .into_iter()
            .filter(|e| e.request_id == request_id)
            .collect();
        let Some(entry) = snap.into_iter().next() else {
            return Err(SqlError::ProfileNotFound(request_id.to_owned()));
        };
        let Some(backend_id) = entry.backend_id else {
            // Race: the request is in flight but the driver hasn't
            // captured the backend id yet. Signal back so the
            // caller can retry — or accept that a very short
            // query finished before cancel landed.
            return Err(SqlError::InvalidSpec(format!(
                "request '{request_id}' has no backend_id yet; retry cancel"
            )));
        };
        // We don't re-export the pool per request; look it up via
        // the binding name.
        let runtime = self
            .profiles
            .get(&entry.backend_name)
            .map(|r| r.clone())
            .ok_or_else(|| SqlError::ProfileNotFound(entry.backend_name.clone()))?;
        runtime
            .driver
            .cancel_backend(&runtime.pool, backend_id)
            .await
    }

    /// Start a transaction pinned to one connection from the
    /// binding's pool. The returned handle runs statements
    /// inside the tx until the caller commits or rolls back. Used
    /// by the pipeline executor's `sql_tx` step — statements that
    /// must atomically succeed or roll back together go through
    /// the handle instead of `plugin.execute(...)`.
    ///
    /// Returns `ProfileNotFound` when the binding isn't registered
    /// and `Transport` / `Driver` errors on `BEGIN` failure.
    pub async fn begin_transaction(
        &self,
        backend_name: &str,
    ) -> Result<Arc<dyn SqlTxHandle>, SqlError> {
        let runtime = self
            .profiles
            .get(backend_name)
            .map(|r| r.clone())
            .ok_or_else(|| SqlError::ProfileNotFound(backend_name.to_owned()))?;
        match &runtime.pool {
            #[cfg(feature = "postgres")]
            PoolHandle::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(SqlError::from_execute)?;
                // Apply isolation level immediately after BEGIN,
                // before any other statement runs. Postgres requires the
                // SET to be the first command inside the tx.
                if let Some(level) = runtime.isolation_level {
                    sqlx::query(level.sql_fragment())
                        .execute(&mut *tx)
                        .await
                        .map_err(SqlError::from_execute)?;
                }
                Ok(Arc::new(transaction::postgres::PostgresTxHandle::new(tx)))
            }
            #[cfg(feature = "sqlite")]
            PoolHandle::Sqlite(pool) => {
                let tx = pool.begin().await.map_err(SqlError::from_execute)?;
                // SQLite is always serializable; isolation_level=Serializable
                // is the only allowed value (config validation rejects
                // others), so there's no SET to issue.
                Ok(Arc::new(transaction::sqlite::SqliteTxHandle::new(tx)))
            }
            #[cfg(feature = "mysql")]
            PoolHandle::Mysql(pool) => {
                let mut tx = pool.begin().await.map_err(SqlError::from_execute)?;
                // Apply isolation level immediately after BEGIN
                // (MySQL accepts the same SET TRANSACTION ISOLATION
                // LEVEL syntax as Postgres inside a tx). Skipped when
                // unset.
                if let Some(level) = runtime.isolation_level {
                    sqlx::query(level.sql_fragment())
                        .execute(&mut *tx)
                        .await
                        .map_err(SqlError::from_execute)?;
                }
                Ok(Arc::new(transaction::mysql::MysqlTxHandle::new(tx)))
            }
        }
    }

    /// Number of registered profiles. Useful in tests and for health
    /// reporting.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Build a [`PreparedStmt`] from a validated config. Resolves
    /// `sql_file` paths, rewrites named placeholders, and emits
    /// `CALL` syntax for stored procedures.
    fn prepare_stmt(cfg: &SqlBackendConfig) -> Result<PreparedStmt, SqlError> {
        let raw = match &cfg.query.body {
            QueryBody::Sql { sql } => sql.clone(),
            QueryBody::SqlFile { sql_file } => {
                let body = std::fs::read_to_string(sql_file).map_err(|e| {
                    SqlError::InvalidSpec(format!("sql_file '{}': {e}", sql_file.display()))
                })?;
                // Same multi-statement + privileged-DDL gates the
                // `sql` variant runs at config.validate — file
                // contents are only available here, so the checks
                // run in-place.
                config::reject_multi_statement(&body)?;
                config::reject_privileged_ddl(&body)?;
                body
            }
            QueryBody::Procedure { procedure } => {
                params::call_statement(procedure, cfg.query.params.len(), cfg.driver)
            }
        };

        let (rewritten, order) = params::rewrite_placeholders(&raw, cfg.driver);

        // If rewrite found named placeholders, the declared `params`
        // list must match the rewrite order one-for-one. Otherwise
        // (`$1`/`?` positional form or procedure) we trust the config
        // order.
        let param_order = if order.is_empty() {
            cfg.query.params.clone()
        } else {
            validate_named_params_match_config(&order, &cfg.query.params)?;
            order
        };

        Ok(PreparedStmt {
            sql: rewritten,
            param_order,
            driver: cfg.driver,
        })
    }
}

/// Verify that every `:name` found by the rewrite appears in the
/// declared `params` list. Missing or extra declarations fail config
/// validation.
///
/// Exceptions (plugin-managed placeholders that callers don't supply
/// — operators MUST NOT list them in `params`):
/// - `_after_*` — keyset stream cursor; the plugin auto-binds
///   them at execute time from the cursor token or operator-declared
///   `stream.initial`.
/// - `idempotency_key` / `idempotency_scope_hash` — gateway-supplied
///   idempotency hint. The plugin injects them
///   into the args map from `BackendRequest.idempotency` before
///   binding; if absent, the binder errors at execute time so
///   operator misuse fails loudly.
fn validate_named_params_match_config(
    rewritten_order: &[String],
    declared: &[String],
) -> Result<(), SqlError> {
    // Every rewritten name must appear in `declared`.
    for name in rewritten_order {
        if name.starts_with("_after_") {
            // Plugin-managed (stream keyset). Don't require declaration.
            continue;
        }
        if matches!(name.as_str(), "idempotency_key" | "idempotency_scope_hash") {
            // Plugin-managed. Injected from
            // `BackendRequest.idempotency` at execute time.
            continue;
        }
        if !declared.contains(name) {
            return Err(SqlError::InvalidSpec(format!(
                "named placeholder ':{name}' is not listed in `params`"
            )));
        }
    }
    // Not an error if `declared` has extras — param_exprs may supply
    // them. We log at debug for now.
    for name in declared {
        if !rewritten_order.contains(name) {
            debug!(param = %name, "param declared in config but not referenced in SQL");
        }
    }
    Ok(())
}

/// Wire shape for [`BackendPlugin::execute_transaction`]'s `tx_group`
/// (the gateway's `PipelineSqlTxStepConfig` serialized to JSON). The
/// nested steps are independent — each binds against the same constant
/// `step_input`, none references a prior step's output — so the whole
/// group runs in a single host→plugin round-trip.
#[derive(Debug, Clone, serde::Deserialize)]
struct TxGroupWire {
    steps: Vec<TxNestedStepWire>,
    #[serde(default)]
    step_input: serde_json::Value,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TxNestedStepWire {
    id: String,
    sql: String,
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_tx_row_mode")]
    row_mode: String,
}

fn default_tx_row_mode() -> String {
    "affected_rows".to_owned()
}

/// First column of the first row as a scalar JSON value (the `scalar`
/// row_mode).
fn tx_first_scalar(mut batch: RowBatch) -> serde_json::Value {
    let Some(row) = batch.rows.drain(..).next() else {
        return serde_json::Value::Null;
    };
    match row {
        serde_json::Value::Object(mut map) => map
            .values_mut()
            .next()
            .map(std::mem::take)
            .unwrap_or(serde_json::Value::Null),
        other => other,
    }
}

/// Run one nested statement against the pinned tx handle, shaping the
/// result per `row_mode`. Returns the shaped JSON or an operator-facing
/// error string the caller surfaces on rollback. Reuses the same
/// rewrite/bind/shape as the non-tx `execute` path.
async fn run_tx_nested_step(
    handle: &dyn transaction::SqlTxHandle,
    driver: DriverKind,
    step: &TxNestedStepWire,
    step_input: &serde_json::Value,
    session: &session::SessionVars,
) -> Result<serde_json::Value, String> {
    let (rewritten_sql, order_from_sql) = params::rewrite_placeholders(&step.sql, driver);
    let param_order = if order_from_sql.is_empty() {
        step.params.clone()
    } else {
        order_from_sql
    };
    let args = params::collect_bound_params(step_input, &param_order)
        .map_err(|e| format!("parameter bind for '{}': {e}", step.id))?;
    let stmt = PreparedStmt {
        sql: rewritten_sql,
        param_order,
        driver,
    };
    match step.row_mode.as_str() {
        "affected_rows" => match handle.execute_affected(&stmt, &args, session).await {
            Ok(count) => Ok(serde_json::json!({ "rows_affected": count })),
            Err(e) => Err(format!("execute_affected: {e}")),
        },
        "many" => match handle.execute(&stmt, &args, session).await {
            Ok(batch) => Ok(serde_json::Value::Array(batch.rows)),
            Err(e) => Err(format!("execute: {e}")),
        },
        "single" => match handle.execute(&stmt, &args, session).await {
            Ok(mut batch) => Ok(batch
                .rows
                .drain(..)
                .next()
                .unwrap_or(serde_json::Value::Null)),
            Err(e) => Err(format!("execute: {e}")),
        },
        "scalar" => match handle.execute(&stmt, &args, session).await {
            Ok(batch) => Ok(tx_first_scalar(batch)),
            Err(e) => Err(format!("execute: {e}")),
        },
        other => Err(format!(
            "unsupported row_mode '{other}' (supported: affected_rows, many, single, scalar)"
        )),
    }
}

#[async_trait]
impl BackendPlugin for SqlBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "sql"
    }

    /// Run an atomic `sql_tx` transaction group (v35). Opens one tx on
    /// `backend_name`'s pool, runs every nested step (binding each
    /// against the group's `step_input`), rolls back on any error, else
    /// commits, and returns `{"steps": {<id>: <shaped-result>}}`. This
    /// is the whole transaction lifecycle the gateway used to drive via
    /// the concrete `SqlTxHandle`; it now lives plugin-side so it can
    /// cross the cdylib FFI as a single round-trip.
    async fn execute_transaction(
        &self,
        backend_name: &str,
        tx_group: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendError> {
        let group: TxGroupWire =
            serde_json::from_value(tx_group.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("sql_tx group: {e}"),
            })?;

        let handle = self
            .begin_transaction(backend_name)
            .await
            .map_err(BackendError::from)?;
        let driver = handle.driver();
        let session = session::SessionVars::from_map(std::collections::BTreeMap::new());

        let mut results = serde_json::Map::with_capacity(group.steps.len());
        for step in &group.steps {
            match run_tx_nested_step(handle.as_ref(), driver, step, &group.step_input, &session)
                .await
            {
                Ok(value) => {
                    results.insert(step.id.clone(), value);
                }
                Err(msg) => {
                    // Rollback is best-effort — the primary error is the
                    // step failure; a rollback failure only gets a warn.
                    if let Err(rb) = handle.rollback().await {
                        tracing::warn!(
                            backend = %backend_name,
                            nested_id = %step.id,
                            rollback_error = %rb,
                            "sql_tx: nested step failed; rollback also errored"
                        );
                    }
                    return Err(BackendError::Transport {
                        message: format!("sql_tx nested step '{}': {msg}", step.id),
                    });
                }
            }
        }

        handle.commit().await.map_err(|e| BackendError::Transport {
            message: format!("sql_tx commit: {e}"),
        })?;

        Ok(serde_json::json!({ "steps": serde_json::Value::Object(results) }))
    }

    /// Expose the JSON Schema derived from the prepared statement's
    /// parameter metadata, populated at `register_profile`
    /// time when `schema.derive` asks for it. The host merges this
    /// with operator-supplied schema before publishing in
    /// `tools/list`.
    fn input_schema(&self, backend_name: &str) -> Option<Value> {
        self.profiles
            .get(backend_name)
            .and_then(|r| r.input_schema.clone())
    }

    /// Expose the JSON Schema derived from the prepared statement's
    /// output columns. Shape follows `row_mode`; nullable
    /// columns widen to `{type: [..., "null"]}` so clients can
    /// distinguish absent-column from SQL NULL.
    fn output_schema(&self, backend_name: &str) -> Option<Value> {
        self.profiles
            .get(backend_name)
            .and_then(|r| r.output_schema.clone())
    }

    /// Audit enrichment — surface the SQL engine kind and the
    /// stable per-binding query reference so audit search can filter
    /// `db.driver=postgres` or `db.query_ref=orders.list_open` without
    /// inspecting the resource URI. `kind` (binding type) is already
    /// in the baseline event; this adds engine-level granularity.
    ///
    /// Returns an empty map for unknown bindings — defensive against
    /// audit emission firing in races where the profile is gone.
    fn audit_metadata(&self, backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        if let Some(runtime) = self.profiles.get(backend_name) {
            map.insert(
                "db.driver".into(),
                Value::String(runtime.driver_kind.as_str().to_owned()),
            );
            map.insert(
                "db.query_ref".into(),
                Value::String(backend_name.to_owned()),
            );
            // Surface the configured cost shape so audit
            // search can filter by `db.cost.unit=per_row` etc. Only
            // appears on bindings that declared a `cost:` block.
            if let Some(cost) = runtime.cost.as_ref() {
                for (k, v) in cost.audit_fields() {
                    map.insert(k, v);
                }
            }
        }
        map
    }

    /// Graceful shutdown / drain. Cooperates with the
    /// gateway's `shutdown_all_with_timeout` budget rather than
    /// imposing its own; the internal [`SHUTDOWN_INTERNAL_CAP`]
    /// is a defense-in-depth ceiling, not a primary control.
    ///
    /// Sequence:
    ///
    /// 1. **Set drain flag.** New `execute()` calls short-circuit
    ///    with `Transport { "...is draining..." }` from this point
    ///    forward — the in-flight count walks monotonically down.
    /// 2. **Wake await-loops.** Every active fire-and-wait poll
    ///    `select!`s its sleep arm against `drain_notify`; on notify
    ///    the loop returns `Timeout` immediately rather than ticking
    ///    out the configured `poll_interval_ms`.
    /// 3. **Wait for in-flight to clear.** Poll `in_flight.len()` on
    ///    [`SHUTDOWN_DRAIN_POLL`] (50ms) until it reaches zero or
    ///    [`SHUTDOWN_INTERNAL_CAP`] elapses. The gateway's outer
    ///    timeout typically wins first.
    /// 4. **Close every pool.** `sqlx::Pool::close().await` on each
    ///    registered profile, run concurrently — that signals
    ///    "no new connections" to the pool's idle workers and
    ///    releases sockets cooperatively.
    /// 5. **Clear profiles.** Drops each `ProfileRuntime`, which
    ///    drops the cache-invalidator's `tokio_util::sync::DropGuard`
    ///    and so cancels any active watch-query background tasks.
    ///
    /// If the gateway times us out mid-drain the future is dropped;
    /// the OS reclaims sockets at process exit. Tx handles held by
    /// callers see `Transport` errors when they next touch their
    /// pool — the cooperative outcome.
    async fn shutdown(&self) {
        // Idempotent: a second shutdown() is a no-op. Some test
        // harnesses call shutdown more than once.
        if self.draining.swap(true, Ordering::AcqRel) {
            return;
        }
        self.drain_notify.notify_waiters();

        let started = Instant::now();
        loop {
            let active = self.in_flight.len();
            if active == 0 {
                break;
            }
            if started.elapsed() >= SHUTDOWN_INTERNAL_CAP {
                warn!(
                    in_flight = active,
                    cap_ms = SHUTDOWN_INTERNAL_CAP.as_millis() as u64,
                    "sql plugin shutdown: drain ceiling exceeded; closing pools with calls in flight"
                );
                break;
            }
            tokio::time::sleep(SHUTDOWN_DRAIN_POLL).await;
        }
        let drain_elapsed = started.elapsed();
        info!(
            elapsed_ms = drain_elapsed.as_millis() as u64,
            profiles = self.profiles.len(),
            "sql plugin drained; closing pools"
        );

        // Close every pool concurrently. Cloning is cheap (each
        // PoolHandle wraps an Arc) and `Pool::close()` waits for
        // the pool's existing connections to drain — bounded by
        // the gateway's outer shutdown timeout.
        let mut closes: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(self.profiles.len());
        for entry in self.profiles.iter() {
            let pool = entry.pool.clone();
            let binding = entry.key().clone();
            closes.push(tokio::spawn(async move {
                match pool {
                    #[cfg(feature = "postgres")]
                    PoolHandle::Postgres(p) => p.close().await,
                    #[cfg(feature = "mysql")]
                    PoolHandle::Mysql(p) => p.close().await,
                    #[cfg(feature = "sqlite")]
                    PoolHandle::Sqlite(p) => p.close().await,
                }
                debug!(backend = %binding, "sql pool closed");
            }));
        }
        for h in closes {
            // Errors here only mean the spawn task panicked or was
            // cancelled — either way we've done our best, log and
            // move on.
            if let Err(e) = h.await {
                warn!(error = %e, "sql pool close task failed");
            }
        }

        // Drop runtimes — DropGuards on cache invalidators cancel
        // their watch tasks here.
        self.profiles.clear();
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
    ) -> Result<(), BackendError> {
        // Refuse new registrations after drain has started.
        // The pool we'd build here would be torn down a moment later
        // by `shutdown()`'s `profiles.clear()`, and any in-flight
        // bootstrap (health check, pool warmup) wastes the gateway's
        // shutdown budget.
        if self.draining.load(Ordering::Acquire) {
            return Err(BackendError::Transport {
                message: format!(
                    "sql binding plugin is draining; refusing register_profile for '{backend_name}'"
                ),
            });
        }
        // The host is retained for the response-cache path.
        // Other binding callbacks (invoke_tool / fetch_content) are
        // not used by SQL today, so the field is read by the cache
        // code only.
        let cfg: SqlBackendConfig =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("SQL binding spec: {e}"),
            })?;

        cfg.validate().map_err(BackendError::from)?;

        // CEL-computed params. Compile every declared
        // expression once at register time so runtime cost is a
        // single `execute` per tick.
        let compiled_param_exprs =
            Arc::new(param_exprs::compile_all(&cfg.query.param_exprs).map_err(BackendError::from)?);
        // session_vars driver compatibility is now enforced at
        // config validate (SQLite rejected; MySQL dotted-key rejected).
        // Postgres + MySQL/MariaDB drivers each apply session vars
        // inside their own pinned-connection paths, no warning needed.

        let driver =
            self.drivers
                .get(&cfg.driver)
                .cloned()
                .ok_or_else(|| BackendError::InvalidSpec {
                    message: format!(
                        "driver '{}' is not compiled into this build",
                        cfg.driver.as_str()
                    ),
                })?;

        let stmt = Self::prepare_stmt(&cfg).map_err(BackendError::from)?;

        let (pool, auth_rotator) = pool::build_pool(&cfg, &driver)
            .await
            .map_err(BackendError::from)?;
        driver
            .health_check(&pool)
            .await
            .map_err(BackendError::from)?;

        if cfg.pool.require_cancel_privilege {
            driver
                .verify_cancel_privilege(&pool)
                .await
                .map_err(BackendError::from)?;
        }

        // Per-credential pool registry. Always present so
        // the dynamic-cred path is uniformly available; static-cred
        // profiles never grow it past the static_digest entry.
        let pool_registry = Arc::new(crate::pool::PoolRegistry::new(
            crate::pool::PoolRegistryConfig::default(),
        ));
        // Detect whether the URL or any session-vars value carries
        // a `${cred://…}` credential token. Profiles with none short-
        // circuit resolution + identity checks entirely on every call
        // — bit-for-bit equivalent to the static-only path. A bare
        // `cred://…` does not count (it travels verbatim).
        let has_cred_refs = config_has_cred_refs(&cfg);
        // Subscribe to revocation events. The closure routes
        // (plugin_id, target) invalidations to the registry's
        // evict_for; the guard is held in the ProfileRuntime so
        // unsubscription happens at profile teardown.
        let registry_for_cb = Arc::clone(&pool_registry);
        let revocation_sub =
            host.subscribe_credential_revoked(Arc::new(move |plugin_id: &str, target: &str| {
                let registry = Arc::clone(&registry_for_cb);
                let plugin_id = plugin_id.to_owned();
                let target = target.to_owned();
                // The callback runs inside the credential cache's
                // lock guard; spawn so we don't block the cache or
                // try to acquire the registry's mutex re-entrantly.
                tokio::spawn(async move {
                    let evicted = registry.evict_for(&plugin_id, &target).await;
                    if evicted > 0 {
                        tracing::info!(
                            target: "mcpg::sql::pool_registry",
                            plugin_id = %plugin_id,
                            target = %target,
                            evicted = evicted,
                            "evicted SQL pools on credential revocation"
                        );
                    }
                });
            }));

        // Secret rotation: subscribe to URI-scoped rotation
        // events. The `__mcpg_secret_refs` hint the gateway injected
        // post-resolution names which `vault://...` (or other) URIs
        // were expanded into this profile's spec. The subscription
        // closure short-circuits unless the rotated `secret_ref` is
        // in that list.
        let rotation_secret_refs: Vec<String> = spec
            .get("__mcpg_secret_refs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let registry_for_rotation = Arc::clone(&pool_registry);
        let secret_refs_for_cb: Arc<Vec<String>> = Arc::new(rotation_secret_refs);
        let rotation_sub =
            host.subscribe_secret_rotation(Arc::new(move |secret_ref: &str, version: u64| {
                if !secret_refs_for_cb.iter().any(|r| r == secret_ref) {
                    return;
                }
                let registry = Arc::clone(&registry_for_rotation);
                let secret_ref = secret_ref.to_owned();
                tokio::spawn(async move {
                    let evicted = registry.evict_for_secret(&secret_ref).await;
                    if evicted > 0 {
                        tracing::info!(
                            target: "mcpg::sql::pool_registry",
                            secret_ref = %secret_ref,
                            version = version,
                            evicted = evicted,
                            "evicted SQL pools on secret rotation"
                        );
                    }
                });
            }));

        // Idle-pool sweeper. Bounded background task that
        // walks the registry every ~minute and drops pools whose
        // last_used age exceeds `idle_eviction`. The Arc holds the
        // task alive past hot-reload (in-flight executes carry a
        // clone of the runtime, hence a clone of the Arc); cancel
        // fires when the last reference drops.
        let idle_sweeper = crate::pool::spawn_idle_sweeper(
            backend_name.to_owned(),
            Arc::clone(&pool_registry),
            Duration::from_secs(60),
        );

        let timeout_dur =
            Duration::from_millis(cfg.query.timeout_ms.unwrap_or(DEFAULT_QUERY_TIMEOUT_MS));

        let input_schema = if cfg.schema.derive.includes_input() {
            match driver
                .describe_parameters(&pool, &stmt.sql, &stmt.param_order)
                .await
            {
                Ok(Some(v)) => Some(v),
                Ok(None) => {
                    warn!(
                        backend = %backend_name,
                        "schema.derive requested input but driver returned no parameter \
                         metadata; falling back to operator-supplied schema"
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        backend = %backend_name,
                        error = %e,
                        "schema.derive failed; falling back to operator-supplied schema"
                    );
                    None
                }
            }
        } else {
            None
        };

        let output_schema = if cfg.schema.derive.includes_output() {
            match driver
                .describe_columns(&pool, &stmt.sql, cfg.query.row_mode)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        backend = %backend_name,
                        error = %e,
                        "schema.derive: output-column introspection failed; \
                         falling back to operator-supplied schema"
                    );
                    None
                }
            }
        } else {
            None
        };

        // Prepare the list_query once at registration so runtime
        // pagination is bind-only, same fast path as the main stmt.
        // `list_query.sql` may reference `:cursor` (bound per call) and
        // `:page_size` (bound from config). Any other `:name` it pulls
        // in is rejected — the listing surface doesn't accept extra
        // caller-supplied args.
        let list = if let Some(list_cfg) = cfg.list_query.clone() {
            let (rewritten, order) = params::rewrite_placeholders(&list_cfg.sql, cfg.driver);
            for name in &order {
                if name != "cursor" && name != "page_size" {
                    return Err(BackendError::InvalidSpec {
                        message: format!(
                            "list_query references ':{name}' but only ':cursor' \
                             and ':page_size' are bound by the plugin"
                        ),
                    });
                }
            }
            let list_stmt = PreparedStmt {
                sql: rewritten,
                param_order: order,
                driver: cfg.driver,
            };
            Some((list_stmt, list_cfg))
        } else {
            None
        };

        // Compile the `await:` block once at registration.
        // The CEL predicate's `row` identifier is bound per-tick
        // from the check query's first row. Empty result sets
        // skip evaluation and retry on the next poll.
        let await_rt = if let Some(aw) = cfg.r#await.clone() {
            let predicate_program =
                cel::Program::compile(&aw.predicate).map_err(|e| BackendError::InvalidSpec {
                    message: format!("await.predicate CEL compile failed: {e}"),
                })?;
            let (check_sql, check_order) = params::rewrite_placeholders(&aw.check.sql, cfg.driver);
            let check_param_order = if check_order.is_empty() {
                aw.check.params.clone()
            } else {
                check_order
            };
            let check_stmt = PreparedStmt {
                sql: check_sql,
                param_order: check_param_order,
                driver: cfg.driver,
            };
            let trigger_stmt = if let Some(trig) = &aw.trigger {
                let (trig_sql, trig_order) = params::rewrite_placeholders(&trig.sql, cfg.driver);
                let trig_param_order = if trig_order.is_empty() {
                    trig.params.clone()
                } else {
                    trig_order
                };
                Some(PreparedStmt {
                    sql: trig_sql,
                    param_order: trig_param_order,
                    driver: cfg.driver,
                })
            } else {
                None
            };
            Some(AwaitRuntime {
                cfg: aw,
                trigger_stmt,
                check_stmt,
                predicate: Arc::new(predicate_program),
            })
        } else {
            None
        };

        // Build StreamRuntime when row_mode: stream. The signing key
        // is taken from the already-resolved `signing_key` value if
        // the operator set one — required for cluster deploys so a
        // cursor minted on instance A verifies on instance B. Without
        // it the plugin generates a per-process random key and warns:
        // cross-node continuation calls will fail verification,
        // single-node continues to work fine.
        let stream_rt = if cfg.query.row_mode == RowMode::Stream {
            let stream_cfg = cfg
                .query
                .stream
                .clone()
                .expect("validate() ensures stream block is present for row_mode: stream");
            let key = match stream_cfg.signing_key.as_ref() {
                Some(value) if !value.expose().is_empty() => {
                    crate::stream::CursorSigningKey::from_bytes(value.expose().as_bytes())
                }
                _ => {
                    tracing::warn!(
                        backend = %backend_name,
                        "sql: row_mode: stream — no `stream.signing_key` set; using \
                         per-process random key. Cursors minted on this instance will \
                         FAIL verification on other instances. For cluster deployments, \
                         set stream.signing_key to share the key across instances."
                    );
                    crate::stream::CursorSigningKey::generate()
                }
            };
            Some(StreamRuntime {
                cfg: stream_cfg,
                key,
            })
        } else {
            None
        };

        // Snapshot a shareable handle to the full config before any
        // partial moves below; the per-credential pool builder needs
        // it on every dynamic-cred call.
        let cfg_arc = Arc::new(cfg.clone());

        let session_vars = SessionVars::from_map(cfg.session_vars);

        // Spawn the cache-invalidation watcher when
        // `cache.enabled` and `cache.invalidate_on` are both set.
        // Validation has already accepted the SQL shape; here we
        // prepare the tracking statement, share the binding's
        // pool / driver / session vars, and hand off to the
        // background loop. The returned `Arc<CacheInvalidator>`
        // is stored on the runtime; its drop guard cancels the
        // task when the last reference (including in-flight
        // execute clones) drops.
        let cache_invalidator = if let Some(cache_cfg) = cfg.cache.as_ref()
            && cache_cfg.enabled
            && let Some(crate::config::CacheInvalidateOn::Watch { sql, interval_ms }) =
                cache_cfg.invalidate_on.as_ref()
        {
            let (rewritten, _order) = params::rewrite_placeholders(sql, cfg.driver);
            let tracking_stmt = crate::params::PreparedStmt {
                sql: rewritten,
                param_order: vec![],
                driver: cfg.driver,
            };
            Some(crate::cache::spawn_invalidator(
                backend_name.to_owned(),
                Arc::clone(&driver),
                pool.clone(),
                tracking_stmt,
                session_vars.clone(),
                Duration::from_millis(*interval_ms),
            ))
        } else {
            None
        };

        let runtime = ProfileRuntime {
            driver_kind: cfg.driver,
            driver,
            pool,
            pool_registry: Arc::clone(&pool_registry),
            cfg: Arc::clone(&cfg_arc),
            has_cred_refs,
            _revocation_sub: Arc::new(revocation_sub),
            _rotation_sub: Arc::new(rotation_sub),
            _idle_sweeper: idle_sweeper,
            _auth_rotator: auth_rotator,
            stmt,
            row_mode: cfg.query.row_mode,
            max_rows: cfg.query.max_rows,
            timeout: timeout_dur,
            session_vars,
            progress_heartbeat: cfg.query.progress_heartbeat_ms.map(Duration::from_millis),
            input_schema,
            output_schema,
            param_exprs: compiled_param_exprs,
            breaker: cfg
                .circuit_breaker
                .map(|c| Arc::new(breaker::CircuitBreaker::new(c))),
            list,
            await_rt,
            stream_rt,
            isolation_level: cfg.isolation_level,
            cache: cfg.cache,
            cache_invalidator,
            cost: match cfg.cost.as_ref() {
                Some(c) => Some(crate::cost::BackendCost::compile(c).map_err(BackendError::from)?),
                None => None,
            },
            host,
        };

        info!(
            backend = %backend_name,
            driver = runtime.driver_kind.as_str(),
            row_mode = ?runtime.row_mode,
            "registered SQL binding profile"
        );
        self.profiles.insert(backend_name.to_owned(), runtime);
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        // Refuse new work the moment shutdown() flips the
        // drain flag. Returning before any pool checkout / in-flight
        // registration means the gateway can race shutdown to a
        // deterministic finish: the in-flight count only walks
        // monotonically downward from this point, never up. Acquire
        // ordering pairs with the Release store in `shutdown()`.
        if self.draining.load(Ordering::Acquire) {
            return Err(BackendError::Transport {
                message: "sql binding plugin is draining; refusing new requests".into(),
            });
        }
        let t0 = std::time::Instant::now();
        let request_id = request.request_id.clone();
        let session_id = request.session_id.clone();
        let identity = request.identity.clone();
        // Wrap engine call in a plugin-scoped span so
        // traces from SQL execute attribute back to
        // `dev.mcpg.backend.sql` for per-plugin override. Driver
        // recorded as a static label since it's enum-bounded.
        let driver_label = self
            .profiles
            .get(backend_name)
            .map(|pr| pr.driver_kind.as_str())
            .unwrap_or("unknown");
        let span = info_span!(
            "sql_binding_execute",
            plugin_id = "dev.mcpg.backend.sql",
            backend = %backend_name,
            driver = driver_label,
        );

        // Open a host-attributed span ALONGSIDE
        // the internal `info_span!` above. The internal span flows
        // through the local `tracing` subscriber; the host span
        // routes to the central observability sink with the plugin
        // alias as a resource attribute. Both are useful — the
        // central sink correlates the SQL plugin's work with the
        // inbound tool call's trace, the local span keeps the
        // historical SQL-plane tracing surface intact.
        //
        // Attrs are bounded: backend name (config-bounded), driver
        // (enum), request id (already on the inbound span). Query
        // SQL is NEVER attached — it would blow span attribute
        // cardinality + leak operator query bodies into the central
        // trace store.
        let host_span = self.host_handle().map(|h| {
            h.span(
                "sql_backend.execute",
                serde_json::json!({
                    "backend": backend_name,
                    "driver": driver_label,
                    "request_id": request_id,
                }),
            )
        });

        let result = self
            .execute_inner(backend_name, request)
            .instrument(span)
            .await;
        // Emit metrics regardless of outcome. Cardinality-guarded
        // labels: binding name (config-bounded), driver (enum),
        // status (closed set). SQL text never becomes a label.
        if let Some(pr) = self.profiles.get(backend_name) {
            let rows = match &result {
                Ok(resp) => serde_json::from_slice::<Value>(&resp.payload)
                    .ok()
                    .and_then(|v| row_count_hint(&v)),
                Err(_) => None,
            };
            let status = match &result {
                Ok(_) => CallStatus::Success,
                Err(BackendError::Timeout { .. }) => CallStatus::Timeout,
                Err(BackendError::InvalidSpec { .. }) => CallStatus::InvalidSpec,
                Err(_) => CallStatus::TransportError,
            };
            let duration = t0.elapsed();
            metrics::record_call(
                backend_name,
                backend_name, // query_ref == binding name until named-query libraries land
                pr.driver_kind,
                status,
                duration,
                rows,
            );
            // Structured SQL-plane audit event.
            //
            // Emits per call at target `mcpg::sql::audit` so an
            // operator's tracing subscriber can route it to a SIEM
            // independently of the gateway's audit plugin. Fields
            // captured here are the SQL-specific half: driver, query
            // outcome, rows. The gateway's AuditPlugin emits the
            // principal + transport + timestamp half via the
            // tool-gate chain. Correlate the two streams on
            // `request_id` (present on both). SQL text is never
            // logged — `binding` is the query_ref.
            let error_kind: Option<&'static str> = match &result {
                Err(BackendError::Timeout { .. }) => Some("timeout"),
                Err(BackendError::InvalidSpec { .. }) => Some("invalid_spec"),
                Err(BackendError::Transport { .. }) => Some("transport"),
                Err(BackendError::ProfileNotFound { .. }) => Some("profile_not_found"),
                _ => None,
            };
            tracing::info!(
                target: "mcpg::sql::audit",
                backend = %backend_name,
                driver = pr.driver_kind.as_str(),
                request_id = %request_id,
                session_id = session_id.as_deref().unwrap_or(""),
                duration_ms = duration.as_millis() as u64,
                rows = rows.unwrap_or(0),
                status = status.as_str(),
                error_kind = error_kind.unwrap_or(""),
                "sql call"
            );

            // Unified host-observability triad.
            // Runs ALONGSIDE the metrics::record_call + audit
            // tracing::info! calls above; coexistence is intentional
            // until the triad-floor sinks subsume the internal calls.
            //
            // Cardinality budget: outcome ∈ {ok, timeout, transport,
            // invalid_spec, profile_not_found}, driver ∈ enum-bounded
            // SQL engines. Backend name is NOT attached to metrics
            // labels here — the SQL plugin already emits per-backend
            // counters via `metrics::record_call`, and the host's
            // metric sink already adds `plugin_alias` automatically.
            if let Some(host) = self.host_handle() {
                let outcome_label = host_outcome_label(&result);
                let elapsed_secs = duration.as_secs_f64();
                host.histogram(
                    "mcpg_sql_backend_latency_seconds",
                    elapsed_secs,
                    &[
                        ("outcome", outcome_label),
                        ("driver", pr.driver_kind.as_str()),
                    ],
                );
                host.counter(
                    "mcpg_sql_backend_calls_total",
                    1,
                    &[
                        ("outcome", outcome_label),
                        ("driver", pr.driver_kind.as_str()),
                    ],
                );

                // Audit events ONLY on notable outcomes (the
                // operator wants to reconstruct failures after the
                // fact). Successful calls would flood the audit
                // sink at SQL traffic rates — the per-call SQL
                // audit line at target `mcpg::sql::audit` is
                // already on the success path. We map the bounded
                // `BackendError` enum onto a small set of dotted
                // audit action names; anything else (or success)
                // skips audit emission entirely.
                if let Some(action) = audit_action_for(&result) {
                    let reason = match &result {
                        Err(e) => e.to_string(),
                        Ok(_) => String::new(),
                    };
                    let event = AuditEvent {
                        event_id: format!("sql-{}-{}", request_id, t0.elapsed().as_nanos()),
                        occurred_at: rfc3339_now(),
                        actor: identity.clone().unwrap_or_else(synthetic_system_identity),
                        action: action.to_owned(),
                        resource: Some(format!("sql-binding://{backend_name}")),
                        outcome: AuditOutcome::Failure,
                        request_id: Some(request_id.clone()),
                        node_id: None,
                        details: serde_json::json!({
                            "backend": backend_name,
                            "driver": pr.driver_kind.as_str(),
                            "duration_ms": duration.as_millis() as u64,
                            "reason": reason,
                            "alias": host.alias(),
                        }),
                        prev_event_hash: None,
                    };
                    // `HostHandle::audit_event` is sync and bridges
                    // an async `HostServices::audit_event` call
                    // through `Handle::block_on` on the static-
                    // firstparty path. Calling that directly from
                    // the multi-threaded runtime worker we're on
                    // would panic (`Cannot start a runtime from
                    // within a runtime`). Move the call onto a
                    // blocking worker and await the result so audit
                    // emission completes BEFORE we return to the
                    // caller — operators want failure audit lines
                    // to land before the failure surfaces upstream
                    // so retries can be correlated against the audit
                    // record by request_id.
                    //
                    // An `_async` variant on HostHandle for
                    // `audit_event` / `resolve_secret` /
                    // `config_snapshot` / `issue_credential` would
                    // let async plugins call them directly without
                    // the spawn_blocking detour.
                    let host_for_audit = host.clone();
                    if let Err(join_err) = tokio::task::spawn_blocking(move || {
                        let _ = host_for_audit.audit_event(event);
                    })
                    .await
                    {
                        // Cancelled or panicked — log at debug and
                        // continue; audit emission is best-effort.
                        debug!(
                            target: "mcpg::sql::host_handle",
                            error = %join_err,
                            "host_handle.audit_event spawn_blocking failed"
                        );
                    }
                }
            }
        }

        // Explicitly drop the host span here so its Drop-driven
        // `span_end` fires AFTER the metrics + audit emission
        // above. Implicit drop at end-of-scope would close the span
        // earlier and the host-sink would see the close before the
        // metric / audit emissions attributed to the same call.
        drop(host_span);

        result
    }

    /// Enumerate resources via the registered `list_query`.
    ///
    /// Returns an empty page for bindings without a `list_query` —
    /// the host merges the empty page with its static registry and
    /// moves on. Keyset mode binds `:cursor` to NULL on the first
    /// page and to the prior page's last `cursor_column` value on
    /// subsequent pages; offset mode binds `:cursor` to the
    /// integer offset.
    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let runtime = self
            .profiles
            .get(backend_name)
            .ok_or_else(|| SqlError::ProfileNotFound(backend_name.to_owned()))?
            .clone();
        let Some((list_stmt, list_cfg)) = &runtime.list else {
            return Ok(ResourcePage::empty());
        };
        let batch = self
            .run_list_query(&runtime, list_stmt, list_cfg, cursor)
            .await?;
        let page = batch_to_resource_page(batch, list_cfg);
        Ok(page)
    }

    /// Run an operator-declared completion query bound to `:prefix`
    /// plus any `:ctx_<key>` named parameters that resolve to entries
    /// in the MCP completion `context.arguments` map.
    ///
    /// `config` shape:
    ///
    /// ```json
    /// { "query": "SELECT DISTINCT repo FROM repos WHERE owner = :ctx_owner AND repo LIKE :prefix || '%' LIMIT 100",
    ///   "max_results": 100 }
    /// ```
    ///
    /// `query` MUST contain `:prefix`. `max_results` defaults to 100
    /// to mirror the gateway's clamp. Returns the first column of
    /// each row coerced to a string; non-string cells are skipped.
    /// Errors map through the standard SqlError → BackendError
    /// conversion; the gateway treats all errors as "no completion
    /// values" (UX hint, not load-bearing).
    ///
    /// `:ctx_<key>` placeholders are resolved from the `context` map
    /// passed by the gateway: `:ctx_owner` binds the value of the
    /// `owner` key. Keys that are not valid SQL identifier suffixes
    /// (alphanumeric + underscore) are logged at warn and skipped at
    /// bind time — the call still proceeds, but `:ctx_<bad-key>` will
    /// fail with `InvalidSpec`. If a context entry is unused, that's
    /// fine; named-parameter binding does not require all keys to be
    /// referenced by the query.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        _variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let cfg: SqlCompletionConfig =
            serde_json::from_value(config.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("variable_completions.config: {e}"),
            })?;
        if !cfg.query.contains(":prefix") {
            return Err(BackendError::InvalidSpec {
                message: "variable_completions.config.query must reference `:prefix`".into(),
            });
        }
        let runtime = self
            .profiles
            .get(backend_name)
            .ok_or_else(|| SqlError::ProfileNotFound(backend_name.to_owned()))?
            .clone();

        // Build a `:ctx_<key>` lookup table from the MCP context map,
        // dropping any key that would form an invalid SQL identifier
        // suffix. Skipping (vs sanitizing) keeps the bind-name surface
        // honest — a referenced `:ctx_bad-key` becomes a hard error
        // below instead of silently rebinding a different name.
        let mut ctx_binds: std::collections::HashMap<String, String> =
            std::collections::HashMap::with_capacity(context.len());
        for (k, v) in context {
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                tracing::warn!(
                    target: "mcpg::sql::completion",
                    backend = %backend_name,
                    key = %k,
                    "completion context key is not a valid SQL identifier suffix; skipping"
                );
                continue;
            }
            ctx_binds.insert(k.to_ascii_lowercase(), v.clone());
        }

        let (rewritten, order) =
            crate::params::rewrite_placeholders(&cfg.query, runtime.driver_kind);
        let stmt = PreparedStmt {
            sql: rewritten,
            param_order: order,
            driver: runtime.driver_kind,
        };
        let mut args = Vec::with_capacity(stmt.param_order.len());
        for name in &stmt.param_order {
            let value = if name == "prefix" {
                Value::String(prefix.to_owned())
            } else if let Some(rest) = name.strip_prefix("ctx_") {
                match ctx_binds.get(rest) {
                    Some(v) => Value::String(v.clone()),
                    None => {
                        return Err(BackendError::InvalidSpec {
                            message: format!(
                                "variable_completions.config.query references `:ctx_{rest}` but completion context has no `{rest}` entry"
                            ),
                        });
                    }
                }
            } else {
                return Err(BackendError::InvalidSpec {
                    message: format!(
                        "variable_completions.config.query references unsupported placeholder ':{name}' (only :prefix and :ctx_<key> are bound)"
                    ),
                });
            };
            args.push(BoundParam {
                name: name.clone(),
                value,
            });
        }

        let batch = runtime
            .driver
            .execute(&runtime.pool, &stmt, &args, &runtime.session_vars)
            .await
            .map_err(BackendError::from)?;

        let max = cfg.max_results.unwrap_or(100) as usize;
        let mut out: Vec<String> = Vec::with_capacity(batch.rows.len().min(max));
        let first_col = batch.columns.first().cloned();
        for row in batch.rows.into_iter().take(max) {
            let cell = match (&first_col, &row) {
                (Some(col), Value::Object(map)) => map.get(col).cloned(),
                _ => None,
            };
            if let Some(Value::String(s)) = cell {
                out.push(s);
            }
        }
        Ok(out)
    }
}

#[derive(Debug, serde::Deserialize)]
struct SqlCompletionConfig {
    /// SQL with `:prefix` placeholder. The plugin rewrites named
    /// placeholders for the active driver and binds `:prefix` to the
    /// caller's typed prefix at call time.
    query: String,
    /// Optional cap on returned rows; defaults to 100. Mirrors the
    /// gateway's clamp at the dispatch layer.
    #[serde(default)]
    max_results: Option<u32>,
}

impl SqlBackendPlugin {
    /// Bind `:cursor` / `:page_size` per the operator's rewritten
    /// list statement order, run through the driver, and return the
    /// row batch. Pagination-mode coherence is already validated at
    /// config time, so this path only does binding + dispatch.
    async fn run_list_query(
        &self,
        runtime: &ProfileRuntime,
        list_stmt: &PreparedStmt,
        list_cfg: &crate::config::ListQueryConfig,
        cursor: Option<&str>,
    ) -> Result<driver::RowBatch, SqlError> {
        let cursor_value = match (list_cfg.mode, cursor) {
            (crate::config::ListQueryMode::Keyset, None) => Value::Null,
            (crate::config::ListQueryMode::Keyset, Some(c)) => Value::String(c.to_owned()),
            (crate::config::ListQueryMode::Offset, None) => {
                Value::Number(serde_json::Number::from(0u64))
            }
            (crate::config::ListQueryMode::Offset, Some(c)) => match c.parse::<u64>() {
                Ok(n) => Value::Number(serde_json::Number::from(n)),
                Err(_) => {
                    return Err(SqlError::InvalidSpec(format!(
                        "offset-mode cursor '{c}' is not a non-negative integer"
                    )));
                }
            },
        };
        let page_size_value = Value::Number(serde_json::Number::from(list_cfg.page_size));

        let mut args = Vec::with_capacity(list_stmt.param_order.len());
        for name in &list_stmt.param_order {
            let value = match name.as_str() {
                "cursor" => cursor_value.clone(),
                "page_size" => page_size_value.clone(),
                other => {
                    return Err(SqlError::InvalidSpec(format!(
                        "list_query references unsupported placeholder ':{other}'"
                    )));
                }
            };
            args.push(BoundParam {
                name: name.clone(),
                value,
            });
        }

        runtime
            .driver
            .execute(&runtime.pool, list_stmt, &args, &runtime.session_vars)
            .await
    }

    async fn execute_inner(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let runtime = self
            .profiles
            .get(backend_name)
            .map(|r| r.clone())
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: backend_name.to_owned(),
            })?;

        // Circuit breaker. If configured and currently Open,
        // fast-fail with a Transport error before we even acquire a
        // pool connection. If Closed, admit and carry the guard
        // across the call — its outcome feeds the breaker's state
        // machine at the end.
        let admit = runtime
            .breaker
            .as_ref()
            .map(|b| b.try_admit())
            .transpose()
            .map_err(BackendError::from)?;

        let result = self
            .execute_inner_impl(backend_name, request, &runtime)
            .await;

        // Record outcome only for driver-class failures
        // (Timeout / Transport). Operator-class errors (InvalidSpec,
        // ProfileNotFound) are bugs or config drift, not DB health
        // signals, so the breaker ignores them.
        if let Some(guard) = admit {
            let success = !matches!(
                &result,
                Err(BackendError::Timeout { .. }) | Err(BackendError::Transport { .. })
            );
            guard.record(success);
        }
        result
    }

    /// Pick the pool to use for this request. Static-cred profiles
    /// short-circuit to `runtime.pool`; dynamic-cred profiles ask the
    /// host to resolve the `${cred://…}` tokens in the URL +
    /// session_vars, then fetch / build a pool from `pool_registry`
    /// keyed on the BLAKE3 digest of the resolved bundle.
    ///
    /// On the dynamic path, requests with `identity: None` (system-
    /// initiated calls — await runtime, watch fetcher) get refused
    /// with a `Transport` error so an arbitrary identity isn't
    /// silently used to satisfy a caller-scoped credential.
    async fn resolve_pool_for_call(
        &self,
        backend_name: &str,
        request: &BackendRequest,
        runtime: &ProfileRuntime,
    ) -> Result<PoolHandle, BackendError> {
        if !runtime.has_cred_refs {
            return Ok(runtime.pool.clone());
        }
        let resolved = resolve_creds_for(runtime, request, backend_name).await?;
        let driver = Arc::clone(&runtime.driver);
        let cfg = Arc::clone(&runtime.cfg);
        let url = resolved.url.clone();
        let pool = runtime
            .pool_registry
            .get_or_build(resolved.digest, resolved.cred_keys.clone(), || async move {
                crate::pool::build_pool_with_url(&cfg, &url, &driver).await
            })
            .await
            .map_err(BackendError::from)?;
        Ok(pool)
    }

    async fn execute_inner_impl(
        &self,
        backend_name: &str,
        request: BackendRequest,
        runtime: &ProfileRuntime,
    ) -> Result<BackendResponse, BackendError> {
        // Fire-and-wait path: when the binding declares an
        // `await:` block, the normal query path is skipped —
        // instead we run the trigger (once) and poll the check
        // query until the CEL predicate matches or the deadline
        // expires. The main query body still has to exist per the
        // schema but is intentionally unused.
        if runtime.await_rt.is_some() {
            return self
                .execute_await_loop(backend_name, request, runtime)
                .await;
        }

        // Register in the in-flight table. RAII guard: the
        // entry is removed when `_in_flight` drops — end of scope,
        // early return, or panic — so the registry cannot leak.
        // The guard also refreshes the `mcpg_sql_requests_in_flight`
        // gauge on both register and drop.
        let _in_flight = in_flight::InFlightGuard::register(
            Arc::clone(&self.in_flight),
            request.request_id.clone(),
            backend_name.to_owned(),
            runtime.driver_kind,
        );

        // Pick the pool for this call. Profiles with no
        // `${cred://…}` token fall through to the static pool,
        // bit-for-bit equivalent to the static-only path. Profiles that
        // do carry a token resolve per-call via the host and
        // hit the per-credential registry.
        let pool: PoolHandle = self
            .resolve_pool_for_call(backend_name, &request, runtime)
            .await?;
        let active_session_vars: Option<SessionVars>;
        let session_vars_ref: &SessionVars;
        // The session-vars set may also have been substituted —
        // when it has, build a per-call SessionVars on the stack.
        // This branch fires only on the dynamic path; the static
        // path uses the pre-built `runtime.session_vars`.
        if runtime.has_cred_refs {
            // Re-resolve to get the resolved session-vars values
            // (small alloc; credential resolver hits the cache the
            // second time so it's effectively free).
            let resolved = resolve_creds_for(runtime, &request, backend_name).await?;
            active_session_vars = Some(SessionVars::from_map(resolved.session_vars));
            session_vars_ref = active_session_vars.as_ref().unwrap();
        } else {
            active_session_vars = None;
            session_vars_ref = &runtime.session_vars;
        }
        // Suppress dead_code lint when the dynamic path is unused.
        let _ = &active_session_vars;

        let mut args_value: Value = if request.payload.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&request.payload).map_err(|e| BackendError::InvalidSpec {
                message: format!("request payload is not valid JSON: {e}"),
            })?
        };

        // Inject CEL-computed params into the args map before
        // placeholder binding. Each compiled expression evaluates
        // against `arguments` and overwrites any caller-supplied
        // value under the same name — operator derivations are
        // not spoofable by clients.
        if !runtime.param_exprs.is_empty() {
            param_exprs::evaluate_into(&mut args_value, runtime.param_exprs.as_slice())
                .map_err(BackendError::from)?;
        }

        // Stream-cursor decoding. When the binding is in
        // stream mode, the plugin injects `_after_<col>` keyset
        // values into the args map before placeholder binding:
        //   • If the caller passed `_cursor: "<token>"`, decode +
        //     verify the HMAC-bound token, check binding-name
        //     match, and bind each cursor_columns entry from the
        //     decoded keyset.
        //   • Else (first page) bind from `stream.initial[col]` if
        //     the operator declared one, otherwise bind JSON null.
        //
        // After this step `_after_<col>` is overwritten in the
        // args map regardless of whether the caller tried to set
        // it directly — keyset values are server-controlled and
        // must not be caller-spoofable. The `_cursor` arg itself is
        // also stripped so it doesn't bleed into operator-declared
        // params with the same name.
        if let Some(stream_rt) = runtime.stream_rt.as_ref() {
            apply_stream_cursor(&mut args_value, stream_rt, backend_name)
                .map_err(BackendError::from)?;
        }

        // Inject the gateway-supplied idempotency
        // hint as named params so operator UPSERT / dedupe-table
        // queries can reference `:idempotency_key` and
        // `:idempotency_scope_hash`. Mirrors the pattern used by the
        // built-in `:prefix` (variable_completions) and `:ctx_*`
        // (per-call principal) injections — the args map is the
        // single source the placeholder binder reads, so we inject
        // BEFORE `collect_bound_params`.
        //
        // Behavior matrix:
        // - hint present, query references `:idempotency_key`:
        //   binds verbatim (the primary path).
        // - hint present, query doesn't reference it: silently
        //   unused, same as `:prefix` in queries that don't need it.
        // - hint absent, query references it: error from the
        //   placeholder binder ("missing required parameter
        //   'idempotency_key'") — operator wrote a query that
        //   requires the key, so calling without one is an
        //   integration error and must surface loudly.
        if let Some(hint) = request.idempotency.as_ref() {
            // Args may be Null when the caller passed no arguments
            // (a legitimate case for dedupe-table queries that derive
            // every param from the hint). Normalise to an empty
            // object so the named-param binder can find the keys.
            if matches!(args_value, Value::Null) {
                args_value = Value::Object(serde_json::Map::new());
            }
            if let Value::Object(obj) = &mut args_value {
                obj.insert(
                    "idempotency_key".to_owned(),
                    Value::String(hint.key.clone()),
                );
                obj.insert(
                    "idempotency_scope_hash".to_owned(),
                    Value::String(hint.scope_hash.clone()),
                );
            }
            // Non-object args (array, scalar) keep the existing
            // collect_bound_params error path: SQL bindings require
            // an object-shaped args payload. Don't try to repair —
            // operator misuse should fail loudly.
        }

        let bound = params::collect_bound_params(&args_value, &runtime.stmt.param_order)
            .map_err(BackendError::from)?;

        // Response cache lookup. Validation already excludes
        // unsafe row modes (affected_rows, stream, result_sets) and
        // procedure bodies, so reaching this branch with `cache.enabled`
        // means we're on a read-shaped SELECT. The host's
        // `cache_get` is keyed per-binding by the gateway,
        // so different bindings never collide; absent a backend the
        // call is a no-op (default `Ok(None)`) and we fall through
        // to the upstream call.
        let cache_key_opt = if let Some(cache) = runtime.cache.as_ref()
            && cache.enabled
        {
            let version = runtime
                .cache_invalidator
                .as_ref()
                .map(|inv| inv.version())
                .unwrap_or(0);
            let key = cache::build_cache_key(
                backend_name,
                &runtime.stmt.sql,
                &bound,
                session_vars_ref,
                version,
            );
            let mut host_ctx = BackendInvocationContext::root(
                request.request_id.clone(),
                request.session_id.clone(),
                backend_name.to_owned(),
            );
            host_ctx.identity = request.identity.clone();
            match runtime.host.cache_get(&host_ctx, key.as_str()).await {
                Ok(Some(bytes)) => {
                    if bytes.len() < CACHE_HEADER_LEN {
                        debug!(
                            backend = %backend_name,
                            "sql cache hit but stored value smaller than header; treating as miss"
                        );
                        Some(key)
                    } else {
                        let truncated = bytes[0] != 0;
                        let payload = bytes.slice(CACHE_HEADER_LEN..);
                        metrics::record_cache_hit(backend_name, runtime.driver_kind);
                        return Ok(BackendResponse {
                            payload: payload.to_vec(),
                            truncated,
                        });
                    }
                }
                Ok(None) => {
                    metrics::record_cache_miss(backend_name, runtime.driver_kind);
                    Some(key)
                }
                Err(e) => {
                    debug!(?e, backend = %backend_name, "sql cache_get failed; falling through");
                    None
                }
            }
        } else {
            None
        };

        // `AffectedRows` requires an `execute`-style submission so the
        // server-reported rows_affected is populated. Other modes use
        // the row-returning path.
        //
        // Both paths are wrapped in `with_heartbeat` so a long-running
        // query periodically emits a tracing event + metrics counter
        // while it waits on the driver. The heartbeat task is torn
        // down as soon as the primary future completes.
        //
        // Schema-drift retry: if the driver returns an error
        // carrying a stale-statement SQLSTATE (Postgres 26000/42P18/
        // 0A000, MySQL 1615) we retry exactly once on a fresh pool
        // connection. sqlx evicts the stale prepared-statement cache
        // on the failure so the second attempt re-prepares
        // automatically.
        let request_id_str = _in_flight.request_id().to_owned();

        // Multi-result-set procedures bypass `RowBatch` entirely
        // — the wire shape is `{"result_sets": [[...], [...]]}` and
        // can't be expressed as a flat `Vec<Value>` of rows. Apply
        // `max_rows` against the total row count and emit
        // `truncated: true` if the procedure produced more.
        if runtime.row_mode == RowMode::ResultSets {
            let fut =
                runtime
                    .driver
                    .execute_multi_result(&pool, &runtime.stmt, &bound, session_vars_ref);
            let mut sets = match timeout(
                runtime.timeout,
                with_heartbeat(
                    backend_name,
                    runtime.driver_kind,
                    runtime.progress_heartbeat,
                    fut,
                ),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    let be = BackendError::from(e);
                    let reason = refund_reason_for(&be);
                    try_emit_refund(runtime, backend_name, &args_value, reason);
                    return Err(be);
                }
                Err(_) => {
                    try_emit_refund(runtime, backend_name, &args_value, "timeout");
                    return Err(BackendError::Timeout {
                        timeout_ms: runtime.timeout.as_millis() as u64,
                    });
                }
            };
            let total: u64 = sets.iter().map(|s| s.len() as u64).sum();
            let truncated = total > runtime.max_rows;
            if truncated {
                // Distribute `max_rows` across sets in declaration
                // order: drain each set up to the remaining budget.
                // Sets past the cut-line keep their structural slot
                // but become empty arrays — preserves the procedure's
                // shape (a 3-set CALL stays a 3-set response) so
                // operators can index by position.
                let mut remaining = runtime.max_rows;
                for set in sets.iter_mut() {
                    let n = set.len() as u64;
                    if remaining >= n {
                        remaining -= n;
                    } else {
                        set.truncate(remaining as usize);
                        remaining = 0;
                    }
                }
            }
            let mut wrapper = serde_json::Map::new();
            let arr: Vec<Value> = sets.into_iter().map(Value::Array).collect();
            wrapper.insert("result_sets".into(), Value::Array(arr));
            wrapper.insert("truncated".into(), Value::Bool(truncated));
            let payload = Value::Object(wrapper);
            let bytes = serde_json::to_vec(&payload).map_err(|e| {
                try_emit_refund(runtime, backend_name, &args_value, "transport");
                BackendError::Transport {
                    message: format!("serialize response: {e}"),
                }
            })?;
            try_emit_charge(
                runtime,
                backend_name,
                &args_value,
                total,
                bytes.len() as u64,
            )?;
            return Ok(BackendResponse {
                payload: bytes,
                truncated,
            });
        }

        let batch = if runtime.row_mode == RowMode::AffectedRows {
            let mut last_err: Option<SqlError> = None;
            let mut batch_result: Option<RowBatch> = None;
            for attempt in 0..2u8 {
                let exec_ctx = driver::ExecCtx {
                    request_id: Some(&request_id_str),
                    in_flight: Some(self.in_flight.as_ref()),
                };
                let fut = runtime.driver.execute_affected_with_ctx(
                    &pool,
                    &runtime.stmt,
                    &bound,
                    session_vars_ref,
                    exec_ctx,
                );
                match timeout(
                    runtime.timeout,
                    with_heartbeat(
                        backend_name,
                        runtime.driver_kind,
                        runtime.progress_heartbeat,
                        fut,
                    ),
                )
                .await
                {
                    Ok(Ok(n)) => {
                        batch_result = Some(RowBatch {
                            columns: vec![],
                            rows: vec![],
                            rows_affected: Some(n),
                            truncated: false,
                            has_more: false,
                        });
                        break;
                    }
                    Ok(Err(e)) => {
                        if attempt == 0 && is_retryable_stale(&e) {
                            metrics::record_prepare_retry(backend_name, runtime.driver_kind);
                            tracing::info!(
                                backend = %backend_name,
                                driver = runtime.driver_kind.as_str(),
                                "sql: stale prepared statement — retrying once"
                            );
                            last_err = Some(e);
                            continue;
                        }
                        let be = BackendError::from(e);
                        let reason = refund_reason_for(&be);
                        try_emit_refund(runtime, backend_name, &args_value, reason);
                        return Err(be);
                    }
                    Err(_) => {
                        try_emit_refund(runtime, backend_name, &args_value, "timeout");
                        return Err(BackendError::Timeout {
                            timeout_ms: runtime.timeout.as_millis() as u64,
                        });
                    }
                }
            }
            match batch_result {
                Some(b) => b,
                None => {
                    let be = BackendError::from(last_err.expect("retry failed without error"));
                    let reason = refund_reason_for(&be);
                    try_emit_refund(runtime, backend_name, &args_value, reason);
                    return Err(be);
                }
            }
        } else {
            let mut last_err: Option<SqlError> = None;
            let mut batch_result: Option<RowBatch> = None;
            for attempt in 0..2u8 {
                let exec_ctx = driver::ExecCtx {
                    request_id: Some(&request_id_str),
                    in_flight: Some(self.in_flight.as_ref()),
                };
                let fut = runtime.driver.execute_with_ctx(
                    &pool,
                    &runtime.stmt,
                    &bound,
                    session_vars_ref,
                    exec_ctx,
                );
                match timeout(
                    runtime.timeout,
                    with_heartbeat(
                        backend_name,
                        runtime.driver_kind,
                        runtime.progress_heartbeat,
                        fut,
                    ),
                )
                .await
                {
                    Ok(Ok(b)) => {
                        batch_result = Some(b);
                        break;
                    }
                    Ok(Err(e)) => {
                        if attempt == 0 && is_retryable_stale(&e) {
                            metrics::record_prepare_retry(backend_name, runtime.driver_kind);
                            tracing::info!(
                                backend = %backend_name,
                                driver = runtime.driver_kind.as_str(),
                                "sql: stale prepared statement — retrying once"
                            );
                            last_err = Some(e);
                            continue;
                        }
                        let be = BackendError::from(e);
                        let reason = refund_reason_for(&be);
                        try_emit_refund(runtime, backend_name, &args_value, reason);
                        return Err(be);
                    }
                    Err(_) => {
                        try_emit_refund(runtime, backend_name, &args_value, "timeout");
                        return Err(BackendError::Timeout {
                            timeout_ms: runtime.timeout.as_millis() as u64,
                        });
                    }
                }
            }
            match batch_result {
                Some(b) => b,
                None => {
                    let be = BackendError::from(last_err.expect("retry failed without error"));
                    let reason = refund_reason_for(&be);
                    try_emit_refund(runtime, backend_name, &args_value, reason);
                    return Err(be);
                }
            }
        };

        // Capture row count before `shape_response` consumes the batch.
        // For `AffectedRows` the count is the driver's rows_affected;
        // for everything else it's the number of returned rows. This
        // is the value `cost::compute` amplifies for `per_row` charges.
        let row_count_for_cost: u64 = if runtime.row_mode == RowMode::AffectedRows {
            batch.rows_affected.unwrap_or(0)
        } else {
            batch.rows.len() as u64
        };
        let (mut payload, truncated) = shape_response(batch, runtime.row_mode, runtime.max_rows)?;

        // Cursor minting: only relevant when the binding is in
        // stream mode AND a stream runtime is configured (always
        // true via validate(), but checked defensively). We inspect
        // the last surviving row, extract values for each
        // cursor_columns entry, encode an HMAC-bound token, and
        // insert it as `next_cursor`. Empty result sets and rows
        // that don't carry the cursor columns produce a `null`
        // cursor — signals "no more pages".
        if runtime.row_mode == RowMode::Stream
            && let Some(stream_rt) = runtime.stream_rt.as_ref()
        {
            let next_cursor = mint_next_cursor(&payload, stream_rt, backend_name);
            if let Value::Object(obj) = &mut payload {
                obj.insert("next_cursor".into(), next_cursor);
            }
        }

        let bytes = serde_json::to_vec(&payload).map_err(|e| {
            try_emit_refund(runtime, backend_name, &args_value, "transport");
            BackendError::Transport {
                message: format!("serialize response: {e}"),
            }
        })?;

        // Record the per-call charge from the post-execution
        // facts (rows + payload bytes). Pre-flight `cost.compute`
        // refuses over-cap charges, so this either succeeds and
        // emits a metric / tracing event or aborts the response with
        // `InvalidSpec` — overcharging is worse than an extra
        // refused call. No-op when the binding has no `cost:`.
        try_emit_charge(
            runtime,
            backend_name,
            &args_value,
            row_count_for_cost,
            bytes.len() as u64,
        )?;

        // Cache write. Skipped on the early-return hit path
        // above (early `return` consumed `cache_key_opt`). Failures
        // are logged at debug level only — a flaky cache must never
        // fail the underlying SQL call.
        if let Some(key) = cache_key_opt
            && let Some(cache) = runtime.cache.as_ref()
        {
            let mut entry = Vec::with_capacity(CACHE_HEADER_LEN + bytes.len());
            entry.push(if truncated { 1u8 } else { 0u8 });
            entry.extend_from_slice(&bytes);
            let mut host_ctx = BackendInvocationContext::root(
                request.request_id.clone(),
                request.session_id.clone(),
                backend_name.to_owned(),
            );
            host_ctx.identity = request.identity.clone();
            let ttl = Duration::from_secs(cache.ttl_seconds);
            if let Err(e) = runtime
                .host
                .cache_put(&host_ctx, key, bytes::Bytes::from(entry), ttl)
                .await
            {
                debug!(?e, backend = %backend_name, "sql cache_put failed; ignoring");
            } else {
                metrics::record_cache_write(backend_name, runtime.driver_kind);
            }
        }

        Ok(BackendResponse {
            payload: bytes,
            truncated,
        })
    }

    /// Fire-and-wait dispatch: run the trigger once (if
    /// any), then poll the check query on `poll_interval_ms`,
    /// evaluating the CEL predicate against each check-row result.
    /// Returns the check row whose predicate matched, or a
    /// `BackendError::Timeout` when `timeout_ms` expires.
    ///
    /// The CEL predicate sees two variables:
    /// - `row` — object shape of the first row from the check
    ///   query (column name → JSON value). Empty result sets bind
    ///   `row = null` so predicates can handle "not yet in the
    ///   table" cleanly.
    /// - `arguments` — the caller's JSON arg object (same shape
    ///   the trigger / check placeholders bind from).
    async fn execute_await_loop(
        &self,
        backend_name: &str,
        request: BackendRequest,
        runtime: &ProfileRuntime,
    ) -> Result<BackendResponse, BackendError> {
        let await_rt = runtime
            .await_rt
            .as_ref()
            .expect("execute_await_loop called without await_rt");

        // Same in-flight accounting as the normal path. The guard
        // lives for the whole poll loop so metrics reflect
        // "request is blocked on a wait."
        let _in_flight = in_flight::InFlightGuard::register(
            Arc::clone(&self.in_flight),
            request.request_id.clone(),
            backend_name.to_owned(),
            runtime.driver_kind,
        );
        // Gauge of currently-active await loops, by driver.
        // The RAII guard decrements on every exit (match / timeout /
        // error / panic) so the gauge can never strand high.
        let _waits_guard = metrics::await_waits_guard(runtime.driver_kind);
        let wait_started = std::time::Instant::now();

        let mut args_value: Value = if request.payload.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&request.payload).map_err(|e| BackendError::InvalidSpec {
                message: format!("request payload is not valid JSON: {e}"),
            })?
        };
        if !runtime.param_exprs.is_empty() {
            param_exprs::evaluate_into(&mut args_value, runtime.param_exprs.as_slice())
                .map_err(BackendError::from)?;
        }

        // Fire the trigger once — its result is discarded; the
        // check loop owns the observable outcome.
        if let Some(trigger_stmt) = &await_rt.trigger_stmt {
            let trig_args = params::collect_bound_params(&args_value, &trigger_stmt.param_order)
                .map_err(BackendError::from)?;
            let trig_fut = runtime.driver.execute(
                &runtime.pool,
                trigger_stmt,
                &trig_args,
                &runtime.session_vars,
            );
            match timeout(runtime.timeout, trig_fut).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    let be = BackendError::from(e);
                    let reason = refund_reason_for(&be);
                    try_emit_refund(runtime, backend_name, &args_value, reason);
                    return Err(be);
                }
                Err(_) => {
                    try_emit_refund(runtime, backend_name, &args_value, "timeout");
                    return Err(BackendError::Timeout {
                        timeout_ms: runtime.timeout.as_millis() as u64,
                    });
                }
            }
        }

        let poll_every = Duration::from_millis(await_rt.cfg.poll_interval_ms);
        let deadline = std::time::Instant::now() + Duration::from_millis(await_rt.cfg.timeout_ms);
        let mut polls: u64 = 0;

        loop {
            let check_args =
                params::collect_bound_params(&args_value, &await_rt.check_stmt.param_order)
                    .map_err(BackendError::from)?;
            let check_fut = runtime.driver.execute(
                &runtime.pool,
                &await_rt.check_stmt,
                &check_args,
                &runtime.session_vars,
            );
            // Cap each individual check call at the same timeout as
            // the normal query path — if the DB is wedged we fail
            // the whole wait rather than pile up blocked tasks.
            let batch = timeout(runtime.timeout, check_fut)
                .await
                .map_err(|_| {
                    try_emit_refund(runtime, backend_name, &args_value, "timeout");
                    BackendError::Timeout {
                        timeout_ms: runtime.timeout.as_millis() as u64,
                    }
                })?
                .map_err(|e| {
                    let be = BackendError::from(e);
                    let reason = refund_reason_for(&be);
                    try_emit_refund(runtime, backend_name, &args_value, reason);
                    be
                })?;
            polls = polls.saturating_add(1);

            let row_value = batch.rows.first().cloned().unwrap_or(Value::Null);

            if evaluate_await_predicate(&await_rt.predicate, &row_value, &args_value) {
                // Match: return the row as the binding response.
                // Shape is consistent with `row_mode: single` —
                // the awaited row, or SQL `null` if the predicate
                // matched an empty result set (uncommon).
                metrics::record_await_wait(backend_name, runtime.driver_kind, "matched", polls);
                metrics::record_await_wake(backend_name, runtime.driver_kind, "matched");
                metrics::record_await_duration(
                    backend_name,
                    runtime.driver_kind,
                    "matched",
                    wait_started.elapsed(),
                );
                let bytes = serde_json::to_vec(&row_value).map_err(|e| {
                    try_emit_refund(runtime, backend_name, &args_value, "transport");
                    BackendError::Transport {
                        message: format!(
                            "await check row serialization (binding={backend_name}, \
                             driver={}, polls={polls}): {e}",
                            runtime.driver_kind.as_str()
                        ),
                    }
                })?;
                // The awaited row is the binding's logical
                // single result; charge per_row uses row_count=1
                // (row_value is null when the predicate matched an
                // empty result set, but we still bill the call).
                let row_count = if matches!(row_value, Value::Null) {
                    0
                } else {
                    1
                };
                try_emit_charge(
                    runtime,
                    backend_name,
                    &args_value,
                    row_count,
                    bytes.len() as u64,
                )?;
                return Ok(BackendResponse {
                    payload: bytes,
                    truncated: false,
                });
            }

            // Predicate didn't match — record a "spurious" wake so
            // operators can chart `rate(spurious) / rate(matched +
            // timeout)` to spot polls that fire faster than the
            // signal arrives.
            metrics::record_await_wake(backend_name, runtime.driver_kind, "spurious");

            // Deadline check: if we're past the budget, return
            // timeout. We check AFTER the current poll's eval so
            // a predicate that becomes true on the last tick
            // before expiry is still honored. The sleep below is
            // capped at `time_until_deadline` so we never over-wait.
            let now = std::time::Instant::now();
            if now >= deadline {
                metrics::record_await_wait(backend_name, runtime.driver_kind, "timeout", polls);
                metrics::record_await_wake(backend_name, runtime.driver_kind, "timeout");
                metrics::record_await_duration(
                    backend_name,
                    runtime.driver_kind,
                    "timeout",
                    wait_started.elapsed(),
                );
                try_emit_refund(runtime, backend_name, &args_value, "timeout");
                return Err(BackendError::Timeout {
                    timeout_ms: await_rt.cfg.timeout_ms,
                });
            }
            let sleep_for = poll_every.min(deadline.saturating_duration_since(now));
            // Race the poll-interval sleep against the
            // plugin's drain notify so a SIGTERM during a long await
            // (e.g. `poll_interval_ms: 5000` watching for an order
            // status change) bails immediately rather than ticking
            // out the full interval. Returns Timeout so callers see
            // the same error as the deadline path above.
            tokio::select! {
                _ = tokio::time::sleep(sleep_for) => {}
                _ = self.drain_notify.notified() => {
                    metrics::record_await_wait(backend_name, runtime.driver_kind, "timeout", polls);
                    metrics::record_await_wake(backend_name, runtime.driver_kind, "timeout");
                    metrics::record_await_duration(
                        backend_name,
                        runtime.driver_kind,
                        "timeout",
                        wait_started.elapsed(),
                    );
                    try_emit_refund(runtime, backend_name, &args_value, "timeout");
                    return Err(BackendError::Timeout {
                        timeout_ms: await_rt.cfg.timeout_ms,
                    });
                }
            }
        }
    }
}

/// Try to charge for one successful execution. No-op when the
/// binding has no `cost:` block. The amount is computed from the
/// per-call base × the unit-specific amplifier (rows for `per_row`,
/// payload bytes for `per_byte`). On failure (over-cap, non-finite,
/// CEL evaluation error) we surface `BackendError::InvalidSpec` —
/// dropping the response is preferable to over-billing per the
/// design in `cost.rs`.
fn try_emit_charge(
    runtime: &ProfileRuntime,
    backend_name: &str,
    args: &Value,
    row_count: u64,
    payload_bytes: u64,
) -> Result<(), BackendError> {
    if let Some(c) = runtime.cost.as_ref() {
        let amount = c
            .compute(args, row_count, payload_bytes)
            .map_err(BackendError::from)?;
        crate::cost::emit_charge(
            backend_name,
            runtime.driver_kind,
            c,
            amount,
            row_count,
            payload_bytes,
        );
    }
    Ok(())
}

/// Emit a refund accounting signal on a non-success terminal
/// outcome. No-op when the binding has no `cost:` block. The
/// `reason` label distinguishes cases that downstream billing
/// reconcilers care about (timeout / transport / invalid_spec).
fn try_emit_refund(
    runtime: &ProfileRuntime,
    backend_name: &str,
    args: &Value,
    reason: &'static str,
) {
    if let Some(c) = runtime.cost.as_ref() {
        crate::cost::emit_refund(backend_name, runtime.driver_kind, c, args, reason);
    }
}

/// Map a `BackendError` to the cost-refund reason label. Centralised
/// so every refund call site agrees on the taxonomy. The labels are
/// stable strings — Prometheus dashboards and audit reconcilers
/// match on them verbatim.
fn refund_reason_for(err: &BackendError) -> &'static str {
    match err {
        BackendError::Timeout { .. } => "timeout",
        BackendError::Transport { .. } => "transport",
        BackendError::InvalidSpec { .. } => "invalid_spec",
        BackendError::ProfileNotFound { .. } => "invalid_spec",
    }
}

/// Evaluate the compiled CEL predicate against a check row +
/// caller arguments. Non-boolean results coerce to `false` so a
/// malformed predicate can't claim a match.
fn evaluate_await_predicate(program: &cel::Program, row: &Value, arguments: &Value) -> bool {
    use cel::{Context as CelContext, Value as CelValue};
    let mut ctx = CelContext::default();
    ctx.add_variable_from_value("row", cel_value_from_json(row));
    ctx.add_variable_from_value("arguments", cel_value_from_json(arguments));
    match program.execute(&ctx) {
        Ok(CelValue::Bool(b)) => b,
        _ => false,
    }
}

/// Bare JSON → cel::Value coercion. Mirrors the plain mapping the
/// plugin uses elsewhere for CEL inputs; full type fidelity isn't
/// needed for predicate evaluation (the predicate typically just
/// tests string / int equality on a status column).
pub(crate) fn cel_value_from_json(v: &Value) -> cel::Value {
    use cel::{
        Value as CelValue,
        objects::{Key as CelKey, Map as CelMap},
    };
    match v {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                CelValue::UInt(u)
            } else if let Some(f) = n.as_f64() {
                CelValue::Float(f)
            } else {
                CelValue::Null
            }
        }
        Value::String(s) => CelValue::String(std::sync::Arc::new(s.clone())),
        Value::Array(arr) => CelValue::List(std::sync::Arc::new(
            arr.iter().map(cel_value_from_json).collect(),
        )),
        Value::Object(obj) => {
            let mut map: std::collections::HashMap<CelKey, CelValue> =
                std::collections::HashMap::with_capacity(obj.len());
            for (k, vv) in obj {
                map.insert(
                    CelKey::String(std::sync::Arc::new(k.clone())),
                    cel_value_from_json(vv),
                );
            }
            CelValue::Map(CelMap {
                map: std::sync::Arc::new(map),
            })
        }
    }
}

/// Run `fut` with a background heartbeat task.
///
/// When `heartbeat` is `Some(interval)`, a tokio task ticks every
/// `interval` and emits:
/// - a `tracing::info!` event at `target = "mcpg::sql::progress"`
/// - an increment of `mcpg_sql_progress_heartbeats_total`
///
/// The task is cancelled as soon as `fut` resolves, so zero heartbeats
/// fire for queries that complete faster than the first tick. When
/// `heartbeat` is `None`, the future is awaited unchanged — zero
/// overhead on the hot path.
async fn with_heartbeat<F, T>(
    binding: &str,
    driver: DriverKind,
    heartbeat: Option<Duration>,
    fut: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    let Some(interval) = heartbeat else {
        return fut.await;
    };
    let binding_owned = binding.to_owned();
    let hb_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately by default; we want the
        // *next* tick to be one interval out so short queries never
        // see a heartbeat.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            tracing::info!(
                target: "mcpg::sql::progress",
                backend = %binding_owned,
                driver = driver.as_str(),
                "sql progress heartbeat"
            );
            metrics::record_progress_heartbeat(&binding_owned, driver);
        }
    });
    let out = fut.await;
    hb_handle.abort();
    out
}

/// True iff the plugin should retry this [`SqlError`] once on a
/// fresh pool connection — specifically for stale-statement cache
/// drift after a concurrent DDL migration.
///
/// Matches only the `Execute` / `Prepare` variants that carry a
/// `sqlx::Error::Database` inner with the known stale SQLSTATE
/// codes. Pool timeouts, connect errors, and generic driver
/// failures propagate unretried.
fn is_retryable_stale(err: &SqlError) -> bool {
    match err {
        SqlError::Execute(inner) | SqlError::Prepare(inner) | SqlError::Driver(inner) => {
            crate::errors::is_stale_statement_error(inner)
        }
        _ => false,
    }
}

fn row_count_hint(payload: &Value) -> Option<u64> {
    match payload {
        Value::Array(rows) => Some(rows.len() as u64),
        Value::Object(m) => {
            if let Some(Value::Number(n)) = m.get("rows_affected") {
                n.as_u64()
            } else if let Some(Value::Array(contents)) = m.get("contents") {
                // `row_mode: resource_contents` → one content entry
                // per row; histogram tracks the row count, not the
                // wrapper.
                Some(contents.len() as u64)
            } else {
                Some(1) // `single` row_mode returns one object
            }
        }
        Value::Null => None,
        _ => None,
    }
}

/// Convert a list_query [`RowBatch`] into a [`ResourcePage`].
///
/// Reads `uri` (required) plus optional `name`, `description`,
/// `mime_type` columns on each row. The next-cursor is derived from
/// the last row's `cursor_column` value in keyset mode, or the
/// running offset + page length in offset mode. Rows that miss the
/// required `uri` are skipped and logged at warn — a misconfigured
/// list_query shouldn't take down the whole listing surface.
fn batch_to_resource_page(
    batch: driver::RowBatch,
    list_cfg: &crate::config::ListQueryConfig,
) -> ResourcePage {
    let row_count = batch.rows.len() as u64;
    let mut resources: Vec<ListedResource> = Vec::with_capacity(batch.rows.len());
    let mut last_cursor_value: Option<String> = None;

    for row in &batch.rows {
        let Value::Object(obj) = row else {
            warn!("list_query: non-object row skipped");
            continue;
        };
        let Some(uri) = obj.get("uri").and_then(|v| v.as_str()) else {
            warn!("list_query: row missing required 'uri' column; skipped");
            continue;
        };
        let listed = ListedResource {
            uri: uri.to_owned(),
            name: obj.get("name").and_then(|v| v.as_str()).map(str::to_owned),
            description: obj
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            mime_type: obj
                .get("mime_type")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        };
        resources.push(listed);
        if let Some(col) = list_cfg.cursor_column.as_deref()
            && let Some(v) = obj.get(col)
        {
            last_cursor_value = Some(cursor_value_to_string(v));
        }
    }

    // `next_cursor == None` signals the listing is exhausted. Rule:
    // fewer rows than page_size means the driver hit the tail.
    let next_cursor = if row_count < list_cfg.page_size {
        None
    } else {
        match list_cfg.mode {
            crate::config::ListQueryMode::Keyset => last_cursor_value,
            crate::config::ListQueryMode::Offset => {
                // Offset cursors are stringified `u64`s — the next
                // page's offset is (prior offset + rows returned).
                // The caller's cursor isn't threaded in here; we
                // return the row count on its own and expect the
                // host to compose. A more complete offset path
                // threads the prior offset through `run_list_query`,
                // but offset mode is scoped to small listings;
                // keyset is the recommended mode for anything else.
                Some(row_count.to_string())
            }
        }
    };

    ResourcePage {
        resources,
        next_cursor,
    }
}

/// Render a JSON value to an opaque cursor string. Keeps the format
/// stable for integers, floats, and strings — the values that appear
/// as cursor columns in practice (ids, timestamps, UUIDs).
fn cursor_value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Reshape a [`RowBatch`] per `row_mode` and enforce `max_rows`.
///
/// The returned JSON value is what the binding exposes to the tool
/// caller. The `bool` in the tuple is the `truncated` flag — true if
/// we dropped rows to stay under `max_rows`.
fn shape_response(
    batch: RowBatch,
    mode: RowMode,
    max_rows: u64,
) -> Result<(Value, bool), BackendError> {
    let truncated = (batch.rows.len() as u64) > max_rows;
    let mut rows = batch.rows;
    if truncated {
        rows.truncate(max_rows as usize);
    }
    match mode {
        RowMode::Single => {
            let row = rows.into_iter().next().unwrap_or(Value::Null);
            Ok((row, truncated))
        }
        RowMode::Many => Ok((Value::Array(rows), truncated)),
        RowMode::Scalar => {
            let row = rows.into_iter().next().unwrap_or(Value::Null);
            let scalar = match row {
                Value::Object(mut map) => {
                    // Pick the *first column* of the row for
                    // `scalar`. BTreeMap iteration would sort
                    // alphabetically, which isn't what callers expect;
                    // instead we take the first key in insertion order
                    // (serde_json::Map preserves that).
                    map.values_mut()
                        .next()
                        .map(std::mem::take)
                        .unwrap_or(Value::Null)
                }
                other => other,
            };
            Ok((scalar, truncated))
        }
        RowMode::AffectedRows => {
            let count = batch.rows_affected.unwrap_or(0);
            let mut m = BTreeMap::new();
            m.insert("rows_affected".to_string(), Value::Number(count.into()));
            Ok((serde_json::to_value(m).unwrap(), false))
        }
        RowMode::ResourceContents => {
            // Build the MCP resources/read contract from SELECT-ed
            // columns. Per-row required columns:
            //   uri:       string
            //   text:      string    ── mutually exclusive with blob
            //   blob:      string    ── base64 per gateway decoder
            //   mime_type: string?   ── optional, emitted as `mimeType`
            // Rows lacking `uri` or carrying both `text`+`blob` are
            // rejected — aligned with the gateway's decode_resource_result
            // contract so a malformed SQL response surfaces at the
            // plugin boundary rather than as an opaque decode error.
            let mut contents = Vec::with_capacity(rows.len());
            for (idx, row) in rows.into_iter().enumerate() {
                let obj = match row {
                    Value::Object(o) => o,
                    other => {
                        return Err(BackendError::Transport {
                            message: format!(
                                "resource_contents[{idx}] is not an object: {}",
                                json_type(&other)
                            ),
                        });
                    }
                };
                let uri = obj
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| BackendError::Transport {
                        message: format!("resource_contents[{idx}] missing required 'uri' column"),
                    })?
                    .to_owned();
                let has_text = obj.get("text").is_some_and(|v| !v.is_null());
                let has_blob = obj.get("blob").is_some_and(|v| !v.is_null());
                if has_text && has_blob {
                    return Err(BackendError::Transport {
                        message: format!(
                            "resource_contents[{idx}] cannot SELECT both 'text' and 'blob' — pick one per row"
                        ),
                    });
                }
                if !has_text && !has_blob {
                    return Err(BackendError::Transport {
                        message: format!(
                            "resource_contents[{idx}] must SELECT either 'text' or 'blob'"
                        ),
                    });
                }
                let mut entry = serde_json::Map::new();
                entry.insert("uri".into(), Value::String(uri));
                if let Some(mt) = obj.get("mime_type").and_then(|v| v.as_str()) {
                    entry.insert("mimeType".into(), Value::String(mt.to_owned()));
                }
                if has_text {
                    entry.insert("text".into(), obj["text"].clone());
                } else {
                    entry.insert("blob".into(), obj["blob"].clone());
                }
                contents.push(Value::Object(entry));
            }
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("contents".into(), Value::Array(contents));
            Ok((Value::Object(wrapper), truncated))
        }
        RowMode::Stream => {
            // Streaming shape: response carries `rows` +
            // `truncated`. The caller (`execute_inner_impl`) injects
            // `next_cursor` after this function returns, since
            // minting a cursor needs runtime state (signing key,
            // cursor_columns, binding name) that doesn't belong in
            // shape_response. When the caller sees `RowMode::Stream`
            // it computes the cursor from the last surviving row's
            // cursor_columns values; null cursor signals "no more
            // pages".
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("rows".into(), Value::Array(rows));
            wrapper.insert("truncated".into(), Value::Bool(truncated));
            Ok((Value::Object(wrapper), truncated))
        }
        RowMode::ResultSets => {
            // Dispatched by `execute_inner_impl` via
            // `execute_multi_result` and shaped inline there. This
            // arm is unreachable in practice (the caller returns
            // early for `RowMode::ResultSets`) but kept for match
            // exhaustiveness — and to fail loudly if a future change
            // accidentally routes a result_sets binding through the
            // single-batch path.
            Err(BackendError::InvalidSpec {
                message: "row_mode: result_sets dispatched through single-batch shape_response \
                          — this is a routing bug; result_sets must go through execute_multi_result"
                    .into(),
            })
        }
    }
}

/// Inject `_after_<col>` keyset values into the args map for the
/// upcoming query. On the first page the values come from
/// `stream.initial[col]` (or JSON null if not declared); on
/// continuation calls they come from a verified, decoded `_cursor`
/// token. The `_cursor` arg itself is consumed (removed) so it
/// can't bleed into operator-declared placeholders.
///
/// Caller-supplied `_after_<col>` values are always overwritten —
/// keyset positions are server-controlled. A caller forging
/// `_after_<col>` directly cannot bypass the cursor binding-name
/// check.
fn apply_stream_cursor(
    args: &mut Value,
    stream_rt: &StreamRuntime,
    backend_name: &str,
) -> Result<(), errors::SqlError> {
    let obj = match args {
        Value::Object(m) => m,
        // First-page calls may legitimately arrive with no args
        // (Value::Null). Promote to an empty object so we can
        // populate the keyset placeholders.
        Value::Null => {
            *args = Value::Object(serde_json::Map::new());
            match args {
                Value::Object(m) => m,
                _ => unreachable!(),
            }
        }
        _ => {
            return Err(errors::SqlError::InvalidSpec(
                "stream-mode args must be a JSON object (or null)".into(),
            ));
        }
    };

    // If the caller passed `_cursor`, decode + verify; on success
    // bind from the keyset, on failure return a clear error.
    let raw_cursor = obj.remove("_cursor");
    let keyset_values: Vec<Value> = match raw_cursor {
        Some(Value::String(token)) if !token.is_empty() => {
            let decoded =
                crate::stream::decode_cursor(&token, &stream_rt.key).ok_or_else(|| {
                    errors::SqlError::InvalidSpec(
                        "stream cursor: token failed verification (malformed, \
                     tampered, signed by a different gateway instance \
                     without shared signing_key, or for a different \
                     binding)"
                            .into(),
                    )
                })?;
            if decoded.binding != backend_name {
                return Err(errors::SqlError::InvalidSpec(format!(
                    "stream cursor: token was minted for binding `{}` but \
                     submitted to `{}` — bindings MUST match",
                    decoded.binding, backend_name
                )));
            }
            if decoded.keyset.len() != stream_rt.cfg.cursor_columns.len() {
                return Err(errors::SqlError::InvalidSpec(format!(
                    "stream cursor: token carries {} keyset values but binding \
                     declares {} cursor_columns — config drift between mint \
                     and consume",
                    decoded.keyset.len(),
                    stream_rt.cfg.cursor_columns.len(),
                )));
            }
            decoded.keyset
        }
        Some(Value::Null) | None => {
            // First page: source from operator-declared `initial`
            // (or null per column when not declared).
            stream_rt
                .cfg
                .cursor_columns
                .iter()
                .map(|col| {
                    stream_rt
                        .cfg
                        .initial
                        .get(col)
                        .cloned()
                        .unwrap_or(Value::Null)
                })
                .collect()
        }
        Some(other) => {
            return Err(errors::SqlError::InvalidSpec(format!(
                "stream cursor: `_cursor` must be a string token (or null/absent), \
                 got {}",
                json_type(&other)
            )));
        }
    };

    // Overwrite `_after_<col>` for each declared cursor column.
    // Caller-supplied values are clobbered — keyset positions are
    // server-controlled.
    for (col, val) in stream_rt.cfg.cursor_columns.iter().zip(keyset_values) {
        obj.insert(format!("_after_{col}"), val);
    }
    Ok(())
}

/// Mint the next cursor token from the shaped Stream-mode response.
/// Looks at the last row in `payload.rows` and pulls one value per
/// declared `cursor_columns`. Returns `Value::Null` when there's no
/// row to anchor (empty page → no more pages) or when the row is
/// missing one of the cursor columns (operator's SELECT list and
/// stream.cursor_columns disagree — surface as null rather than a
/// malformed cursor; a separate error path could be added if
/// operators want it caught).
fn mint_next_cursor(payload: &Value, stream_rt: &StreamRuntime, backend_name: &str) -> Value {
    let rows = match payload.get("rows").and_then(|r| r.as_array()) {
        Some(rows) if !rows.is_empty() => rows,
        _ => return Value::Null,
    };
    let last = match rows.last() {
        Some(Value::Object(o)) => o,
        _ => return Value::Null,
    };
    let mut keyset = Vec::with_capacity(stream_rt.cfg.cursor_columns.len());
    for col in &stream_rt.cfg.cursor_columns {
        match last.get(col) {
            Some(v) => keyset.push(v.clone()),
            None => {
                tracing::warn!(
                    backend = %backend_name,
                    cursor_column = %col,
                    "sql stream: last row missing cursor column — emitting null next_cursor"
                );
                return Value::Null;
            }
        }
    }
    let token = crate::stream::encode_cursor(
        &crate::stream::StreamCursorPayload {
            version: 1,
            binding: backend_name.to_owned(),
            profile: String::new(),
            keyset,
        },
        &stream_rt.key,
    );
    Value::String(token)
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_response_single_empty_rows_is_null() {
        let (v, t) = shape_response(RowBatch::default(), RowMode::Single, 100).unwrap();
        assert!(v.is_null());
        assert!(!t);
    }

    #[test]
    fn shape_response_many_truncates() {
        let batch = RowBatch {
            columns: vec!["id".into()],
            rows: vec![
                serde_json::json!({"id": 1}),
                serde_json::json!({"id": 2}),
                serde_json::json!({"id": 3}),
            ],
            rows_affected: None,
            truncated: false,
            has_more: false,
        };
        let (v, t) = shape_response(batch, RowMode::Many, 2).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert!(t);
    }

    #[test]
    fn shape_response_scalar_picks_first_column() {
        let batch = RowBatch {
            columns: vec!["count".into()],
            rows: vec![serde_json::json!({"count": 7})],
            rows_affected: None,
            truncated: false,
            has_more: false,
        };
        let (v, _) = shape_response(batch, RowMode::Scalar, 1).unwrap();
        assert_eq!(v, serde_json::json!(7));
    }

    #[test]
    fn shape_response_stream_wraps_rows_and_cursor() {
        let batch = RowBatch {
            columns: vec!["id".into()],
            rows: vec![serde_json::json!({"id": 1}), serde_json::json!({"id": 2})],
            rows_affected: None,
            truncated: false,
            has_more: false,
        };
        let (v, t) = shape_response(batch, RowMode::Stream, 10).unwrap();
        assert!(!t, "rows ≤ max_rows must not be flagged truncated");
        let o = v.as_object().expect("stream mode returns an object");
        assert_eq!(o["rows"].as_array().unwrap().len(), 2);
        // next_cursor is injected by the caller (execute_inner_impl)
        // post-shape, since cursor minting needs runtime state.
        // shape_response's Stream branch emits only rows + truncated.
        assert!(!o.contains_key("next_cursor"));
        assert_eq!(o["truncated"], serde_json::json!(false));
    }

    #[test]
    fn shape_response_stream_truncates_over_max() {
        let batch = RowBatch {
            columns: vec!["id".into()],
            rows: (0..5).map(|i| serde_json::json!({"id": i})).collect(),
            rows_affected: None,
            truncated: false,
            has_more: false,
        };
        let (v, t) = shape_response(batch, RowMode::Stream, 2).unwrap();
        assert!(t);
        let o = v.as_object().unwrap();
        assert_eq!(o["rows"].as_array().unwrap().len(), 2);
        assert_eq!(o["truncated"], serde_json::json!(true));
    }

    #[test]
    fn shape_response_affected_rows() {
        let batch = RowBatch {
            columns: vec![],
            rows: vec![],
            rows_affected: Some(3),
            truncated: false,
            has_more: false,
        };
        let (v, _) = shape_response(batch, RowMode::AffectedRows, 1).unwrap();
        assert_eq!(v, serde_json::json!({"rows_affected": 3}));
    }

    #[test]
    fn shape_response_resource_contents_wraps_rows() {
        // SELECT uri/text(/mime_type) → { "contents": [...] }.
        let batch = RowBatch {
            columns: vec![],
            rows: vec![
                serde_json::json!({
                    "uri": "sqldoc://readme",
                    "text": "hello",
                    "mime_type": "text/markdown"
                }),
                serde_json::json!({
                    "uri": "sqldoc://logo",
                    "blob": "iVBORw0KGg..."
                }),
            ],
            rows_affected: None,
            truncated: false,
            has_more: false,
        };
        let (v, _) = shape_response(batch, RowMode::ResourceContents, 100).unwrap();
        assert_eq!(v["contents"][0]["uri"], "sqldoc://readme");
        assert_eq!(v["contents"][0]["text"], "hello");
        assert_eq!(v["contents"][0]["mimeType"], "text/markdown");
        assert_eq!(v["contents"][1]["uri"], "sqldoc://logo");
        assert_eq!(v["contents"][1]["blob"], "iVBORw0KGg...");
    }

    #[test]
    fn shape_response_resource_contents_rejects_missing_uri() {
        let batch = RowBatch {
            rows: vec![serde_json::json!({"text": "orphan"})],
            ..RowBatch::default()
        };
        let err = shape_response(batch, RowMode::ResourceContents, 100).unwrap_err();
        assert!(
            matches!(err, BackendError::Transport { ref message } if message.contains("missing required 'uri'"))
        );
    }

    #[test]
    fn shape_response_resource_contents_rejects_both_text_and_blob() {
        let batch = RowBatch {
            rows: vec![serde_json::json!({
                "uri": "x",
                "text": "hi",
                "blob": "aGVsbG8="
            })],
            ..RowBatch::default()
        };
        let err = shape_response(batch, RowMode::ResourceContents, 100).unwrap_err();
        assert!(
            matches!(err, BackendError::Transport { ref message } if message.contains("cannot SELECT both"))
        );
    }

    #[test]
    fn shape_response_resource_contents_rejects_row_without_payload() {
        let batch = RowBatch {
            rows: vec![serde_json::json!({"uri": "x"})],
            ..RowBatch::default()
        };
        let err = shape_response(batch, RowMode::ResourceContents, 100).unwrap_err();
        assert!(
            matches!(err, BackendError::Transport { ref message } if message.contains("must SELECT either 'text' or 'blob'"))
        );
    }

    #[test]
    fn validate_named_params_allows_extras_in_config() {
        // Extra declared params are tolerated (they may be used by
        // `param_exprs`).
        assert!(
            validate_named_params_match_config(&["a".to_string()], &["a".into(), "b".into()])
                .is_ok()
        );
    }

    #[test]
    fn validate_named_params_errors_on_missing_declaration() {
        let err =
            validate_named_params_match_config(&["a".to_string(), "missing".into()], &["a".into()])
                .unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("missing")));
    }

    #[test]
    fn plugin_kind_is_sql() {
        let p = SqlBackendPlugin::new();
        assert_eq!(p.kind(), "sql");
    }

    #[test]
    fn plugin_reports_manifest_id() {
        let p = SqlBackendPlugin::new();
        assert_eq!(p.manifest().id, "dev.mcpg.backend.sql");
    }

    #[tokio::test]
    async fn audit_metadata_surfaces_driver_and_query_ref() {
        // Registered SQL bindings expose the underlying engine
        // and a stable query_ref to the gateway audit lane. The
        // gateway merges this map into `mcpg.backend.executed` event
        // details before emit, so `db.driver=sqlite` filters land
        // without inspecting the resource URI.
        let p = SqlBackendPlugin::new();
        let spec = serde_json::json!({
            "driver": "sqlite",
            "url": "sqlite::memory:",
            "query": { "sql": "SELECT 1", "row_mode": "scalar" }
        });
        p.register_profile("ping", &spec, mcpg_plugin_protocol::noop_backend_host())
            .await
            .unwrap();

        let meta = p.audit_metadata("ping");
        assert_eq!(
            meta.get("db.driver").and_then(|v| v.as_str()),
            Some("sqlite")
        );
        assert_eq!(
            meta.get("db.query_ref").and_then(|v| v.as_str()),
            Some("ping"),
            "query_ref should be the binding name"
        );
    }

    #[tokio::test]
    async fn execute_transaction_runs_group_and_shapes_results() {
        // v35: a sql_tx group runs every nested step in one tx on a
        // pinned connection, shaping per row_mode. CREATE + INSERT +
        // SELECT share the single tx connection (sqlite::memory: is
        // per-connection, so the table is visible to later steps).
        let p = SqlBackendPlugin::new();
        let spec = serde_json::json!({
            "driver": "sqlite",
            "url": "sqlite::memory:",
            "query": { "sql": "SELECT 1", "row_mode": "scalar" }
        });
        p.register_profile("txdb", &spec, mcpg_plugin_protocol::noop_backend_host())
            .await
            .unwrap();

        let tx_group = serde_json::json!({
            "steps": [
                { "id": "create", "sql": "CREATE TABLE t (n INTEGER)", "row_mode": "affected_rows" },
                { "id": "ins", "sql": "INSERT INTO t (n) VALUES (:n)", "params": ["n"], "row_mode": "affected_rows" },
                { "id": "cnt", "sql": "SELECT COUNT(*) AS c FROM t", "row_mode": "scalar" }
            ],
            "step_input": { "n": 42 }
        });
        let out = p.execute_transaction("txdb", &tx_group).await.unwrap();
        let steps = out
            .get("steps")
            .and_then(|v| v.as_object())
            .expect("steps map");
        assert_eq!(steps["ins"]["rows_affected"].as_u64(), Some(1));
        assert_eq!(
            steps["cnt"].as_u64(),
            Some(1),
            "scalar count of inserted rows"
        );
    }

    #[tokio::test]
    async fn execute_transaction_errors_on_bad_step_and_rolls_back() {
        // A failing nested step aborts the whole group: execute_transaction
        // returns the error (with the nested id) and rolls back (best
        // effort). No partial commit.
        let p = SqlBackendPlugin::new();
        let spec = serde_json::json!({
            "driver": "sqlite",
            "url": "sqlite::memory:",
            "query": { "sql": "SELECT 1", "row_mode": "scalar" }
        });
        p.register_profile("txdb", &spec, mcpg_plugin_protocol::noop_backend_host())
            .await
            .unwrap();

        let tx_group = serde_json::json!({
            "steps": [
                { "id": "create", "sql": "CREATE TABLE t (n INTEGER)", "row_mode": "affected_rows" },
                { "id": "boom", "sql": "INSERT INTO no_such_table (n) VALUES (1)", "row_mode": "affected_rows" }
            ],
            "step_input": {}
        });
        let err = p.execute_transaction("txdb", &tx_group).await.unwrap_err();
        match err {
            BackendError::Transport { message } => {
                assert!(
                    message.contains("boom"),
                    "error names the failing step: {message}"
                );
            }
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_transaction_unknown_backend_is_profile_not_found() {
        let p = SqlBackendPlugin::new();
        let err = p
            .execute_transaction(
                "nope",
                &serde_json::json!({ "steps": [], "step_input": {} }),
            )
            .await
            .unwrap_err();
        // begin_transaction maps ProfileNotFound through From<SqlError>.
        assert!(
            matches!(err, BackendError::ProfileNotFound { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn audit_metadata_for_unknown_binding_is_empty() {
        // Defensive: audit emission may race with profile teardown
        // — return an empty map rather than synthesizing fields for
        // a binding the registry no longer knows.
        let p = SqlBackendPlugin::new();
        let meta = p.audit_metadata("never-registered");
        assert!(meta.is_empty());
    }

    #[tokio::test]
    async fn cancel_request_unknown_id_returns_profile_not_found() {
        // Cancel targets an in-flight registry entry; a
        // missing entry is ProfileNotFound, never a panic.
        let p = SqlBackendPlugin::new();
        let err = p.cancel_request("does-not-exist").await.unwrap_err();
        assert!(matches!(err, SqlError::ProfileNotFound(ref id) if id == "does-not-exist"));
    }

    #[test]
    fn is_retryable_stale_only_fires_for_non_db_errors_false() {
        // The helper must return false for every non-database
        // error — pool timeouts, connect errors, invalid-spec, etc.
        // Only database errors carrying a stale SQLSTATE are
        // retryable, and constructing sqlx::Error::Database requires
        // live driver output, so the live-DB assertion lives in the
        // integration tests.
        assert!(!is_retryable_stale(&SqlError::PoolTimeout(1000)));
        assert!(!is_retryable_stale(&SqlError::Timeout(5000)));
        assert!(!is_retryable_stale(&SqlError::InvalidSpec("bad".into())));
        assert!(!is_retryable_stale(&SqlError::ProfileNotFound("x".into())));
        assert!(!is_retryable_stale(&SqlError::Serialize("e".into())));
        // PoolTimedOut wrapped inside Execute isn't stale either.
        assert!(!is_retryable_stale(&SqlError::Execute(
            sqlx::Error::PoolTimedOut
        )));
    }

    // ----------------------------------------------------------------
    // Progress heartbeat
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn with_heartbeat_disabled_returns_future_unchanged() {
        let out = with_heartbeat("demo", DriverKind::Sqlite, None, async { 42_u32 }).await;
        assert_eq!(out, 42);
    }

    #[tokio::test]
    async fn with_heartbeat_enabled_still_returns_future_output() {
        // The heartbeat task must not perturb the future's return value
        // regardless of how often it ticks.
        let out = with_heartbeat(
            "demo",
            DriverKind::Sqlite,
            Some(Duration::from_millis(50)),
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                "done"
            },
        )
        .await;
        assert_eq!(out, "done");
    }

    #[tokio::test]
    async fn with_heartbeat_does_not_hang_after_future_completes() {
        // Defensive: the heartbeat task must be aborted so the outer
        // future resolves promptly — no leaked tokio tasks.
        let t0 = std::time::Instant::now();
        let _ = with_heartbeat(
            "demo",
            DriverKind::Sqlite,
            Some(Duration::from_millis(100)),
            async { 1 },
        )
        .await;
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "with_heartbeat didn't return promptly: {:?}",
            t0.elapsed()
        );
    }

    // ---- list_query row → ResourcePage projection -------------------

    fn list_cfg_keyset() -> crate::config::ListQueryConfig {
        crate::config::ListQueryConfig {
            sql: "SELECT uri, id FROM docs".into(),
            mode: crate::config::ListQueryMode::Keyset,
            cursor_column: Some("id".into()),
            page_size: 2,
        }
    }

    #[test]
    fn batch_to_resource_page_emits_full_page_with_cursor() {
        let batch = driver::RowBatch {
            columns: vec!["uri".into(), "id".into()],
            rows: vec![
                serde_json::json!({"uri": "mem://1", "id": 1}),
                serde_json::json!({"uri": "mem://2", "id": 2}),
            ],
            ..Default::default()
        };
        let page = batch_to_resource_page(batch, &list_cfg_keyset());
        assert_eq!(page.resources.len(), 2);
        assert_eq!(page.resources[0].uri, "mem://1");
        assert_eq!(page.next_cursor.as_deref(), Some("2"));
    }

    #[test]
    fn batch_to_resource_page_short_page_exhausts_cursor() {
        let batch = driver::RowBatch {
            columns: vec!["uri".into(), "id".into()],
            rows: vec![serde_json::json!({"uri": "mem://1", "id": 1})],
            ..Default::default()
        };
        let page = batch_to_resource_page(batch, &list_cfg_keyset());
        assert_eq!(page.resources.len(), 1);
        assert!(page.next_cursor.is_none(), "short page must exhaust cursor");
    }

    #[test]
    fn batch_to_resource_page_skips_rows_without_uri() {
        let batch = driver::RowBatch {
            columns: vec!["uri".into(), "id".into()],
            rows: vec![
                serde_json::json!({"id": 1}),
                serde_json::json!({"uri": "mem://2", "id": 2}),
            ],
            ..Default::default()
        };
        let page = batch_to_resource_page(batch, &list_cfg_keyset());
        assert_eq!(page.resources.len(), 1);
        assert_eq!(page.resources[0].uri, "mem://2");
    }

    #[test]
    fn batch_to_resource_page_reads_optional_columns() {
        let batch = driver::RowBatch {
            columns: vec![
                "uri".into(),
                "name".into(),
                "description".into(),
                "mime_type".into(),
                "id".into(),
            ],
            rows: vec![serde_json::json!({
                "uri": "mem://1",
                "name": "first",
                "description": "a doc",
                "mime_type": "text/plain",
                "id": 1,
            })],
            ..Default::default()
        };
        let mut cfg = list_cfg_keyset();
        cfg.page_size = 1;
        let page = batch_to_resource_page(batch, &cfg);
        let r = &page.resources[0];
        assert_eq!(r.name.as_deref(), Some("first"));
        assert_eq!(r.description.as_deref(), Some("a doc"));
        assert_eq!(r.mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn cursor_value_to_string_handles_common_types() {
        assert_eq!(cursor_value_to_string(&serde_json::json!(42)), "42");
        assert_eq!(cursor_value_to_string(&serde_json::json!("abc")), "abc");
        assert_eq!(cursor_value_to_string(&serde_json::json!(null)), "");
    }

    // ------------------------------------------------------------------
    // stream — apply_stream_cursor / mint_next_cursor unit tests
    // ------------------------------------------------------------------

    fn rt(cols: &[&str], initial: serde_json::Map<String, Value>) -> StreamRuntime {
        StreamRuntime {
            cfg: crate::stream::StreamConfig {
                cursor_columns: cols.iter().map(|s| (*s).into()).collect(),
                initial,
                signing_key: None,
            },
            key: crate::stream::CursorSigningKey::from_bytes(b"unit-test-key"),
        }
    }

    #[test]
    fn apply_stream_cursor_first_page_uses_initial() {
        let mut initial = serde_json::Map::new();
        initial.insert("id".into(), serde_json::json!(0));
        let stream_rt = rt(&["id"], initial);
        let mut args = serde_json::json!({"max_rows": 100});

        apply_stream_cursor(&mut args, &stream_rt, "users.list").unwrap();
        let obj = args.as_object().unwrap();
        assert_eq!(obj["_after_id"], serde_json::json!(0));
        assert_eq!(obj["max_rows"], serde_json::json!(100));
    }

    #[test]
    fn apply_stream_cursor_first_page_with_no_initial_is_null() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let mut args = serde_json::json!({});

        apply_stream_cursor(&mut args, &stream_rt, "x").unwrap();
        assert_eq!(args["_after_id"], serde_json::json!(null));
    }

    #[test]
    fn apply_stream_cursor_continuation_decodes_token() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let token = crate::stream::encode_cursor(
            &crate::stream::StreamCursorPayload {
                version: 1,
                binding: "users.list".into(),
                profile: String::new(),
                keyset: vec![serde_json::json!(42)],
            },
            &stream_rt.key,
        );
        let mut args = serde_json::json!({"_cursor": token, "limit": 10});

        apply_stream_cursor(&mut args, &stream_rt, "users.list").unwrap();
        let obj = args.as_object().unwrap();
        assert_eq!(obj["_after_id"], serde_json::json!(42));
        // _cursor consumed, not visible to operator placeholders.
        assert!(!obj.contains_key("_cursor"));
    }

    #[test]
    fn apply_stream_cursor_rejects_token_for_other_binding() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let token = crate::stream::encode_cursor(
            &crate::stream::StreamCursorPayload {
                version: 1,
                binding: "other.binding".into(),
                profile: String::new(),
                keyset: vec![serde_json::json!(42)],
            },
            &stream_rt.key,
        );
        let mut args = serde_json::json!({"_cursor": token});

        let err = apply_stream_cursor(&mut args, &stream_rt, "users.list").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("minted for binding"), "got: {msg}");
    }

    #[test]
    fn apply_stream_cursor_rejects_keyset_arity_mismatch() {
        // Token carries 1 keyset value but binding expects 2 (composite key).
        let stream_rt = rt(&["created_at", "id"], serde_json::Map::new());
        let token = crate::stream::encode_cursor(
            &crate::stream::StreamCursorPayload {
                version: 1,
                binding: "users.list".into(),
                profile: String::new(),
                keyset: vec![serde_json::json!(42)],
            },
            &stream_rt.key,
        );
        let mut args = serde_json::json!({"_cursor": token});
        let err = apply_stream_cursor(&mut args, &stream_rt, "users.list").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("config drift"), "got: {msg}");
    }

    #[test]
    fn apply_stream_cursor_rejects_malformed_token() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let mut args = serde_json::json!({"_cursor": "garbage"});
        let err = apply_stream_cursor(&mut args, &stream_rt, "users.list").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("failed verification"), "got: {msg}");
    }

    #[test]
    fn apply_stream_cursor_overrides_caller_supplied_after() {
        // Caller cannot inject `_after_<col>` directly — server-
        // controlled. Plugin overwrites silently.
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let mut args = serde_json::json!({"_after_id": 999});
        apply_stream_cursor(&mut args, &stream_rt, "x").unwrap();
        // First-page initial wins (null when no initial declared).
        assert_eq!(args["_after_id"], serde_json::json!(null));
    }

    #[test]
    fn apply_stream_cursor_promotes_null_args_to_object() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let mut args = Value::Null;
        apply_stream_cursor(&mut args, &stream_rt, "x").unwrap();
        assert!(args.is_object());
        assert_eq!(args["_after_id"], serde_json::json!(null));
    }

    #[test]
    fn mint_next_cursor_emits_token_for_last_row() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let payload = serde_json::json!({
            "rows": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}],
            "truncated": false
        });
        let cursor = mint_next_cursor(&payload, &stream_rt, "users.list");
        let token = cursor.as_str().expect("cursor is a string");
        let decoded = crate::stream::decode_cursor(token, &stream_rt.key).unwrap();
        assert_eq!(decoded.binding, "users.list");
        assert_eq!(decoded.keyset, vec![serde_json::json!(2)]);
    }

    #[test]
    fn mint_next_cursor_emits_null_for_empty_rows() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let payload = serde_json::json!({"rows": [], "truncated": false});
        assert!(mint_next_cursor(&payload, &stream_rt, "x").is_null());
    }

    #[test]
    fn mint_next_cursor_emits_null_when_row_missing_cursor_column() {
        let stream_rt = rt(&["id"], serde_json::Map::new());
        let payload = serde_json::json!({
            "rows": [{"name": "no-id-here"}],
            "truncated": false
        });
        assert!(mint_next_cursor(&payload, &stream_rt, "x").is_null());
    }

    #[test]
    fn mint_next_cursor_handles_composite_key() {
        let stream_rt = rt(&["created_at", "id"], serde_json::Map::new());
        let payload = serde_json::json!({
            "rows": [{"created_at": "2026-05-08", "id": 7, "name": "row7"}],
            "truncated": true
        });
        let cursor = mint_next_cursor(&payload, &stream_rt, "events.list");
        let token = cursor.as_str().unwrap();
        let decoded = crate::stream::decode_cursor(token, &stream_rt.key).unwrap();
        assert_eq!(
            decoded.keyset,
            vec![serde_json::json!("2026-05-08"), serde_json::json!(7)]
        );
    }

    #[test]
    fn stream_cursor_full_round_trip_first_to_continuation() {
        // End-to-end: page 1 mint → caller submits as _cursor → plugin
        // decodes → binds same id back to _after_id. Closes the loop.
        let mut initial = serde_json::Map::new();
        initial.insert("id".into(), serde_json::json!(0));
        let stream_rt = rt(&["id"], initial);

        // First page: caller passes nothing relating to streaming.
        let mut page_one_args = serde_json::json!({});
        apply_stream_cursor(&mut page_one_args, &stream_rt, "items").unwrap();
        assert_eq!(page_one_args["_after_id"], serde_json::json!(0));

        // Server returns rows; plugin mints next cursor.
        let page_one_payload = serde_json::json!({
            "rows": [{"id": 17, "name": "x"}, {"id": 23, "name": "y"}],
            "truncated": false
        });
        let cursor = mint_next_cursor(&page_one_payload, &stream_rt, "items");

        // Caller submits cursor on page 2. Plugin decodes + binds.
        let mut page_two_args = serde_json::json!({"_cursor": cursor});
        apply_stream_cursor(&mut page_two_args, &stream_rt, "items").unwrap();
        assert_eq!(page_two_args["_after_id"], serde_json::json!(23));
    }
}
