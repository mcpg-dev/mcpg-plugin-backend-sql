//! Response cache for read-only SQL bindings.
//!
//! The cache key is composed as:
//!
//! ```text
//! blake3( binding || \0 || query_ref || \0 || canonical_params || \0 || session_vars_signature )
//! ```
//!
//! - `binding` — operator-declared binding name (already the
//!   audit-event `db.query_ref`). Distinct bindings never collide.
//! - `query_ref` — a stable hash of the SQL body itself. Including it
//!   means a hot-reload that swaps the SQL while keeping the same
//!   binding name (e.g. fixing a typo) does NOT serve stale entries
//!   composed against the old query.
//! - `canonical_params` — JSON-canonicalized bound parameters
//!   (object keys sorted, no whitespace). The parameter map is the
//!   only dynamic input the engine sends to the driver.
//! - `session_vars_signature` — sorted `key=value` pairs of the
//!   binding's `session_vars`. Different identity-bound contexts
//!   never share entries even if the rest of the inputs match.
//!
//! Hashing happens up front and the gateway-side cache treats the
//! returned hash as a content-addressed lookup; nothing inspects
//! the structure of the hash.
//!
//! The host's per-binding cache routing (`cache_for_call(ctx)`)
//! means each SQL binding either has its own
//! `ResponseCache` instance (operator declared `cache: { kind: …, … }`
//! on the gateway-side `BackendConfig`) or falls back to the gateway-
//! wide default. SQL binding-side `cache.enabled: true` is the opt-in
//! that says "for this profile, attempt `cache_get` / `cache_put`."
//! With no backend the calls are no-ops and the binding still works.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, info, warn};

use crate::driver::{PoolHandle, SqlDriver};
use crate::params::{BoundParam, PreparedStmt};
use crate::session::SessionVars;

/// Compose the BLAKE3 cache key for one SQL call.
///
/// `version` is the binding's current cache-invalidation generation.
/// Mixing it into the key means a version bump makes every
/// previously-stored entry naturally miss in one atomic step. When
/// the binding has no invalidator wired the caller passes `0` and
/// the version contributes a stable byte pattern.
pub(crate) fn build_cache_key(
    backend_name: &str,
    sql_text: &str,
    bound_params: &[BoundParam],
    session_vars: &SessionVars,
    version: u64,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"sql\0");
    h.update(backend_name.as_bytes());
    h.update(b"\0");
    h.update(sql_text.as_bytes());
    h.update(b"\0");
    write_canonical_params(&mut h, bound_params);
    h.update(b"\0");
    write_session_vars(&mut h, &session_vars.values);
    h.update(b"\0");
    h.update(&version.to_le_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// Cache-invalidation runtime state.
///
/// Holds the version stamp + a `DropGuard` that cancels the watcher
/// task when the last reference to the invalidator drops. Cloning
/// the surrounding `ProfileRuntime` clones the `Arc<CacheInvalidator>`
/// so concurrent executes hold the watcher alive past hot-reload;
/// the watcher tears down once all clones (including the in-flight
/// ones) drop.
pub(crate) struct CacheInvalidator {
    version: AtomicU64,
    /// Cancels the spawned watch task on drop.
    _cancel_guard: DropGuard,
}

impl CacheInvalidator {
    /// Read the current version stamp. Used by cache-key composition.
    /// Acquire ordering ensures callers observe a bumped version
    /// no later than the watcher's call site.
    pub(crate) fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Bump the version. Only called by the watch loop when its
    /// tracking cursor changes.
    fn bump(&self) -> u64 {
        // `fetch_add` returns the *prior* value; +1 is the new one.
        self.version.fetch_add(1, Ordering::AcqRel) + 1
    }
}

/// Spawn the invalidation watcher. Returns an `Arc` whose drop
/// cancels the task. The caller stores it on `ProfileRuntime`.
///
/// The polling interval is enforced at config-validate time
/// (≥ 100 ms). The first poll establishes the baseline and does
/// not bump the version — only subsequent polls whose cursor
/// differs from the baseline trigger a bump.
pub(crate) fn spawn_invalidator(
    backend_name: String,
    driver: Arc<dyn SqlDriver>,
    pool: PoolHandle,
    stmt: PreparedStmt,
    session_vars: SessionVars,
    interval: Duration,
) -> Arc<CacheInvalidator> {
    let token = CancellationToken::new();
    let invalidator = Arc::new(CacheInvalidator {
        version: AtomicU64::new(0),
        _cancel_guard: token.clone().drop_guard(),
    });

    let task_invalidator = Arc::clone(&invalidator);
    tokio::spawn(invalidation_loop(
        backend_name,
        driver,
        pool,
        stmt,
        session_vars,
        interval,
        token,
        task_invalidator,
    ));

    invalidator
}

/// Background poll loop. Mirrors the design of
/// [`crate::watch::poll_loop`]: at every interval, run the
/// tracking query, extract the first scalar of the first row, and
/// compare with the previous value. On change, bump the version
/// stamp. Errors are logged at warn level and the loop continues —
/// transient connectivity issues must not strand the watcher.
#[allow(clippy::too_many_arguments)]
async fn invalidation_loop(
    backend_name: String,
    driver: Arc<dyn SqlDriver>,
    pool: PoolHandle,
    stmt: PreparedStmt,
    session_vars: SessionVars,
    interval: Duration,
    cancel: CancellationToken,
    invalidator: Arc<CacheInvalidator>,
) {
    info!(
        backend = %backend_name,
        driver = stmt.driver.as_str(),
        interval_ms = interval.as_millis() as u64,
        "sql cache invalidator: started"
    );

    let mut last_cursor: Option<Value> = None;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(backend = %backend_name, "sql cache invalidator: cancelled");
                return;
            }
            _ = ticker.tick() => {
                match driver.execute(&pool, &stmt, &[], &session_vars).await {
                    Ok(batch) => {
                        let cursor = first_scalar(&batch.rows);
                        if cursor != last_cursor {
                            if last_cursor.is_some() {
                                let new_version = invalidator.bump();
                                debug!(
                                    backend = %backend_name,
                                    version = new_version,
                                    "sql cache invalidator: cursor changed; version bumped"
                                );
                            }
                            last_cursor = cursor;
                        }
                    }
                    Err(e) => {
                        warn!(
                            backend = %backend_name,
                            error = %e,
                            "sql cache invalidator: tracking poll failed (continuing)"
                        );
                    }
                }
            }
        }
    }
}

/// First-column-of-first-row scalar, with rows as either `Object`
/// (column-named) or scalar `Value`s — same shape `crate::watch::watch`
/// produces. Empty batches map to `None` (a real cursor swap from
/// `None` → `Some(_)` later does *not* count as a change because
/// the baseline is established silently).
fn first_scalar(rows: &[Value]) -> Option<Value> {
    let first = rows.first()?;
    match first {
        Value::Object(map) => map.values().next().cloned(),
        other => Some(other.clone()),
    }
}

/// Hash bound params in declared order. `BoundParam` already preserves
/// the engine-declared parameter order so two calls with the same
/// values produce the same digest.
fn write_canonical_params(h: &mut blake3::Hasher, params: &[BoundParam]) {
    for (i, p) in params.iter().enumerate() {
        h.update(&(i as u32).to_le_bytes());
        h.update(p.name.as_bytes());
        h.update(b"=");
        write_value(h, &p.value);
        h.update(b";");
    }
}

/// Hash session vars in sorted-key order. `BTreeMap` already keeps
/// the iteration order canonical, so a JSON-shaped operator-supplied
/// order can't change the key.
fn write_session_vars(h: &mut blake3::Hasher, vars: &BTreeMap<String, String>) {
    for (k, v) in vars.iter() {
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(v.as_bytes());
        h.update(b";");
    }
}

/// Canonicalize a JSON value into the hasher. Object keys are
/// sorted; arrays preserve order. This is *just* enough
/// canonicalization for the cache-key contract — full RFC 8785 is
/// overkill given our parameter values come straight from a
/// JSON-RPC arg map.
fn write_value(h: &mut blake3::Hasher, v: &Value) {
    match v {
        Value::Null => h.update(b"n").finalize_hint(),
        Value::Bool(true) => h.update(b"t").finalize_hint(),
        Value::Bool(false) => h.update(b"f").finalize_hint(),
        Value::Number(n) => {
            h.update(b"#");
            h.update(n.to_string().as_bytes()).finalize_hint()
        }
        Value::String(s) => {
            h.update(b"\"");
            h.update(s.as_bytes());
            h.update(b"\"").finalize_hint()
        }
        Value::Array(arr) => {
            h.update(b"[");
            for (i, item) in arr.iter().enumerate() {
                h.update(&(i as u32).to_le_bytes());
                write_value(h, item);
            }
            h.update(b"]").finalize_hint()
        }
        Value::Object(obj) => {
            h.update(b"{");
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for k in keys {
                h.update(k.as_bytes());
                h.update(b":");
                write_value(h, &obj[k]);
                h.update(b";");
            }
            h.update(b"}").finalize_hint()
        }
    };
}

trait FinalizeHint {
    fn finalize_hint(&mut self);
}

impl FinalizeHint for blake3::Hasher {
    fn finalize_hint(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(name: &str, value: Value) -> BoundParam {
        BoundParam {
            name: name.to_owned(),
            value,
        }
    }

    fn empty_vars() -> SessionVars {
        SessionVars::default()
    }

    fn vars_with(items: &[(&str, &str)]) -> SessionVars {
        let mut m = BTreeMap::new();
        for (k, v) in items {
            m.insert((*k).to_owned(), (*v).to_owned());
        }
        SessionVars::from_map(m)
    }

    #[test]
    fn same_inputs_same_key() {
        let a = build_cache_key(
            "list_users",
            "SELECT * FROM users WHERE org = :org",
            &[p("org", json!("acme"))],
            &empty_vars(),
            0,
        );
        let b = build_cache_key(
            "list_users",
            "SELECT * FROM users WHERE org = :org",
            &[p("org", json!("acme"))],
            &empty_vars(),
            0,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn different_binding_names_diverge() {
        let a = build_cache_key("a", "SQL", &[p("k", json!(1))], &empty_vars(), 0);
        let b = build_cache_key("b", "SQL", &[p("k", json!(1))], &empty_vars(), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_sql_text_diverges() {
        let a = build_cache_key("x", "SELECT 1", &[], &empty_vars(), 0);
        let b = build_cache_key("x", "SELECT 2", &[], &empty_vars(), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_param_values_diverge() {
        let a = build_cache_key("x", "SQL", &[p("k", json!(1))], &empty_vars(), 0);
        let b = build_cache_key("x", "SQL", &[p("k", json!(2))], &empty_vars(), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_session_vars_diverge() {
        let v1 = vars_with(&[("tenant", "alpha")]);
        let v2 = vars_with(&[("tenant", "bravo")]);
        let a = build_cache_key("x", "SQL", &[], &v1, 0);
        let b = build_cache_key("x", "SQL", &[], &v2, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn nested_object_param_canonical_under_key_reorder() {
        // Two `Value::Object` payloads with different key order must
        // hash equally — operators receive the same args via
        // serde_json::Value where Map preserves insertion order, so a
        // reordered JSON-RPC payload should not bust the cache.
        let mut obj1 = serde_json::Map::new();
        obj1.insert("a".into(), json!(1));
        obj1.insert("b".into(), json!(2));
        let mut obj2 = serde_json::Map::new();
        obj2.insert("b".into(), json!(2));
        obj2.insert("a".into(), json!(1));
        let a = build_cache_key("x", "SQL", &[p("o", Value::Object(obj1))], &empty_vars(), 0);
        let b = build_cache_key("x", "SQL", &[p("o", Value::Object(obj2))], &empty_vars(), 0);
        assert_eq!(a, b);
    }

    #[test]
    fn version_bump_changes_key() {
        // Incrementing the version stamp must produce a
        // different key for otherwise-identical inputs. This is the
        // entire point of the version-stamp invalidation strategy.
        let a = build_cache_key("x", "SQL", &[p("k", json!(1))], &empty_vars(), 0);
        let b = build_cache_key("x", "SQL", &[p("k", json!(1))], &empty_vars(), 1);
        assert_ne!(a, b);
    }
}
