//! Pool wiring — delegates to the driver with the validated config.
//!
//! Two layers:
//!
//! * [`build_pool`] is the original single-pool entry point used by
//!   the static-credential path. The connection URL is the sole
//!   credential surface; operators route secret material through the
//!   gateway-level string interpolator (`${env.VAR}` at config-load
//!   time, `vault:…` / `aws-sm:…` schemes via plugin-provided secret
//!   resolvers) so cleartext never lives in YAML source. The plugin
//!   itself performs no credential resolution on this path.
//!
//! * [`PoolRegistry`] is the per-credential pool cache used by the
//!   dynamic `cred://` path. It keys pools on a BLAKE3 digest of the
//!   resolved credential bundle so two callers whose credentials end
//!   up identical (e.g. two callers mapped to the same Vault DB
//!   role) share one pool. The registry is bounded — LRU eviction
//!   triggers at `pool_max_entries` so an issuer plugin emitting too
//!   many distinct caller credentials can't pin unbounded memory or
//!   exhaust DB connection limits.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, info};

use crate::auth::TokenRotator;
use crate::config::SqlBackendConfig;
use crate::driver::{ConnectCfg, ConnectOutcome, PoolHandle, SqlDriver};
use crate::errors::SqlError;

/// Open a connection pool for the binding. The URL is passed through
/// to the driver as-is; sqlx parses embedded credentials natively.
///
/// On cloud-auth bindings the driver consults the
/// [`crate::auth::AuthProvider`] supplied via [`ConnectCfg::with_auth_provider`]
/// for an initial token + spawns a refresher; the rotator handle is
/// returned to the caller alongside the pool so the profile runtime
/// can pin its lifetime.
pub async fn build_pool(
    cfg: &SqlBackendConfig,
    driver: &Arc<dyn SqlDriver>,
) -> Result<(PoolHandle, Option<Arc<TokenRotator>>), SqlError> {
    let mut connect_cfg = ConnectCfg::from_config(cfg);
    if let Some(auth) = &cfg.auth {
        let provider = auth.build_provider().await.map_err(SqlError::from)?;
        connect_cfg = connect_cfg.with_auth_provider(provider);
    }
    let ConnectOutcome { pool, rotator } = driver.connect(&connect_cfg).await?;
    Ok((pool, rotator))
}

/// Open a connection pool with an explicit, pre-resolved URL — the
/// driver-facing URL after `cred://` substitution. All other pool
/// knobs come from `cfg` unchanged. Used by the per-credential path
/// in [`PoolRegistry`].
///
/// `auth:` blocks are mutually exclusive with `cred://` references
/// (validated at config-load), so this path never builds an
/// auth-rotated pool — the returned rotator is always `None`. The
/// signature mirrors [`build_pool`] for shape symmetry; callers that
/// only need the pool can `.0` the result.
pub async fn build_pool_with_url(
    cfg: &SqlBackendConfig,
    url: &str,
    driver: &Arc<dyn SqlDriver>,
) -> Result<PoolHandle, SqlError> {
    let mut connect_cfg = ConnectCfg::from_config(cfg);
    connect_cfg.url = url.to_owned();
    let ConnectOutcome { pool, rotator: _ } = driver.connect(&connect_cfg).await?;
    Ok(pool)
}

// ---------------------------------------------------------------------------
// PoolRegistry — per-credential pool cache
// ---------------------------------------------------------------------------

/// 32-byte BLAKE3 digest of a resolved credential bundle. Two
/// requests whose credentials hash identically — same DB user,
/// password, etc. — share one pool through the registry.
pub type CredDigest = [u8; 32];

/// Stable digest of "no credentials resolved" — used for the
/// static-cred fast path so that a profile with no `cred://`
/// references gets exactly one pool through the registry, bit-for-
/// bit equivalent to today's single-pool behaviour.
#[must_use]
pub fn static_digest() -> CredDigest {
    blake3::hash(b"static").into()
}

/// Compute a stable digest from a sorted set of `(field, value)`
/// pairs. The caller (the SQL adapter's `resolve_creds_for` helper)
/// constructs the pair list deterministically — typically the
/// resolved URL plus any session-vars values that contained
/// `cred://` URIs.
#[must_use]
pub fn digest_credential_bundle(pairs: &[(String, String)]) -> CredDigest {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = blake3::Hasher::new();
    for (k, v) in sorted {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

/// One entry in the [`PoolRegistry`].
pub struct PoolEntry {
    /// The live pool. `Clone` is cheap (it's an `Arc` inside).
    pub pool: PoolHandle,
    /// `(plugin_id, target)` pairs that contributed to this pool's
    /// digest. The revocation subscriber maps an incoming
    /// `(plugin_id, target)` to the pools that need eviction.
    pub cred_keys: Vec<(String, String)>,
    /// Monotonic timestamp (ms since registry creation) of the most
    /// recent `get_or_build` hit. Drives idle eviction.
    pub last_used: AtomicU64,
}

impl std::fmt::Debug for PoolEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolEntry")
            .field("cred_keys", &self.cred_keys)
            .field("last_used_ms", &self.last_used.load(Ordering::Relaxed))
            .finish()
    }
}

/// Bounded registry of per-credential pools keyed by [`CredDigest`].
///
/// The registry is cheap to clone — interior state lives behind an
/// `Arc<AsyncMutex>`. The async mutex is held for the full
/// `get_or_build` round trip so two concurrent first-callers for the
/// same digest serialise on the slow `connect` path (avoids
/// thundering-herd open during a Vault-issued credential refresh).
/// Steady-state hits are mutex-acquire + atomic-store; sub-µs.
#[derive(Clone)]
pub struct PoolRegistry {
    inner: Arc<AsyncMutex<Inner>>,
    config: PoolRegistryConfig,
    /// Reference instant for `last_used` deltas. Per-instance so
    /// tests can run with sub-second granularity.
    epoch: Instant,
}

struct Inner {
    pools: HashMap<CredDigest, Arc<PoolEntry>>,
}

/// Operator-tunable knobs for the registry.
#[derive(Debug, Clone)]
pub struct PoolRegistryConfig {
    /// Maximum number of distinct per-credential pools held at any
    /// time. When the registry is full, the LRU entry is evicted —
    /// closing its underlying connections — to make room. Defaults
    /// to 256: pools are heavier than cache entries, so we cap
    /// well below the credential cache's `max_entries` (10k).
    pub pool_max_entries: usize,
    /// Idle-eviction threshold. Pools that haven't been used for
    /// at least this long are dropped on the next sweep. Defaults
    /// to 15 min — enough to amortise the connect cost across
    /// long-tail idle callers without holding open DB connections
    /// indefinitely.
    pub idle_eviction: Duration,
}

impl Default for PoolRegistryConfig {
    fn default() -> Self {
        Self {
            pool_max_entries: 256,
            idle_eviction: Duration::from_secs(15 * 60),
        }
    }
}

impl PoolRegistry {
    /// Build a fresh registry with the given configuration. The
    /// returned handle is empty — pools are populated lazily by
    /// `get_or_build` on first miss for each credential digest.
    #[must_use]
    pub fn new(config: PoolRegistryConfig) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(Inner {
                pools: HashMap::new(),
            })),
            config,
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Look up or build the pool for `digest`. On cache miss, runs
    /// `build` to construct a fresh [`PoolHandle`] under the
    /// registry's lock — concurrent callers for the same digest see
    /// only one underlying `connect` call.
    ///
    /// `cred_keys` is the list of `(plugin_id, target)` pairs the
    /// resolver visited to build the credential bundle. The
    /// registry stores them on the entry so [`evict_for`] can find
    /// the pools to drop when a revocation event fires for
    /// `(plugin_id, target)`.
    pub async fn get_or_build<F, Fut>(
        &self,
        digest: CredDigest,
        cred_keys: Vec<(String, String)>,
        build: F,
    ) -> Result<PoolHandle, SqlError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<PoolHandle, SqlError>>,
    {
        let now = self.now_ms();
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.pools.get(&digest) {
            entry.last_used.store(now, Ordering::Relaxed);
            metrics::counter!("mcpg_sql_pool_registry_total", "outcome" => "hit").increment(1);
            return Ok(entry.pool.clone());
        }
        // Miss path: build under the lock so a thundering herd of
        // concurrent first-callers all get one pool.
        metrics::counter!("mcpg_sql_pool_registry_total", "outcome" => "miss").increment(1);
        let pool = build().await?;
        // LRU evict if we'd overflow.
        while guard.pools.len() >= self.config.pool_max_entries {
            // Find the entry with the oldest `last_used`. Ties
            // broken by the digest's natural ordering for
            // determinism in tests.
            let lru_key = guard
                .pools
                .iter()
                .min_by_key(|(k, e)| (e.last_used.load(Ordering::Relaxed), **k))
                .map(|(k, _)| *k);
            if let Some(k) = lru_key {
                let removed = guard.pools.remove(&k);
                metrics::counter!("mcpg_sql_pool_registry_evictions_total", "reason" => "lru")
                    .increment(1);
                drop(removed); // close happens inside Drop on the inner pool
            } else {
                break;
            }
        }
        let entry = Arc::new(PoolEntry {
            pool: pool.clone(),
            cred_keys,
            last_used: AtomicU64::new(now),
        });
        guard.pools.insert(digest, entry);
        Ok(pool)
    }

    /// Evict every pool whose `cred_keys` contains `(plugin_id,
    /// target)`. Called by the revocation subscriber when the
    /// gateway's credential cache fires `Revoked` for that pair.
    /// Returns the number of pools removed.
    pub async fn evict_for(&self, plugin_id: &str, target: &str) -> usize {
        let mut guard = self.inner.lock().await;
        let to_remove: Vec<CredDigest> = guard
            .pools
            .iter()
            .filter(|(_, e)| {
                e.cred_keys
                    .iter()
                    .any(|(p, t)| p == plugin_id && t == target)
            })
            .map(|(k, _)| *k)
            .collect();
        let count = to_remove.len();
        for k in to_remove {
            guard.pools.remove(&k);
        }
        if count > 0 {
            metrics::counter!(
                "mcpg_sql_pool_registry_evictions_total",
                "reason" => "revoked",
            )
            .increment(count as u64);
        }
        count
    }

    /// Drop every pool in the registry. Called from the secret-
    /// rotation subscriber when a `vault://...` URI tied to this
    /// profile rotates — the resolved DB password baked into each
    /// pool is now stale, so we drop the lot and let the next call
    /// rebuild against the freshly-resolved bundle.
    ///
    /// We don't track per-entry source URIs because every entry in
    /// a single profile's registry shares the same set of resolved
    /// secret refs (the spec carries one DB URL with one password).
    /// The plugin's subscription callback gates the call on whether
    /// the rotated `secret_ref` was registered for this profile.
    pub async fn evict_for_secret(&self, _secret_ref: &str) -> usize {
        let mut guard = self.inner.lock().await;
        let count = guard.pools.len();
        guard.pools.clear();
        if count > 0 {
            metrics::counter!(
                "mcpg_sql_pool_registry_evictions_total",
                "reason" => "secret_rotation",
            )
            .increment(count as u64);
        }
        count
    }

    /// Drop every pool that hasn't been used within the registry's
    /// `idle_eviction` window. Safe to call repeatedly from a
    /// background sweeper task.
    pub async fn sweep_idle(&self) -> usize {
        let now = self.now_ms();
        let threshold_ms = self.config.idle_eviction.as_millis() as u64;
        let mut guard = self.inner.lock().await;
        let to_remove: Vec<CredDigest> = guard
            .pools
            .iter()
            .filter(|(_, e)| {
                let last = e.last_used.load(Ordering::Relaxed);
                now.saturating_sub(last) >= threshold_ms
            })
            .map(|(k, _)| *k)
            .collect();
        let count = to_remove.len();
        for k in to_remove {
            guard.pools.remove(&k);
        }
        if count > 0 {
            metrics::counter!(
                "mcpg_sql_pool_registry_evictions_total",
                "reason" => "idle",
            )
            .increment(count as u64);
        }
        count
    }

    /// Number of pools currently in the registry. Used by tests +
    /// admin/inspect surfaces.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.pools.len()
    }

    /// Whether the registry has zero pools (mirrors `len`).
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.pools.is_empty()
    }

    /// Iterate the live pools' `PoolHandle` clones. Used at
    /// shutdown to drive `Pool::close()` on each one concurrently.
    pub async fn snapshot_pools(&self) -> Vec<PoolHandle> {
        self.inner
            .lock()
            .await
            .pools
            .values()
            .map(|e| e.pool.clone())
            .collect()
    }
}

/// Idle-pool sweeper guard. Holding this Arc keeps the background
/// sweeper task alive; dropping the last clone cancels it. The
/// surrounding `ProfileRuntime` clones the Arc into in-flight
/// executes so a hot-reload that replaces the runtime mid-call does
/// not strand callers — the sweeper drops only once every clone is
/// gone.
pub struct IdleSweeper {
    /// Cancels the spawned sweeper task on drop.
    _cancel_guard: DropGuard,
}

/// Spawn a periodic background task that calls
/// [`PoolRegistry::sweep_idle`] at `interval`. Returns an Arc whose
/// drop cancels the task — the caller stores it on the runtime so
/// teardown is implicit. Errors from `sweep_idle` cannot occur (the
/// method is infallible), so the loop has no error path beyond
/// receiving the cancellation signal.
#[must_use]
pub fn spawn_idle_sweeper(
    backend_name: String,
    registry: Arc<PoolRegistry>,
    interval: Duration,
) -> Arc<IdleSweeper> {
    let token = CancellationToken::new();
    let guard = IdleSweeper {
        _cancel_guard: token.clone().drop_guard(),
    };
    tokio::spawn(idle_sweep_loop(backend_name, registry, interval, token));
    Arc::new(guard)
}

async fn idle_sweep_loop(
    backend_name: String,
    registry: Arc<PoolRegistry>,
    interval: Duration,
    cancel: CancellationToken,
) {
    info!(
        target: "mcpg::sql::pool_registry",
        backend = %backend_name,
        interval_ms = interval.as_millis() as u64,
        "sql pool idle sweeper: started"
    );
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately; consume it so the first
    // sweep happens after one full interval, not at startup.
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(
                    target: "mcpg::sql::pool_registry",
                    backend = %backend_name,
                    "sql pool idle sweeper: cancelled"
                );
                return;
            }
            _ = ticker.tick() => {
                let evicted = registry.sweep_idle().await;
                if evicted > 0 {
                    info!(
                        target: "mcpg::sql::pool_registry",
                        backend = %backend_name,
                        evicted = evicted,
                        "evicted idle SQL pools"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pool_handle() -> PoolHandle {
        // A real PoolHandle requires a live driver. Tests only
        // exercise the registry's bookkeeping, so we build a
        // SQLite memory pool — cheap to construct and torn down
        // when the test ends.
        #[cfg(feature = "sqlite")]
        {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect_lazy("sqlite::memory:")
                .expect("lazy connect");
            return PoolHandle::Sqlite(pool);
        }
        #[allow(unreachable_code)]
        {
            panic!("PoolRegistry tests require the sqlite feature");
        }
    }

    #[tokio::test]
    async fn dedup_by_digest() {
        let reg = PoolRegistry::new(PoolRegistryConfig::default());
        let d = blake3::hash(b"alice-creds").into();
        let _ = reg
            .get_or_build(d, vec![("vault".into(), "orders".into())], || async {
                Ok(fake_pool_handle())
            })
            .await
            .unwrap();
        let _ = reg
            .get_or_build(d, vec![("vault".into(), "orders".into())], || async {
                panic!("must not rebuild on hit")
            })
            .await
            .unwrap();
        assert_eq!(reg.len().await, 1);
    }

    #[tokio::test]
    async fn separate_digests_get_separate_pools() {
        let reg = PoolRegistry::new(PoolRegistryConfig::default());
        let d1: CredDigest = blake3::hash(b"alice").into();
        let d2: CredDigest = blake3::hash(b"bob").into();
        reg.get_or_build(d1, vec![("vault".into(), "orders".into())], || async {
            Ok(fake_pool_handle())
        })
        .await
        .unwrap();
        reg.get_or_build(d2, vec![("vault".into(), "orders".into())], || async {
            Ok(fake_pool_handle())
        })
        .await
        .unwrap();
        assert_eq!(reg.len().await, 2);
    }

    #[tokio::test]
    async fn evict_for_drops_matching_pools() {
        let reg = PoolRegistry::new(PoolRegistryConfig::default());
        let d1: CredDigest = blake3::hash(b"alice").into();
        let d2: CredDigest = blake3::hash(b"bob").into();
        let d3: CredDigest = blake3::hash(b"carol").into();
        reg.get_or_build(d1, vec![("vault".into(), "orders".into())], || async {
            Ok(fake_pool_handle())
        })
        .await
        .unwrap();
        reg.get_or_build(d2, vec![("vault".into(), "orders".into())], || async {
            Ok(fake_pool_handle())
        })
        .await
        .unwrap();
        // Different target — should NOT be evicted.
        reg.get_or_build(d3, vec![("vault".into(), "payments".into())], || async {
            Ok(fake_pool_handle())
        })
        .await
        .unwrap();
        let evicted = reg.evict_for("vault", "orders").await;
        assert_eq!(evicted, 2);
        assert_eq!(reg.len().await, 1);
    }

    #[tokio::test]
    async fn evict_for_secret_drops_all_pools() {
        let reg = PoolRegistry::new(PoolRegistryConfig::default());
        let d1: CredDigest = blake3::hash(b"alice").into();
        let d2: CredDigest = blake3::hash(b"bob").into();
        reg.get_or_build(d1, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        reg.get_or_build(d2, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        assert_eq!(reg.len().await, 2);
        let dropped = reg.evict_for_secret("vault://kv/db#password").await;
        assert_eq!(dropped, 2, "all pools dropped on rotation");
        assert_eq!(reg.len().await, 0);
    }

    #[tokio::test]
    async fn lru_eviction_when_over_capacity() {
        let reg = PoolRegistry::new(PoolRegistryConfig {
            pool_max_entries: 2,
            idle_eviction: Duration::from_secs(60),
        });
        let d1: CredDigest = blake3::hash(b"a").into();
        let d2: CredDigest = blake3::hash(b"b").into();
        let d3: CredDigest = blake3::hash(b"c").into();
        reg.get_or_build(d1, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        // Sleep so last_used differs.
        tokio::time::sleep(Duration::from_millis(2)).await;
        reg.get_or_build(d2, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        reg.get_or_build(d3, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        // d1 was LRU; should be evicted.
        assert_eq!(reg.len().await, 2);
    }

    #[tokio::test]
    async fn idle_sweep_drops_stale_pools() {
        let reg = PoolRegistry::new(PoolRegistryConfig {
            pool_max_entries: 100,
            idle_eviction: Duration::from_millis(5),
        });
        let d: CredDigest = blake3::hash(b"alice").into();
        reg.get_or_build(d, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        assert_eq!(reg.len().await, 1);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let evicted = reg.sweep_idle().await;
        assert_eq!(evicted, 1);
        assert_eq!(reg.len().await, 0);
    }

    #[test]
    fn digest_credential_bundle_is_order_independent() {
        let a = digest_credential_bundle(&[
            ("url".into(), "postgres://u:p@h/db".into()),
            ("session.role".into(), "readonly".into()),
        ]);
        let b = digest_credential_bundle(&[
            ("session.role".into(), "readonly".into()),
            ("url".into(), "postgres://u:p@h/db".into()),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_credential_bundle_distinguishes_distinct_inputs() {
        let a = digest_credential_bundle(&[("url".into(), "postgres://u1:p@h/db".into())]);
        let b = digest_credential_bundle(&[("url".into(), "postgres://u2:p@h/db".into())]);
        assert_ne!(a, b);
    }

    #[test]
    fn static_digest_is_stable() {
        assert_eq!(static_digest(), static_digest());
    }

    #[tokio::test]
    async fn spawned_sweeper_evicts_idle_pools() {
        let reg = Arc::new(PoolRegistry::new(PoolRegistryConfig {
            pool_max_entries: 100,
            idle_eviction: Duration::from_millis(20),
        }));
        let d: CredDigest = blake3::hash(b"alice").into();
        reg.get_or_build(d, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        assert_eq!(reg.len().await, 1);

        let _guard = spawn_idle_sweeper(
            "test_binding".to_owned(),
            Arc::clone(&reg),
            Duration::from_millis(30),
        );
        // Wait long enough for: idle threshold (20 ms) + sweeper
        // interval tick (30 ms) + a slack for scheduling.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(reg.len().await, 0, "spawned sweeper should evict idle pool");
    }

    #[tokio::test]
    async fn dropped_sweeper_guard_cancels_task() {
        let reg = Arc::new(PoolRegistry::new(PoolRegistryConfig {
            pool_max_entries: 100,
            idle_eviction: Duration::from_millis(5),
        }));
        let guard = spawn_idle_sweeper(
            "test_binding".to_owned(),
            Arc::clone(&reg),
            Duration::from_millis(10),
        );
        // Drop the guard, then add a pool and let it idle. If the
        // sweeper were still running, it would evict; it shouldn't.
        drop(guard);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let d: CredDigest = blake3::hash(b"alice").into();
        reg.get_or_build(d, vec![], || async { Ok(fake_pool_handle()) })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(reg.len().await, 1, "cancelled sweeper must not evict");
    }
}
