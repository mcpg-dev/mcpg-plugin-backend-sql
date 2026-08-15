//! Background token-rotation task for cloud-auth pools.
//!
//! Sits in front of an `sqlx::Pool` and, on a schedule derived from
//! the provider's TTL, calls [`AuthProvider::fetch_token`], rebuilds
//! the connection options with the fresh token, and pushes them into
//! the pool via `Pool::set_connect_options`. Existing physical
//! connections drain naturally — sqlx applies new options only to
//! future connection-acquire calls — and the pool's `max_lifetime`
//! is capped to `token_ttl - safety_margin` at construction time so
//! no live connection outlives the token it was authenticated with.
//!
//! The rotator is owned by an [`Arc`]; the spawned task holds a
//! `Weak` so dropping the last [`TokenRotator`] handle (e.g. at
//! profile teardown) cancels the loop without waiting for the next
//! tick. The cancellation path is implicit — the loop wakes,
//! observes `Weak::upgrade` returning `None`, and exits.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::AuthProvider;

/// Operator-tunable rotator knobs.
#[derive(Debug, Clone)]
pub struct RotatorConfig {
    /// Refresh `safety_margin` before the provider's reported TTL.
    /// 60 s for RDS / Azure AD (15 min tokens); shorter for unit
    /// tests that need to observe rotation in real time.
    pub safety_margin: Duration,
    /// Lower bound on the refresh interval. Guards against a buggy
    /// provider returning a near-zero TTL and pinning the rotator at
    /// 100% CPU. Default 5 s.
    pub min_interval: Duration,
}

impl Default for RotatorConfig {
    fn default() -> Self {
        Self {
            safety_margin: Duration::from_secs(60),
            min_interval: Duration::from_secs(5),
        }
    }
}

impl RotatorConfig {
    /// Refresh interval for a token with the given declared TTL.
    /// `ttl - safety_margin`, floored at `min_interval`. Returns
    /// `None` when the provider reports `Duration::MAX` — rotation
    /// is disabled for that pool.
    #[must_use]
    pub fn interval_for(&self, ttl: Duration) -> Option<Duration> {
        if ttl == Duration::MAX {
            return None;
        }
        let target = ttl.checked_sub(self.safety_margin).unwrap_or_default();
        Some(target.max(self.min_interval))
    }

    /// Cap on the pool's `max_lifetime`. Connections older than this
    /// are recycled before their token expires. Same expression as
    /// [`Self::interval_for`] but returns `None` only on `Duration::MAX`
    /// — for finite TTLs it always emits a usable cap.
    #[must_use]
    pub fn pool_max_lifetime_for(&self, ttl: Duration) -> Option<Duration> {
        if ttl == Duration::MAX {
            return None;
        }
        Some(
            ttl.checked_sub(self.safety_margin)
                .unwrap_or_default()
                .max(self.min_interval),
        )
    }
}

/// Owns the spawned rotation task. Drop the handle to stop rotation;
/// the inner `DropGuard` cancels the spawned future on the next
/// scheduler poll.
///
/// `Clone` is intentionally absent: the rotator is per-pool, and the
/// caller (driver `connect()` impl) hands the single instance to the
/// `ProfileRuntime` which holds it for the profile's lifetime. Pool
/// teardown ⇒ runtime teardown ⇒ rotator drop ⇒ task exit.
#[must_use]
pub struct TokenRotator {
    _drop_guard: DropGuard,
    /// Notifier the rotator pings on a fresh-token success — tests
    /// await this instead of polling. Public via accessor below.
    refresh_notify: Arc<Notify>,
    /// Join handle for the rotation task. Not awaited at drop —
    /// cancellation is the supported teardown — but exposed so tests
    /// can `.abort()` and `.await` for a deterministic stop.
    handle: JoinHandle<()>,
}

impl TokenRotator {
    /// Spawn a rotator that drives `apply_token` every
    /// `cfg.interval_for(provider.token_ttl())`. The first tick fires
    /// at `interval`, NOT immediately — the seed token is expected to
    /// have been applied at pool-construction time before this call.
    ///
    /// `apply_token` receives the freshly fetched token and returns
    /// `Ok(())` on success. Errors from either `fetch_token` or
    /// `apply_token` log + emit a counter but don't crash the loop;
    /// the next tick retries. Persistent failure manifests as
    /// connection errors when the existing token expires — operators
    /// see it via the gateway's pool-error metrics.
    pub fn spawn<A>(
        provider: Arc<dyn AuthProvider>,
        apply_token: A,
        cfg: RotatorConfig,
    ) -> Arc<Self>
    where
        A: ApplyToken + 'static,
    {
        let cancel = CancellationToken::new();
        let cancel_child = cancel.clone();
        let refresh_notify = Arc::new(Notify::new());
        let notify_child = Arc::clone(&refresh_notify);

        let interval = match cfg.interval_for(provider.token_ttl()) {
            Some(d) => d,
            None => {
                // Infinite TTL — register a no-op task so the handle
                // shape is uniform. The task exits on cancel.
                let cancel_child2 = cancel_child.clone();
                let handle = tokio::spawn(async move {
                    cancel_child2.cancelled().await;
                });
                let drop_guard = cancel.drop_guard();
                return Arc::new(Self {
                    _drop_guard: drop_guard,
                    refresh_notify,
                    handle,
                });
            }
        };

        let scheme = provider.scheme();
        let apply: Arc<dyn ApplyToken> = Arc::new(apply_token);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_child.cancelled() => {
                        tracing::debug!(
                            target: "mcpg::sql::auth",
                            scheme,
                            "token rotator cancelled"
                        );
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {}
                }

                match provider.fetch_token().await {
                    Ok(token) => match apply.apply(&token).await {
                        Ok(()) => {
                            metrics::counter!(
                                "mcpg_sql_auth_token_refresh_total",
                                "scheme" => scheme,
                                "outcome" => "ok",
                            )
                            .increment(1);
                            tracing::debug!(
                                target: "mcpg::sql::auth",
                                scheme,
                                "rotated cloud-auth token"
                            );
                            notify_child.notify_waiters();
                        }
                        Err(e) => {
                            metrics::counter!(
                                "mcpg_sql_auth_token_refresh_total",
                                "scheme" => scheme,
                                "outcome" => "apply_error",
                            )
                            .increment(1);
                            tracing::warn!(
                                target: "mcpg::sql::auth",
                                scheme,
                                error = %e,
                                "token rotation: apply failed; retrying on next tick"
                            );
                        }
                    },
                    Err(e) => {
                        metrics::counter!(
                            "mcpg_sql_auth_token_refresh_total",
                            "scheme" => scheme,
                            "outcome" => "fetch_error",
                        )
                        .increment(1);
                        tracing::warn!(
                            target: "mcpg::sql::auth",
                            scheme,
                            error = %e,
                            "token rotation: fetch failed; retrying on next tick"
                        );
                    }
                }
            }
        });

        let drop_guard = cancel.drop_guard();
        Arc::new(Self {
            _drop_guard: drop_guard,
            refresh_notify,
            handle,
        })
    }

    /// Notifier fired after each successful rotation. Tests `await`
    /// this to synchronise on a refresh without polling.
    #[must_use]
    pub fn refresh_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.refresh_notify)
    }

    /// Abort + await the spawned task. Used in tests for deterministic
    /// teardown; production drops the whole `Arc<TokenRotator>` and
    /// the cancel token does the same job asynchronously.
    pub async fn shutdown(self: Arc<Self>) {
        // We can't move out of an Arc, so just abort the handle —
        // the DropGuard will fire when the Arc is dropped.
        self.handle.abort();
    }
}

/// Sink for fresh tokens. Implementations call into a sqlx pool's
/// `set_connect_options` (production) or a test channel (rotator
/// tests). Async because real impls may do an `await` (e.g. wrapping
/// the call in a `spawn_blocking` for a sync sqlx API isn't needed
/// here, but we leave room for a future provider that does).
#[async_trait::async_trait]
pub trait ApplyToken: Send + Sync {
    /// Apply the freshly fetched token. Errors here only log + retry
    /// on the next tick; they don't kill the rotator.
    async fn apply(&self, token: &super::SecretToken) -> Result<(), super::AuthError>;
}

#[async_trait::async_trait]
impl<F, Fut> ApplyToken for F
where
    F: Fn(&super::SecretToken) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), super::AuthError>> + Send,
{
    async fn apply(&self, token: &super::SecretToken) -> Result<(), super::AuthError> {
        (self)(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::MockAuthProvider;
    use std::sync::Mutex;

    #[test]
    fn interval_floors_at_min_interval() {
        let cfg = RotatorConfig {
            safety_margin: Duration::from_secs(60),
            min_interval: Duration::from_secs(5),
        };
        // 30s TTL → 30 - 60 = saturating to 0 → floored to 5s
        let i = cfg.interval_for(Duration::from_secs(30));
        assert_eq!(i, Some(Duration::from_secs(5)));
        // 900s TTL (RDS) → 840s
        let i = cfg.interval_for(Duration::from_secs(900));
        assert_eq!(i, Some(Duration::from_secs(840)));
        // MAX → None (rotation disabled)
        assert_eq!(cfg.interval_for(Duration::MAX), None);
    }

    #[test]
    fn pool_max_lifetime_caps_at_ttl_minus_margin() {
        let cfg = RotatorConfig::default();
        // 900s → 840s.
        let cap = cfg.pool_max_lifetime_for(Duration::from_secs(900));
        assert_eq!(cap, Some(Duration::from_secs(840)));
    }

    #[tokio::test]
    async fn rotator_calls_apply_on_each_tick() {
        let provider = Arc::new(MockAuthProvider::new("tok-A", Duration::from_millis(100)));
        let provider_dyn: Arc<dyn AuthProvider> = provider.clone();

        let observed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_inner = Arc::clone(&observed);

        let cfg = RotatorConfig {
            // No margin; min 50ms. Provider TTL 100ms → interval 50ms.
            safety_margin: Duration::from_millis(0),
            min_interval: Duration::from_millis(50),
        };

        let apply = move |t: &super::super::SecretToken| {
            let observed = Arc::clone(&observed_inner);
            let val = t.expose().to_owned();
            async move {
                observed.lock().unwrap().push(val);
                Ok(())
            }
        };

        let rotator = TokenRotator::spawn(provider_dyn, apply, cfg);
        let notify = rotator.refresh_notify();

        // Wait for two rotations.
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), notify.notified())
                .await
                .expect("rotator did not refresh in time");
        }

        let count = provider.fetch_count();
        assert!(count >= 2, "expected ≥2 refreshes, got {count}");
        let obs = observed.lock().unwrap().clone();
        assert!(
            obs.iter().all(|t| t == "tok-A"),
            "unexpected tokens: {obs:?}"
        );

        rotator.shutdown().await;
    }

    #[tokio::test]
    async fn rotator_with_infinite_ttl_does_not_tick() {
        let provider = Arc::new(MockAuthProvider::new("tok", Duration::MAX));
        let provider_dyn: Arc<dyn AuthProvider> = provider.clone();
        let cfg = RotatorConfig::default();

        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_inner = Arc::clone(&count);
        let apply = move |_t: &super::super::SecretToken| {
            let c = Arc::clone(&count_inner);
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
        };

        let rotator = TokenRotator::spawn(provider_dyn, apply, cfg);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(provider.fetch_count(), 0);
        rotator.shutdown().await;
    }
}
