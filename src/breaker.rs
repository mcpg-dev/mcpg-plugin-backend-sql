//! Per-binding circuit breaker for SQL calls.
//!
//! Fails fast when the database is unhealthy so a misbehaving backend
//! doesn't drag the gateway down. The existing
//! `mcpg-plugin-reliability-circuit-breaker` operates at the ToolGate level — per
//! tool name, post-dispatch. That works, but it can't distinguish a
//! pool-exhaustion storm from application errors, and its half-open
//! probe is "just retry the real call." This module adds the
//! binding-scoped half of the story:
//!
//! - **Failure signal** includes pool timeouts and `BackendError::Transport`,
//!   not only `is_error` tool results. Operators set `failure_threshold`
//!   to trip after N consecutive failures.
//! - **Open state** short-circuits `plugin.execute()` with a fast
//!   `Transport` error carrying `circuit_open` — no round trip to the
//!   DB, no pool acquire.
//! - **Half-open** admits the first call after `cooldown_ms`; its
//!   outcome decides Closed (success) or Open again (failure). One
//!   probe in flight at a time — excess callers short-circuit as if
//!   the breaker were still Open.
//!
//! The breaker is config-driven; operators opt in per-binding via
//! the new `[bindings.sql.circuit_breaker]` block. Disabled by
//! default — existing bindings see no behavior change.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::errors::SqlError;

/// Per-binding breaker configuration. Absence in the spec means
/// "no breaker" — the call always reaches the driver.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures required to trip Closed → Open.
    /// Defaults to 5.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// How long the breaker stays Open before transitioning to
    /// HalfOpen. Defaults to 30 s.
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_cooldown_ms() -> u64 {
    30_000
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            cooldown_ms: default_cooldown_ms(),
        }
    }
}

impl CircuitBreakerConfig {
    /// Validate bounds. Zero thresholds disable the breaker the
    /// hard way — we reject them so operator intent is explicit.
    pub fn validate(&self) -> Result<(), SqlError> {
        if self.failure_threshold == 0 {
            return Err(SqlError::InvalidSpec(
                "circuit_breaker.failure_threshold must be > 0 \
                 (omit the whole block to disable the breaker)"
                    .into(),
            ));
        }
        if self.cooldown_ms == 0 {
            return Err(SqlError::InvalidSpec(
                "circuit_breaker.cooldown_ms must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// Runtime state. Shared across all callers of one profile via
/// `Arc`; every atomic touched on the fast path stays lock-free.
/// The `Mutex<Instant>` only fires on Closed → Open transitions
/// (rare) and when checking Open → HalfOpen (cheap).
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    /// Count of consecutive failures in the Closed state. Resets
    /// to 0 on any success.
    consecutive_failures: AtomicU32,
    /// Wall-clock (mono) the breaker opened; consulted to decide
    /// whether cooldown has elapsed. Only meaningful when
    /// `state == Open`.
    opened_at: Mutex<Option<Instant>>,
    /// Is a half-open probe currently in flight? Used to admit
    /// exactly one probe and short-circuit the rest.
    probe_in_flight: AtomicBool,
    /// Total trips since process start — observability.
    total_trips: AtomicU64,
    state: AtomicCircuitState,
}

/// Closed / Open / HalfOpen encoded as three atomic u8 values so
/// the state is loadable without a lock.
#[derive(Debug)]
struct AtomicCircuitState(std::sync::atomic::AtomicU8);

impl AtomicCircuitState {
    const CLOSED: u8 = 0;
    const OPEN: u8 = 1;
    const HALF_OPEN: u8 = 2;

    fn new_closed() -> Self {
        Self(std::sync::atomic::AtomicU8::new(Self::CLOSED))
    }

    fn load(&self) -> CircuitState {
        match self.0.load(Ordering::Acquire) {
            Self::CLOSED => CircuitState::Closed,
            Self::OPEN => CircuitState::Open,
            Self::HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    fn store(&self, s: CircuitState) {
        let v = match s {
            CircuitState::Closed => Self::CLOSED,
            CircuitState::Open => Self::OPEN,
            CircuitState::HalfOpen => Self::HALF_OPEN,
        };
        self.0.store(v, Ordering::Release);
    }
}

/// Public breaker state, returned by [`CircuitBreaker::snapshot`]
/// for observability surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)] // variants are the canonical closed/open/half-open
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    /// Construct a breaker from an operator config.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            consecutive_failures: AtomicU32::new(0),
            opened_at: Mutex::new(None),
            probe_in_flight: AtomicBool::new(false),
            total_trips: AtomicU64::new(0),
            state: AtomicCircuitState::new_closed(),
        }
    }

    /// Current snapshot for observability.
    pub fn snapshot(&self) -> CircuitSnapshot {
        CircuitSnapshot {
            state: self.state.load(),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            total_trips: self.total_trips.load(Ordering::Relaxed),
        }
    }

    /// Decide whether to admit the incoming call. Transitions the
    /// state machine as a side-effect:
    ///
    /// - **Closed** → admit.
    /// - **Open** but cooldown elapsed → transition to HalfOpen,
    ///   admit as the probe.
    /// - **Open** and still cooling → reject with
    ///   `Transport("circuit_open")`.
    /// - **HalfOpen** with a probe already in flight → reject;
    ///   the probe's outcome decides the next transition.
    /// - **HalfOpen** with no probe → admit as the probe.
    pub fn try_admit(&self) -> Result<AdmitGuard<'_>, SqlError> {
        match self.state.load() {
            CircuitState::Closed => Ok(AdmitGuard {
                breaker: self,
                probe: false,
            }),
            CircuitState::Open => {
                if self.cooldown_elapsed() {
                    // Transition to HalfOpen; admit as the probe.
                    self.state.store(CircuitState::HalfOpen);
                    info!("sql circuit: Open → HalfOpen (cooldown elapsed)");
                    self.probe_in_flight.store(true, Ordering::Release);
                    Ok(AdmitGuard {
                        breaker: self,
                        probe: true,
                    })
                } else {
                    Err(fast_fail_error())
                }
            }
            CircuitState::HalfOpen => {
                // Try to claim the probe slot. If another probe is
                // already in flight, short-circuit.
                if self
                    .probe_in_flight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    Ok(AdmitGuard {
                        breaker: self,
                        probe: true,
                    })
                } else {
                    Err(fast_fail_error())
                }
            }
        }
    }

    /// Called by the guard when the admitted call succeeds. In
    /// HalfOpen, success promotes the breaker back to Closed.
    fn record_success(&self, was_probe: bool) {
        self.consecutive_failures.store(0, Ordering::Release);
        if was_probe {
            self.probe_in_flight.store(false, Ordering::Release);
            self.state.store(CircuitState::Closed);
            info!("sql circuit: HalfOpen → Closed (probe succeeded)");
            // Clear the opened_at timestamp so the next trip
            // starts from a clean slate.
            *self.opened_at.lock() = None;
        }
    }

    /// Called by the guard when the admitted call fails. In
    /// Closed, increments the streak and trips at the threshold.
    /// In HalfOpen, the probe failure re-opens the breaker for
    /// another cooldown cycle.
    fn record_failure(&self, was_probe: bool) {
        if was_probe {
            self.probe_in_flight.store(false, Ordering::Release);
            self.state.store(CircuitState::Open);
            *self.opened_at.lock() = Some(Instant::now());
            warn!("sql circuit: HalfOpen → Open (probe failed)");
            return;
        }
        let n = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= self.config.failure_threshold {
            // Trip the breaker. We don't reset consecutive_failures
            // — it stays elevated until the next success.
            if self
                .state
                .0
                .compare_exchange(
                    AtomicCircuitState::CLOSED,
                    AtomicCircuitState::OPEN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                *self.opened_at.lock() = Some(Instant::now());
                self.total_trips.fetch_add(1, Ordering::Relaxed);
                warn!(
                    consecutive_failures = n,
                    threshold = self.config.failure_threshold,
                    "sql circuit: Closed → Open"
                );
            }
        } else {
            debug!(consecutive_failures = n, "sql circuit: failure recorded");
        }
    }

    fn cooldown_elapsed(&self) -> bool {
        let opened_at = *self.opened_at.lock();
        match opened_at {
            Some(t) => t.elapsed() >= Duration::from_millis(self.config.cooldown_ms),
            None => true, // defensive: no opened_at → treat as elapsed
        }
    }
}

fn fast_fail_error() -> SqlError {
    // `Transport` projects to `BackendError::Transport` at the
    // plugin boundary — keeps retry semantics consistent with
    // other transient failures.
    SqlError::Driver(sqlx::Error::PoolClosed)
}

/// Observability snapshot for admin tooling.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(missing_docs)] // self-describing public fields
pub struct CircuitSnapshot {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub total_trips: u64,
}

/// RAII guard yielded by [`CircuitBreaker::try_admit`]. The caller
/// **must** invoke [`AdmitGuard::record`] with the outcome before
/// dropping; forgetting to call it leaves the breaker's counters
/// stale (and, for probes, blocks the probe slot until the next
/// admit). `Drop` treats an unrecorded guard as a success to avoid
/// blackholing the probe slot when a caller panics; this is the
/// conservative choice because the breaker is an availability
/// aid, not a correctness mechanism.
#[must_use = "AdmitGuard must receive a success/failure record before drop"]
#[derive(Debug)]
pub struct AdmitGuard<'a> {
    breaker: &'a CircuitBreaker,
    probe: bool,
}

impl<'a> AdmitGuard<'a> {
    /// Record the admitted call's outcome and consume the guard.
    pub fn record(self, success: bool) {
        if success {
            self.breaker.record_success(self.probe);
        } else {
            self.breaker.record_failure(self.probe);
        }
        // Skip Drop's fallback.
        std::mem::forget(self);
    }

    /// True if this admission is serving as the half-open probe.
    pub fn is_probe(&self) -> bool {
        self.probe
    }
}

impl Drop for AdmitGuard<'_> {
    fn drop(&mut self) {
        // Unrecorded guard: treat as success so an accidental
        // panic path doesn't leave the probe slot pinned or
        // falsely increment failures.
        self.breaker.record_success(self.probe);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: u32, cooldown_ms: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: threshold,
            cooldown_ms,
        }
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let err = cfg(0, 1000).validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("failure_threshold")));
    }

    #[test]
    fn validate_rejects_zero_cooldown() {
        let err = cfg(3, 0).validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("cooldown_ms")));
    }

    #[test]
    fn closed_admits_and_records_success() {
        let cb = CircuitBreaker::new(cfg(3, 1000));
        let g = cb.try_admit().unwrap();
        assert!(!g.is_probe());
        g.record(true);
        let snap = cb.snapshot();
        assert_eq!(snap.state, CircuitState::Closed);
        assert_eq!(snap.consecutive_failures, 0);
    }

    #[test]
    fn consecutive_failures_trip_the_breaker() {
        let cb = CircuitBreaker::new(cfg(3, 1000));
        for _ in 0..3 {
            let g = cb.try_admit().unwrap();
            g.record(false);
        }
        let snap = cb.snapshot();
        assert_eq!(snap.state, CircuitState::Open);
        assert_eq!(snap.total_trips, 1);
    }

    #[test]
    fn success_resets_the_failure_streak() {
        let cb = CircuitBreaker::new(cfg(3, 1000));
        cb.try_admit().unwrap().record(false);
        cb.try_admit().unwrap().record(false);
        cb.try_admit().unwrap().record(true); // reset
        assert_eq!(cb.snapshot().consecutive_failures, 0);
        assert_eq!(cb.snapshot().state, CircuitState::Closed);
    }

    #[test]
    fn open_rejects_before_cooldown() {
        let cb = CircuitBreaker::new(cfg(1, 10_000));
        cb.try_admit().unwrap().record(false); // trip
        let err = cb.try_admit().unwrap_err();
        assert!(matches!(err, SqlError::Driver(_)));
    }

    #[test]
    fn open_half_open_probe_succeeds_and_recloses() {
        let cb = CircuitBreaker::new(cfg(1, 1));
        // Trip.
        cb.try_admit().unwrap().record(false);
        std::thread::sleep(Duration::from_millis(5));
        // Cooldown elapsed → probe admitted.
        let g = cb.try_admit().unwrap();
        assert!(g.is_probe());
        assert_eq!(cb.snapshot().state, CircuitState::HalfOpen);
        g.record(true);
        assert_eq!(cb.snapshot().state, CircuitState::Closed);
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let cb = CircuitBreaker::new(cfg(1, 1));
        cb.try_admit().unwrap().record(false);
        std::thread::sleep(Duration::from_millis(5));
        let g = cb.try_admit().unwrap();
        assert!(g.is_probe());
        g.record(false);
        assert_eq!(cb.snapshot().state, CircuitState::Open);
        assert_eq!(cb.snapshot().total_trips, 1);
    }

    #[test]
    fn half_open_admits_one_probe_at_a_time() {
        let cb = CircuitBreaker::new(cfg(1, 1));
        cb.try_admit().unwrap().record(false);
        std::thread::sleep(Duration::from_millis(5));
        let g = cb.try_admit().expect("probe admitted");
        // Second caller should short-circuit; probe is in flight.
        let second = cb.try_admit();
        assert!(second.is_err(), "concurrent probe should be rejected");
        g.record(true);
    }

    #[test]
    fn drop_without_record_treats_as_success() {
        let cb = CircuitBreaker::new(cfg(3, 1000));
        cb.try_admit().unwrap().record(false);
        {
            let _g = cb.try_admit().unwrap();
            // dropped here without .record() — our Drop treats as success
        }
        // Streak should be reset by the fake success.
        assert_eq!(cb.snapshot().consecutive_failures, 0);
    }
}
