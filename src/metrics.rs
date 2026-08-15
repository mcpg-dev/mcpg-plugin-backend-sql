//! Metrics emission via the `metrics` crate.
//!
//! MCPG doesn't currently expose a Prometheus endpoint, but many
//! downstream deployments wire one in via `metrics-exporter-prometheus`
//! or similar. Registering here means SQL binding metrics show up
//! automatically when an exporter is plugged in, without any
//! per-binding wiring.
//!
//! **Label cardinality is bounded by construction.** `binding` and
//! `query` are operator-declared strings (O(config)); `driver` is a
//! finite enum; `status` and `outcome` are small closed sets. SQL
//! text never appears as a label — it would blow up cardinality.

use std::time::Duration;

use metrics::{counter, gauge, histogram};

use crate::config::DriverKind;

/// Metric name constants kept in one place so naming stays consistent.
pub(crate) mod names {
    pub const CALLS_TOTAL: &str = "mcpg_sql_calls_total";
    pub const DURATION_SECONDS: &str = "mcpg_sql_duration_seconds";
    pub const ROWS_RETURNED: &str = "mcpg_sql_rows_returned";
    pub const PROGRESS_HEARTBEATS: &str = "mcpg_sql_progress_heartbeats_total";
    pub const REQUESTS_IN_FLIGHT: &str = "mcpg_sql_requests_in_flight";
    pub const PREPARE_RETRIES: &str = "mcpg_sql_prepare_retries_total";
    pub const AWAIT_POLLS: &str = "mcpg_sql_await_polls_total";
    // Full await observability triad. POLLS already exists
    // (one bump per loop terminating in matched/timeout); the three
    // below give per-poll granularity + active gauge + duration
    // histogram so dashboards can chart "active awaits" + "p95 wait
    // duration" + "spurious wake rate" without deriving from POLLS.
    pub const AWAIT_WAITS_ACTIVE: &str = "mcpg_sql_await_waits_active";
    pub const AWAIT_DURATION_SECONDS: &str = "mcpg_sql_await_duration_seconds";
    pub const AWAIT_WAKES: &str = "mcpg_sql_await_wakes_total";
    // Response cache. `hits` and `misses` are mutually
    // exclusive on a per-call basis; `writes` is bumped on
    // successful cache_put after a miss-then-execute path.
    pub const CACHE_HITS: &str = "mcpg_sql_cache_hits_total";
    pub const CACHE_MISSES: &str = "mcpg_sql_cache_misses_total";
    pub const CACHE_WRITES: &str = "mcpg_sql_cache_writes_total";
    // Cost / billing telemetry. Counter is in
    // micro-units (1 USD = 1_000_000) to preserve precision
    // through u64; histogram is the per-call decimal amount.
    // Refunded counter increments on every error path so
    // downstream billing reconcilers can credit back any
    // amount the gateway-side payment gate captured.
    pub const COST_TOTAL: &str = "mcpg_sql_cost_total";
    pub const CALL_COST: &str = "mcpg_sql_call_cost";
    pub const COST_REFUNDED: &str = "mcpg_sql_cost_refunded_total";
}

/// Record a single call outcome. Emitted once per `execute()`.
pub(crate) fn record_call(
    binding: &str,
    query_ref: &str,
    driver: DriverKind,
    status: CallStatus,
    duration: Duration,
    rows: Option<u64>,
) {
    let status_label = status.as_str();
    let driver_label = driver.as_str();

    counter!(
        names::CALLS_TOTAL,
        "backend" => binding.to_owned(),
        "query" => query_ref.to_owned(),
        "driver" => driver_label,
        "status" => status_label,
    )
    .increment(1);

    histogram!(
        names::DURATION_SECONDS,
        "backend" => binding.to_owned(),
        "query" => query_ref.to_owned(),
        "driver" => driver_label,
    )
    .record(duration.as_secs_f64());

    if let Some(n) = rows {
        histogram!(
            names::ROWS_RETURNED,
            "backend" => binding.to_owned(),
            "query" => query_ref.to_owned(),
        )
        .record(n as f64);
    }
}

/// Bump the `mcpg_sql_prepare_retries_total` counter when the
/// plugin caught a stale-statement SQLSTATE and retried the query
/// on a fresh pool connection. Elevated values on a
/// production deployment correlate with concurrent DDL / schema
/// migrations mid-uptime.
pub(crate) fn record_prepare_retry(binding: &str, driver: DriverKind) {
    counter!(
        names::PREPARE_RETRIES,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
    )
    .increment(1);
}

/// Update the `mcpg_sql_requests_in_flight` gauge per driver.
/// Called from the RAII guard on both register and drop so the gauge
/// always reflects the authoritative registry count. The `driver`
/// label lets operators disambiguate engine-specific saturation.
pub(crate) fn record_in_flight(count: usize, driver: DriverKind) {
    gauge!(
        names::REQUESTS_IN_FLIGHT,
        "driver" => driver.as_str(),
    )
    .set(count as f64);
}

/// Record the terminal outcome of an await loop —
/// `matched` (predicate satisfied and we're returning the check
/// row) or `timeout` (poll budget exhausted). The `polls` value
/// fuels a histogram-style bump on the poll counter so operators
/// can spot flows that consistently overrun their configured
/// interval budget.
pub(crate) fn record_await_wait(
    binding: &str,
    driver: DriverKind,
    outcome: &'static str,
    polls: u64,
) {
    // Polls are counted by bumping the counter `polls` times —
    // the metrics crate histogram path expects `f64` samples but
    // for a simple poll-count we prefer the plain counter. Only
    // one call site per await loop so the loop over `polls` is
    // bounded (timeout_ms / poll_interval_ms) and cheap.
    let polls = polls as i64;
    if polls > 0 {
        counter!(
            names::AWAIT_POLLS,
            "backend" => binding.to_owned(),
            "driver" => driver.as_str(),
            "outcome" => outcome,
        )
        .increment(polls as u64);
    }
    // No wait-duration histogram here — the caller doesn't pass
    // wall time, to keep the interface narrow. Operators who need
    // wait-duration histograms can derive from `AWAIT_POLLS` ×
    // configured poll_interval_ms, or enable the `duration_ms`
    // tracing-span audit stream at `mcpg::sql::audit`.
}

/// Increment the active-awaits gauge. Returns a guard whose
/// `Drop` decrements the gauge — pairing the bump with the loop's
/// lifetime regardless of how it exits (match / timeout / error /
/// panic). The gauge is per-driver, not per-binding, to keep label
/// cardinality bounded as the await runtime scales out.
pub(crate) fn await_waits_guard(driver: DriverKind) -> AwaitWaitsGuard {
    gauge!(
        names::AWAIT_WAITS_ACTIVE,
        "driver" => driver.as_str(),
    )
    .increment(1.0);
    AwaitWaitsGuard { driver }
}

pub(crate) struct AwaitWaitsGuard {
    driver: DriverKind,
}

impl Drop for AwaitWaitsGuard {
    fn drop(&mut self) {
        gauge!(
            names::AWAIT_WAITS_ACTIVE,
            "driver" => self.driver.as_str(),
        )
        .decrement(1.0);
    }
}

/// Bump the await-wakes counter. One call per poll, with the
/// `kind` label distinguishing terminal outcomes from intermediate
/// "spurious" wakes (the predicate didn't match, but we'll loop
/// again). Operators chart `rate(spurious) / rate(matched+timeout)`
/// to spot wait blocks whose poll interval is too aggressive.
pub(crate) fn record_await_wake(binding: &str, driver: DriverKind, kind: &'static str) {
    counter!(
        names::AWAIT_WAKES,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
        "kind" => kind,
    )
    .increment(1);
}

/// Record total await wall-clock duration. One call per loop
/// at terminal outcome — `matched` or `timeout`. The `outcome`
/// label lets operators distinguish happy-path latency from the
/// (configured) timeout ceiling.
pub(crate) fn record_await_duration(
    binding: &str,
    driver: DriverKind,
    outcome: &'static str,
    duration: Duration,
) {
    histogram!(
        names::AWAIT_DURATION_SECONDS,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
        "outcome" => outcome,
    )
    .record(duration.as_secs_f64());
}

/// Bump the progress-heartbeat counter. Emitted by the heartbeat
/// task once per `progress_heartbeat_ms` interval while a query is
/// in flight. Gives operators a "query still running" signal via
/// Prometheus even when the gateway hasn't yet wired through the MCP
/// progressToken sink.
pub(crate) fn record_progress_heartbeat(binding: &str, driver: DriverKind) {
    counter!(
        names::PROGRESS_HEARTBEATS,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
    )
    .increment(1);
}

/// Bump the response-cache hit counter. One call per
/// `execute()` that returned a cached response without touching the
/// driver.
pub(crate) fn record_cache_hit(binding: &str, driver: DriverKind) {
    counter!(
        names::CACHE_HITS,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
    )
    .increment(1);
}

/// Bump the response-cache miss counter. One call per
/// `execute()` that consulted the cache, didn't find a match, and
/// fell through to the driver.
pub(crate) fn record_cache_miss(binding: &str, driver: DriverKind) {
    counter!(
        names::CACHE_MISSES,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
    )
    .increment(1);
}

/// Bump the response-cache write counter. One call per
/// successful `cache_put` after a miss + driver-execute. Failures
/// (transport / serialization) are debug-logged and don't bump
/// this counter.
pub(crate) fn record_cache_write(binding: &str, driver: DriverKind) {
    counter!(
        names::CACHE_WRITES,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
    )
    .increment(1);
}

/// Record a successful per-call charge. Bumps the
/// micro-unit counter and records the decimal amount in the
/// per-call histogram. Both metrics carry the operator-declared
/// currency so cross-currency aggregation is the operator's
/// responsibility (the `currency` label keeps reading clean).
pub(crate) fn record_cost(
    binding: &str,
    driver: DriverKind,
    currency: &str,
    unit: crate::config::CostUnit,
    amount: f64,
) {
    // Counter: micro-units, saturating on overflow. We round to
    // nearest to keep cumulative drift below 0.5 µunit/call.
    let micro = if amount.is_finite() && amount >= 0.0 {
        (amount * 1_000_000.0).round().min(u64::MAX as f64) as u64
    } else {
        0
    };
    counter!(
        names::COST_TOTAL,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
        "currency" => currency.to_owned(),
        "unit" => unit.as_str(),
    )
    .increment(micro);
    histogram!(
        names::CALL_COST,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
        "currency" => currency.to_owned(),
        "unit" => unit.as_str(),
    )
    .record(amount);
}

/// Record a refund signal on a non-success terminal outcome.
/// Same micro-unit shape as [`record_cost`]; the
/// `reason` label distinguishes timeout / transport / breaker
/// /etc. Reasons are a finite closed set defined by the caller
/// so cardinality stays bounded.
pub(crate) fn record_cost_refunded(
    binding: &str,
    driver: DriverKind,
    currency: &str,
    reason: &'static str,
    amount: f64,
) {
    let micro = if amount.is_finite() && amount >= 0.0 {
        (amount * 1_000_000.0).round().min(u64::MAX as f64) as u64
    } else {
        0
    };
    counter!(
        names::COST_REFUNDED,
        "backend" => binding.to_owned(),
        "driver" => driver.as_str(),
        "currency" => currency.to_owned(),
        "reason" => reason,
    )
    .increment(micro);
}

/// Status label for `calls_total`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CallStatus {
    /// Query ran and returned rows / affected-count successfully.
    Success,
    /// Deadline (server- or client-side) exceeded.
    Timeout,
    /// Transport-class failure — connect refused, drop mid-query, etc.
    TransportError,
    /// Config-class failure — bad spec, missing param.
    InvalidSpec,
}

impl CallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::InvalidSpec => "invalid_spec",
        }
    }
}
