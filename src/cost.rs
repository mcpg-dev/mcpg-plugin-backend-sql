//! Per-binding cost / billing telemetry.
//!
//! ## Why this lives in the binding plugin (and not in a payment plugin)
//!
//! MCPG already ships four payment-protocol plugins
//! (`dev.mcpg.payment.{mpp,x402,ucp,acp}`) that gate `tools/call` at
//! the **gateway dispatch layer** via their `ToolGatePlugin` impl.
//! Those plugins issue HTTP-402 challenges, verify credentials in
//! `_meta`, and attach receipts to the result `_meta` — they sit
//! between the policy gate and the binding executor and never look
//! inside a binding's response.
//!
//! That model is great for per-call charges with a flat or
//! arg-derived price (the four payment plugins all support that).
//! It is **not** sufficient for SQL bindings, which want to charge
//! based on **post-execution** facts:
//!
//! * `per_row` — pay per returned row (think "1¢ per record served")
//! * `per_byte` — pay per response payload byte (think "egress fee")
//! * `per_call` — flat per execution (the same shape the payment
//!   plugins already model, repeated here for symmetry)
//! * `per_query` — alias of `per_call`, named for ops clarity when
//!   the binding represents a logical "query" rather than a single
//!   `tools/call`
//!
//! Per-row / per-byte amounts are not knowable at challenge-issuance
//! time, so we don't attempt to retrofit them onto the existing
//! pre-dispatch payment gate. Instead, the SQL plugin computes the
//! actual charge **after** the driver returns and emits structured
//! billing telemetry: counters, histograms, and a `tracing::info!`
//! event on `mcpg::sql::cost`. Downstream billing systems (or the
//! same 4 payment plugins, configured to log rather than gate)
//! reconcile against this stream.
//!
//! ## Refund accounting on timeout-returning-current
//!
//! When the SQL plugin returns `BackendError::Timeout` or
//! `BackendError::Transport`, the operator typically wants to
//! **refund** any amount the gateway-side payment plugin would
//! have collected — the call did not produce a successful result.
//! For per-call shapes the operator's billing system can already
//! handle this from the gateway audit log; for per-row/per-byte
//! shapes we record an explicit refund signal:
//!
//! * `mcpg_sql_cost_refunded_total{binding,driver,currency,reason}`
//!   counter increments (in micro-units of the configured currency)
//!   on every error path. The amount carries forward the **base
//!   per-call rate** (or a `0` for purely per-row/per-byte shapes
//!   where no per-call floor exists), so reconciliation pipelines
//!   know how much to credit back.
//!
//! ## Cluster correctness
//!
//! Cost metrics aggregate across instances via the gateway's
//! existing Prometheus / OTLP recorder. No state is held in the
//! binding plugin itself — every cost computation is per-call and
//! emitted immediately. Hot reload re-compiles the CEL expression;
//! in-flight calls finish on the prior cost spec via the cloned
//! `ProfileRuntime`.

use std::collections::BTreeMap;

use serde_json::Value;
use tracing::{info, warn};

use crate::config::{CostSpec, CostUnit};
use crate::errors::SqlError;
use crate::metrics::record_cost;

/// Compiled per-binding cost spec — what `ProfileRuntime` actually
/// holds. The CEL program is `Arc`-shared (cel::Program isn't
/// `Clone`) so cloning the runtime stays cheap.
#[derive(Debug)]
pub struct BackendCost {
    pub unit: CostUnit,
    pub currency: String,
    /// `None` → use `expression`. `Some(amount)` → static literal
    /// already validated as a positive finite f64.
    pub amount: Option<f64>,
    /// Compiled CEL — only set when the operator declared
    /// `expression`. Variables: `arguments` (object).
    pub expression: Option<std::sync::Arc<cel::Program>>,
    /// Verbatim source for diagnostics + audit metadata. Same value
    /// the operator wrote in YAML.
    pub source: String,
    /// Optional cap in the operator-declared currency. When the
    /// per-call computed amount exceeds this, the call is **refused**
    /// with `InvalidSpec` (defensive — protects against runaway
    /// charges from misconfigured CEL or a flood of rows).
    pub max_per_call: Option<f64>,
}

impl Clone for BackendCost {
    fn clone(&self) -> Self {
        Self {
            unit: self.unit,
            currency: self.currency.clone(),
            amount: self.amount,
            expression: self.expression.as_ref().map(std::sync::Arc::clone),
            source: self.source.clone(),
            max_per_call: self.max_per_call,
        }
    }
}

impl BackendCost {
    /// Compile a [`CostSpec`] into the runtime form. Validation has
    /// already accepted shape-level invariants (`exactly one of
    /// amount / expression`, currency not empty, …); here we only
    /// turn the literal amount into f64 and the expression into a
    /// `cel::Program`.
    pub fn compile(spec: &CostSpec) -> Result<Self, SqlError> {
        let amount = match spec.amount.as_deref() {
            Some(s) => Some(parse_decimal_amount(s, "cost.amount")?),
            None => None,
        };
        let expression = match spec.expression.as_deref() {
            Some(src) => {
                let program = cel::Program::compile(src).map_err(|e| {
                    SqlError::InvalidSpec(format!("cost.expression does not compile as CEL: {e}"))
                })?;
                Some(std::sync::Arc::new(program))
            }
            None => None,
        };
        let max_per_call = match spec.max_per_call.as_deref() {
            Some(s) => Some(parse_decimal_amount(s, "cost.max_per_call")?),
            None => None,
        };
        // Pick the more useful of (literal | expression) for the
        // diagnostic source string. Validation guarantees exactly
        // one is set.
        let source = spec
            .amount
            .clone()
            .or_else(|| spec.expression.clone())
            .unwrap_or_default();
        Ok(Self {
            unit: spec.unit,
            currency: spec.currency.clone(),
            amount,
            expression,
            source,
            max_per_call,
        })
    }

    /// Compute the charge for one successful call.
    ///
    /// * For `PerCall` / `PerQuery`, returns the base rate.
    /// * For `PerRow`, returns base × `row_count`.
    /// * For `PerByte`, returns base × `payload_bytes`.
    ///
    /// `arguments` is the caller's tool args (object or null) used
    /// only when the operator declared a CEL expression. The CEL
    /// expression is evaluated once per call regardless of unit —
    /// the result is the **base rate**, then amplified by the unit.
    ///
    /// Returns `Err(InvalidSpec)` when the resolved amount is not
    /// a positive finite number, or when `max_per_call` is set and
    /// the computed total exceeds it. The caller surfaces both as
    /// hard refusals — overcharging is worse than rate-limiting.
    pub fn compute(
        &self,
        arguments: &Value,
        row_count: u64,
        payload_bytes: u64,
    ) -> Result<f64, SqlError> {
        let base = self.resolve_base(arguments)?;
        let amplified = match self.unit {
            CostUnit::PerCall | CostUnit::PerQuery => base,
            CostUnit::PerRow => base * (row_count as f64),
            CostUnit::PerByte => base * (payload_bytes as f64),
        };
        if !amplified.is_finite() || amplified < 0.0 {
            return Err(SqlError::InvalidSpec(format!(
                "cost computed to non-finite or negative amount {amplified} \
                 (base={base}, unit={}, rows={row_count}, bytes={payload_bytes})",
                self.unit.as_str()
            )));
        }
        if let Some(cap) = self.max_per_call
            && amplified > cap
        {
            return Err(SqlError::InvalidSpec(format!(
                "cost {amplified} {currency} exceeds cost.max_per_call \
                 ({cap} {currency}); refusing the call",
                currency = self.currency,
            )));
        }
        Ok(amplified)
    }

    /// Resolve the base rate from either the literal `amount` or
    /// the CEL `expression`. Keeps the CEL evaluation step away
    /// from the metric-emission caller.
    fn resolve_base(&self, arguments: &Value) -> Result<f64, SqlError> {
        if let Some(amt) = self.amount {
            return Ok(amt);
        }
        let program = self.expression.as_ref().ok_or_else(|| {
            SqlError::InvalidSpec(
                "cost spec has neither amount nor expression — should be unreachable".into(),
            )
        })?;
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value("arguments", crate::cel_value_from_json(arguments));
        let result = program.execute(&ctx).map_err(|e| {
            SqlError::InvalidSpec(format!(
                "cost.expression evaluation failed: {e} (source: {})",
                self.source,
            ))
        })?;
        cel_value_to_f64(&result).ok_or_else(|| {
            SqlError::InvalidSpec(format!(
                "cost.expression must evaluate to a positive number, got {result:?} \
                 (source: {})",
                self.source,
            ))
        })
    }

    /// Audit-metadata fields for this binding's cost configuration.
    /// Surfaced under the `db.cost.*` namespace via the existing
    /// `audit_metadata()` hook so audit search can filter on
    /// `db.cost.unit=per_row`.
    pub fn audit_fields(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert(
            "db.cost.unit".into(),
            Value::String(self.unit.as_str().into()),
        );
        m.insert(
            "db.cost.currency".into(),
            Value::String(self.currency.clone()),
        );
        m.insert("db.cost.source".into(), Value::String(self.source.clone()));
        if let Some(cap) = self.max_per_call {
            m.insert(
                "db.cost.max_per_call".into(),
                Value::String(format_amount(cap)),
            );
        }
        m
    }
}

/// Emit the cost-recorded metrics + tracing event for a successful
/// call. Splitting this from `BackendCost::compute` keeps the
/// pure-function arithmetic testable without touching the metrics
/// recorder; the runtime hot path calls both in sequence.
pub(crate) fn emit_charge(
    backend_name: &str,
    driver: crate::config::DriverKind,
    cost: &BackendCost,
    amount: f64,
    row_count: u64,
    payload_bytes: u64,
) {
    record_cost(backend_name, driver, &cost.currency, cost.unit, amount);
    info!(
        target: "mcpg::sql::cost",
        backend = %backend_name,
        driver = driver.as_str(),
        unit = cost.unit.as_str(),
        currency = %cost.currency,
        amount = %format_amount(amount),
        rows = row_count,
        bytes = payload_bytes,
        "sql cost recorded"
    );
}

/// Emit the refund accounting metric on a non-success terminal
/// outcome. The amount is the per-call **base rate** (or 0 when
/// the unit is purely per-row/per-byte and there's no flat floor).
/// Operators reconciling charges vs. refunds use the `reason`
/// label to distinguish:
///
/// * `timeout` — the call did not complete within `query.timeout_ms`
/// * `transport` — driver / pool transport failure
/// * `invalid_spec` — the request was rejected (validation, params)
/// * `breaker_open` — circuit breaker short-circuited
/// * `cancelled` — caller-side cancellation
///
/// The base rate is computed against the call's args even when the
/// expression branch was unreachable — failing to compute the base
/// just yields a `0` refund amount and a warn log. That's the
/// conservative choice: better to record the refund signal with
/// amount=0 than swallow the event entirely.
pub(crate) fn emit_refund(
    backend_name: &str,
    driver: crate::config::DriverKind,
    cost: &BackendCost,
    arguments: &Value,
    reason: &'static str,
) {
    let amount = match cost.unit {
        CostUnit::PerCall | CostUnit::PerQuery => {
            cost.resolve_base(arguments).unwrap_or_else(|e| {
                warn!(
                    backend = %backend_name,
                    error = %e,
                    "sql cost refund: base resolution failed; recording amount=0"
                );
                0.0
            })
        }
        CostUnit::PerRow | CostUnit::PerByte => 0.0, // no flat floor
    };
    crate::metrics::record_cost_refunded(backend_name, driver, &cost.currency, reason, amount);
    info!(
        target: "mcpg::sql::cost",
        backend = %backend_name,
        driver = driver.as_str(),
        unit = cost.unit.as_str(),
        currency = %cost.currency,
        amount = %format_amount(amount),
        reason = reason,
        "sql cost refund recorded"
    );
}

/// Parse a decimal-string amount into a non-negative finite f64.
/// Centralised so config validation and `BackendCost::compile` use
/// identical rules.
pub(crate) fn parse_decimal_amount(s: &str, field: &str) -> Result<f64, SqlError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SqlError::InvalidSpec(format!("{field} must not be empty")));
    }
    let v: f64 = trimmed.parse().map_err(|e| {
        SqlError::InvalidSpec(format!("{field} '{trimmed}' is not a valid decimal: {e}"))
    })?;
    if !v.is_finite() {
        return Err(SqlError::InvalidSpec(format!(
            "{field} '{trimmed}' is not a finite number"
        )));
    }
    if v < 0.0 {
        return Err(SqlError::InvalidSpec(format!(
            "{field} '{trimmed}' must be non-negative"
        )));
    }
    Ok(v)
}

/// Coerce a CEL result into f64 if possible. Accepts Int / UInt /
/// Float; rejects everything else (operator must return a number).
fn cel_value_to_f64(v: &cel::Value) -> Option<f64> {
    match v {
        cel::Value::Int(i) => Some(*i as f64),
        cel::Value::UInt(u) => Some(*u as f64),
        cel::Value::Float(f) => Some(*f),
        cel::Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

/// Format an f64 amount for human-readable logs / audit metadata.
/// We format with up to 6 fractional digits and trim trailing
/// zeros so amounts like `1.0` render as `"1"` and `0.000001` as
/// `"0.000001"`. This avoids scientific notation and keeps the
/// audit lane consistent across very small / very large amounts.
fn format_amount(v: f64) -> String {
    let mut s = format!("{v:.6}");
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CostUnit;
    use serde_json::json;

    fn flat_cost(unit: CostUnit, amount: f64, currency: &str) -> BackendCost {
        BackendCost {
            unit,
            currency: currency.into(),
            amount: Some(amount),
            expression: None,
            source: amount.to_string(),
            max_per_call: None,
        }
    }

    #[test]
    fn per_call_returns_base_regardless_of_rows() {
        let c = flat_cost(CostUnit::PerCall, 0.10, "USD");
        assert_eq!(c.compute(&json!({}), 0, 0).unwrap(), 0.10);
        assert_eq!(c.compute(&json!({}), 1_000_000, 1_000_000).unwrap(), 0.10);
    }

    #[test]
    fn per_row_amplifies_by_count() {
        let c = flat_cost(CostUnit::PerRow, 0.001, "USD");
        // 250 rows × 0.001 = 0.25
        let v = c.compute(&json!({}), 250, 999_999).unwrap();
        assert!((v - 0.25).abs() < 1e-9);
    }

    #[test]
    fn per_byte_amplifies_by_payload_size() {
        let c = flat_cost(CostUnit::PerByte, 0.000001, "USD");
        // 1 MiB payload × 1µ¢/byte ≈ 1.04 USD
        let v = c.compute(&json!({}), 0, 1_048_576).unwrap();
        assert!((v - 1.048576).abs() < 1e-9);
    }

    #[test]
    fn max_per_call_refuses_overcharge() {
        let mut c = flat_cost(CostUnit::PerRow, 0.001, "USD");
        c.max_per_call = Some(0.50);
        // 600 rows × 0.001 = 0.60 → exceeds cap
        let err = c.compute(&json!({}), 600, 0).unwrap_err();
        assert!(
            matches!(&err, SqlError::InvalidSpec(m) if m.contains("max_per_call")),
            "expected cap rejection, got: {err:?}"
        );
    }

    #[test]
    fn cel_expression_evaluates_against_args() {
        let program = cel::Program::compile("arguments.tier == \"pro\" ? 1.00 : 0.10").unwrap();
        let c = BackendCost {
            unit: CostUnit::PerCall,
            currency: "USD".into(),
            amount: None,
            expression: Some(std::sync::Arc::new(program)),
            source: "(tier expr)".into(),
            max_per_call: None,
        };
        let v_pro = c.compute(&json!({"tier": "pro"}), 0, 0).unwrap();
        let v_free = c.compute(&json!({"tier": "free"}), 0, 0).unwrap();
        assert!((v_pro - 1.00).abs() < 1e-9);
        assert!((v_free - 0.10).abs() < 1e-9);
    }

    #[test]
    fn cel_non_numeric_result_rejected() {
        let program = cel::Program::compile("\"not-a-number\"").unwrap();
        let c = BackendCost {
            unit: CostUnit::PerCall,
            currency: "USD".into(),
            amount: None,
            expression: Some(std::sync::Arc::new(program)),
            source: "(string expr)".into(),
            max_per_call: None,
        };
        // String doesn't parse as f64, so we expect an error.
        let err = c.compute(&json!({}), 0, 0).unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(_)));
    }

    #[test]
    fn parse_decimal_rejects_negative() {
        let err = parse_decimal_amount("-1.50", "cost.amount").unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("non-negative")));
    }

    #[test]
    fn parse_decimal_rejects_non_finite() {
        let err = parse_decimal_amount("inf", "cost.amount").unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("finite")));
    }

    #[test]
    fn parse_decimal_rejects_empty() {
        let err = parse_decimal_amount("   ", "cost.amount").unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(m) if m.contains("not be empty")));
    }

    #[test]
    fn audit_fields_render_minimal_set() {
        let c = flat_cost(CostUnit::PerRow, 0.001, "USD");
        let m = c.audit_fields();
        assert_eq!(m.get("db.cost.unit").unwrap(), &json!("per_row"));
        assert_eq!(m.get("db.cost.currency").unwrap(), &json!("USD"));
        assert!(m.contains_key("db.cost.source"));
        assert!(!m.contains_key("db.cost.max_per_call"), "no cap → no field");
    }

    #[test]
    fn audit_fields_include_max_per_call_when_set() {
        let mut c = flat_cost(CostUnit::PerRow, 0.001, "USD");
        c.max_per_call = Some(2.50);
        let m = c.audit_fields();
        // Cap should round-trip through the trim-trailing-zeros formatter.
        assert_eq!(m.get("db.cost.max_per_call").unwrap(), &json!("2.5"));
    }

    #[test]
    fn format_amount_trims_trailing_zeros() {
        assert_eq!(format_amount(1.0), "1");
        assert_eq!(format_amount(1.5), "1.5");
        assert_eq!(format_amount(0.000001), "0.000001");
        assert_eq!(format_amount(0.123456789), "0.123457"); // 6 dp cap
    }
}
