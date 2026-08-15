//! CEL-computed parameters for SQL bindings.
//!
//! Operators declare `param_exprs: { name: "<CEL expression>" }` on a
//! query. At `register_profile` time the plugin compiles each
//! expression once; at execute time it evaluates every expression
//! against the call's argument object and injects the result back
//! into the argument map under the named key. Placeholder binding
//! then proceeds through the usual `collect_bound_params` path.
//!
//! # Available variables
//!
//! The first cut exposes just `arguments` — the JSON argument object
//! the caller supplied. That covers the common pattern of computing
//! one param from another: `limit: "arguments.page_size * 2"`. Full
//! principal / env context (`$context.principal_id`, `$env.*`)
//! requires `BackendRequest` to carry an identity snapshot; that
//! extension is deliberately deferred to keep this a scoped,
//! plugin-local change.
//!
//! # Collision policy
//!
//! If an expression name matches a key already present in
//! `arguments`, the CEL-computed value **overrides** the caller's
//! value. This matches the operator intent: param_exprs are
//! server-side derivations (e.g. tenant injection) and shouldn't be
//! overridable by client input. A `tracing::warn!` is emitted so
//! operators spot accidental collisions at config-review time.

use std::collections::BTreeMap;

use cel::{Context as CelContext, Program, Value as CelValue};
use serde_json::Value;

use crate::errors::SqlError;

/// A compiled `param_exprs` entry — the declared name and the
/// compiled CEL program. `cel::Program` isn't `Clone`; the
/// [`crate::ProfileRuntime`] shares these through an `Arc<Vec<_>>`.
#[derive(Debug)]
pub struct ParamExpr {
    /// Declared target key in the args map.
    pub name: String,
    /// Compiled CEL program — evaluated per call.
    pub program: Program,
    /// Original source, retained for diagnostics.
    pub source: String,
}

/// Compile every expression in the operator's `param_exprs` map.
/// Ordering follows the map's natural (BTreeMap) order, which makes
/// error messages deterministic.
pub fn compile_all(exprs: &BTreeMap<String, String>) -> Result<Vec<ParamExpr>, SqlError> {
    let mut out = Vec::with_capacity(exprs.len());
    for (name, source) in exprs {
        let program = Program::compile(source).map_err(|e| {
            SqlError::InvalidSpec(format!(
                "param_exprs['{name}'] does not compile as CEL: {e}"
            ))
        })?;
        out.push(ParamExpr {
            name: name.clone(),
            program,
            source: source.clone(),
        });
    }
    Ok(out)
}

/// Evaluate every compiled expression against the call's arguments
/// and inject results into the args map. Overwrites existing keys —
/// param_exprs win over caller-supplied values for the same name (and
/// we log at warn when that happens so operators can audit).
pub fn evaluate_into(args: &mut Value, exprs: &[ParamExpr]) -> Result<(), SqlError> {
    if exprs.is_empty() {
        return Ok(());
    }
    // Normalize `args` to an object for key-based injection. `null`
    // (no args supplied) becomes `{}`.
    if matches!(args, Value::Null) {
        *args = Value::Object(serde_json::Map::new());
    }
    let obj = match args {
        Value::Object(o) => o,
        _ => {
            return Err(SqlError::InvalidSpec(format!(
                "param_exprs require an object-shaped args payload; got {}",
                type_name(args)
            )));
        }
    };
    // Rebuild the CEL snapshot per expression so later exprs can
    // reference earlier ones' results through `arguments.<name>`.
    // Iteration order is the BTreeMap's (alphabetical), so chained
    // derivations are deterministic — document it in the config
    // example if operators start relying on it.
    for expr in exprs {
        let args_cel = json_to_cel(&Value::Object(obj.clone()));
        let mut ctx = CelContext::default();
        ctx.add_variable("arguments", args_cel).map_err(|e| {
            SqlError::InvalidSpec(format!("param_exprs['{}']: bind arguments: {e}", expr.name))
        })?;
        let out = expr.program.execute(&ctx).map_err(|e| {
            SqlError::InvalidSpec(format!(
                "param_exprs['{}'] failed: {e} (source: {})",
                expr.name, expr.source
            ))
        })?;
        let json_value = cel_to_json(out);
        if obj.contains_key(&expr.name) {
            tracing::warn!(
                param = %expr.name,
                "caller-supplied value for '{}' overridden by param_exprs",
                expr.name
            );
        }
        obj.insert(expr.name.clone(), json_value);
    }
    Ok(())
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Convert a serde_json Value to a CEL Value. Recursive.
fn json_to_cel(v: &Value) -> CelValue {
    use cel::objects::{Key as CelKey, Map as CelMap};
    use std::sync::Arc;
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
                CelValue::String(Arc::new(n.to_string()))
            }
        }
        Value::String(s) => CelValue::String(Arc::new(s.clone())),
        Value::Array(arr) => CelValue::List(Arc::new(arr.iter().map(json_to_cel).collect())),
        Value::Object(map) => {
            let mut out = std::collections::HashMap::new();
            for (k, v) in map {
                out.insert(CelKey::String(Arc::new(k.clone())), json_to_cel(v));
            }
            CelValue::Map(CelMap { map: Arc::new(out) })
        }
    }
}

/// Convert a CEL Value to a serde_json Value. Lossy for types that
/// don't have JSON equivalents (bytes → base64 string; duration /
/// timestamp → string). Matches the gateway's coercion conventions.
fn cel_to_json(v: CelValue) -> Value {
    match v {
        CelValue::Null => Value::Null,
        CelValue::Bool(b) => Value::Bool(b),
        CelValue::Int(i) => Value::Number(i.into()),
        CelValue::UInt(u) => Value::Number(u.into()),
        CelValue::Float(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        CelValue::String(s) => Value::String(s.as_ref().clone()),
        CelValue::Bytes(b) => {
            use base64::Engine as _;
            Value::String(base64::engine::general_purpose::STANDARD.encode(b.as_ref()))
        }
        CelValue::List(items) => {
            Value::Array(items.iter().map(|v| cel_to_json(v.clone())).collect())
        }
        CelValue::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in m.map.iter() {
                let key = match k {
                    cel::objects::Key::String(s) => s.as_ref().clone(),
                    cel::objects::Key::Int(i) => i.to_string(),
                    cel::objects::Key::Uint(u) => u.to_string(),
                    cel::objects::Key::Bool(b) => b.to_string(),
                };
                obj.insert(key, cel_to_json(v.clone()));
            }
            Value::Object(obj)
        }
        CelValue::Duration(d) => Value::String(d.to_string()),
        CelValue::Timestamp(t) => Value::String(t.to_rfc3339()),
        // Types we don't explicitly map fall through to string-ified
        // debug form. Unexpected but safer than panicking.
        other => Value::String(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(name: &str, src: &str) -> Vec<ParamExpr> {
        let mut m = BTreeMap::new();
        m.insert(name.to_string(), src.to_string());
        compile_all(&m).unwrap()
    }

    #[test]
    fn compile_rejects_invalid_cel() {
        let mut m = BTreeMap::new();
        m.insert("bad".into(), "this is not cel (((".into());
        let err = compile_all(&m).unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(msg) if msg.contains("bad")));
    }

    #[test]
    fn evaluate_computes_integer_from_arguments() {
        let exprs = one("limit", "arguments.page_size * 2");
        let mut args = json!({ "page_size": 50 });
        evaluate_into(&mut args, &exprs).unwrap();
        assert_eq!(args["limit"], json!(100));
    }

    #[test]
    fn evaluate_computes_string_conditional() {
        let exprs = one("mode", "arguments.verbose ? 'full' : 'compact'");
        let mut args = json!({ "verbose": true });
        evaluate_into(&mut args, &exprs).unwrap();
        assert_eq!(args["mode"], "full");
    }

    #[test]
    fn param_exprs_override_caller_supplied_value() {
        // Security-relevant: server-side derivations (tenant
        // injection etc.) must not be spoofable by client input.
        let exprs = one("tenant", "'server-enforced'");
        let mut args = json!({ "tenant": "attacker-spoofed" });
        evaluate_into(&mut args, &exprs).unwrap();
        assert_eq!(args["tenant"], "server-enforced");
    }

    #[test]
    fn evaluate_handles_null_args() {
        // `args = null` is a valid BackendRequest payload (no args).
        // param_exprs should still evaluate against an empty object.
        let exprs = one("greeting", "'hello'");
        let mut args = Value::Null;
        evaluate_into(&mut args, &exprs).unwrap();
        assert_eq!(args["greeting"], "hello");
    }

    #[test]
    fn evaluate_rejects_non_object_args() {
        let exprs = one("x", "1");
        let mut args = json!([1, 2, 3]);
        let err = evaluate_into(&mut args, &exprs).unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(msg) if msg.contains("array")));
    }

    #[test]
    fn evaluate_reports_runtime_failure_source() {
        // Runtime CEL failure (e.g. field access on null) should
        // surface the expression source so operators can debug.
        let exprs = one("bad", "arguments.missing.deeply.nested");
        let mut args = json!({});
        let err = evaluate_into(&mut args, &exprs).unwrap_err();
        assert!(matches!(&err, SqlError::InvalidSpec(msg)
                if msg.contains("bad") && msg.contains("arguments.missing")));
    }

    #[test]
    fn evaluate_deterministic_order_via_btree() {
        // BTreeMap iteration is alphabetical, so compilation +
        // evaluation order is deterministic. Later exprs can
        // depend on earlier ones through the shared args map.
        let mut m = BTreeMap::new();
        m.insert("a".to_string(), "arguments.base".to_string());
        m.insert("b".to_string(), "arguments.a + 1".to_string());
        let exprs = compile_all(&m).unwrap();
        let mut args = json!({ "base": 10 });
        evaluate_into(&mut args, &exprs).unwrap();
        assert_eq!(args["a"], 10);
        assert_eq!(args["b"], 11);
    }
}
