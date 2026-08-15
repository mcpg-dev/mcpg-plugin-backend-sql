//! Parameter handling: placeholder rewriting and JSON → driver value
//! coercion.
//!
//! Named (`:name`) placeholders are rewritten at registration time to the
//! driver-native positional form (`$1..$N` for Postgres, `?` for
//! MySQL/SQLite). Positional forms (`$1`, `?`) pass through as-is. This
//! keeps runtime binding dirt cheap — we only walk the placeholder list
//! once.

use serde_json::Value;

use crate::config::DriverKind;
use crate::errors::SqlError;

/// A single argument to bind at execution time, after JSON coercion.
///
/// The value is carried as raw JSON and re-encoded per driver in
/// each adapter. A more aggressive path (precomputed `sqlx::Encode`
/// trait objects) is a possible future optimization.
#[derive(Debug, Clone)]
pub struct BoundParam {
    /// Name of the tool argument this value came from. Used for error
    /// messages only.
    pub name: String,
    /// JSON value handed off to the driver.
    pub value: Value,
}

/// Prepared statement: the rewritten SQL plus the ordered parameter
/// names.
///
/// The rewritten SQL uses the driver's native placeholder shape; the
/// `param_order` list is in the order in which the driver expects
/// arguments (matches left-to-right occurrences of `:name` in the
/// original SQL, or the declared `params` order for positional input).
#[derive(Debug, Clone)]
pub struct PreparedStmt {
    /// SQL statement with driver-native placeholders.
    pub sql: String,
    /// Ordered parameter names.
    pub param_order: Vec<String>,
    /// Driver the SQL was rewritten for. Used by adapters to decide
    /// how to bind.
    pub driver: DriverKind,
}

/// Rewrite `:name`-style named placeholders to the driver's native
/// form.
///
/// - Postgres → `$1..$N`
/// - MySQL/MariaDB/SQLite → `?`
///
/// A fresh rewrite happens once at registration time. The returned
/// `param_order` matches the left-to-right occurrence of each `:name`
/// — the driver binds arguments in that order.
///
/// Placeholders that appear inside a single-quoted SQL string literal
/// are left untouched (naive lexer — fine for 99% of operator SQL).
/// Table/column identifiers cannot appear as `:name` placeholders;
/// this function does not try to enforce that.
pub fn rewrite_placeholders(sql: &str, driver: DriverKind) -> (String, Vec<String>) {
    let mut out = String::with_capacity(sql.len());
    let mut order: Vec<String> = Vec::new();
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                out.push(c as char);
                i += 1;
            }
            b'"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                out.push(c as char);
                i += 1;
            }
            b':' if !in_single_quote && !in_double_quote => {
                // `::` is a Postgres cast, not a placeholder.
                if i + 1 < bytes.len() && bytes[i + 1] == b':' {
                    out.push(':');
                    out.push(':');
                    i += 2;
                    continue;
                }
                // Collect the identifier that follows.
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j == start {
                    // lone `:` with nothing after — keep as literal
                    out.push(':');
                    i += 1;
                    continue;
                }
                let name = std::str::from_utf8(&bytes[start..j])
                    .expect("ASCII range enforced by predicate")
                    .to_string();
                match driver {
                    DriverKind::Postgres => {
                        order.push(name);
                        out.push('$');
                        out.push_str(&order.len().to_string());
                    }
                    DriverKind::Mysql | DriverKind::Mariadb | DriverKind::Sqlite => {
                        order.push(name);
                        out.push('?');
                    }
                }
                i = j;
            }
            other => {
                out.push(other as char);
                i += 1;
            }
        }
    }
    (out, order)
}

/// Wrap a procedure name into the driver-appropriate `CALL` statement.
///
/// The procedure is called with `arity` positional placeholders in
/// driver-native shape. Returns the SQL string; the caller is
/// responsible for preserving the `params` order for binding.
pub fn call_statement(procedure: &str, arity: usize, driver: DriverKind) -> String {
    let placeholders: Vec<String> = (1..=arity)
        .map(|i| match driver {
            DriverKind::Postgres => format!("${i}"),
            DriverKind::Mysql | DriverKind::Mariadb | DriverKind::Sqlite => "?".to_string(),
        })
        .collect();
    format!("CALL {procedure}({})", placeholders.join(", "))
}

/// Pull `BoundParam`s out of the caller's JSON argument map in the
/// order the prepared statement expects.
///
/// Missing required params are an `InvalidSpec` carrying the argument
/// name. JSON `null` is accepted and bound as SQL NULL.
pub fn collect_bound_params(
    args: &Value,
    param_order: &[String],
) -> Result<Vec<BoundParam>, SqlError> {
    let obj = match args {
        Value::Object(map) => map,
        Value::Null => {
            if param_order.is_empty() {
                return Ok(vec![]);
            }
            return Err(SqlError::InvalidSpec(format!(
                "tool arguments must be an object when parameters are declared; missing '{}'",
                param_order[0]
            )));
        }
        _ => {
            return Err(SqlError::InvalidSpec(
                "tool arguments must be a JSON object".into(),
            ));
        }
    };
    let mut out = Vec::with_capacity(param_order.len());
    for name in param_order {
        match obj.get(name) {
            Some(value) => out.push(BoundParam {
                name: name.clone(),
                value: value.clone(),
            }),
            None => {
                return Err(SqlError::InvalidSpec(format!(
                    "missing required parameter '{name}'"
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_named_to_postgres() {
        let (sql, order) = rewrite_placeholders(
            "SELECT * FROM users WHERE id = :user_id AND tenant = :tenant",
            DriverKind::Postgres,
        );
        assert_eq!(sql, "SELECT * FROM users WHERE id = $1 AND tenant = $2");
        assert_eq!(order, vec!["user_id".to_string(), "tenant".into()]);
    }

    #[test]
    fn rewrite_named_to_mysql() {
        let (sql, order) = rewrite_placeholders(
            "SELECT * FROM users WHERE id = :id AND tenant = :tenant",
            DriverKind::Mysql,
        );
        assert_eq!(sql, "SELECT * FROM users WHERE id = ? AND tenant = ?");
        assert_eq!(order, vec!["id".to_string(), "tenant".into()]);
    }

    #[test]
    fn rewrite_preserves_postgres_cast_operator() {
        let (sql, order) =
            rewrite_placeholders("SELECT id::text FROM t WHERE x = :x", DriverKind::Postgres);
        assert_eq!(sql, "SELECT id::text FROM t WHERE x = $1");
        assert_eq!(order, vec!["x".to_string()]);
    }

    #[test]
    fn rewrite_leaves_string_literals_alone() {
        let (sql, order) = rewrite_placeholders(
            "SELECT 'not :a placeholder' AS k WHERE id = :id",
            DriverKind::Postgres,
        );
        assert_eq!(sql, "SELECT 'not :a placeholder' AS k WHERE id = $1");
        assert_eq!(order, vec!["id".to_string()]);
    }

    #[test]
    fn rewrite_leaves_positional_unchanged() {
        let (sql, order) =
            rewrite_placeholders("SELECT * FROM t WHERE id = $1", DriverKind::Postgres);
        assert_eq!(sql, "SELECT * FROM t WHERE id = $1");
        assert!(order.is_empty());
    }

    #[test]
    fn call_statement_postgres() {
        assert_eq!(
            call_statement("orders.summary", 2, DriverKind::Postgres),
            "CALL orders.summary($1, $2)"
        );
    }

    #[test]
    fn call_statement_mysql() {
        assert_eq!(
            call_statement("summary", 3, DriverKind::Mysql),
            "CALL summary(?, ?, ?)"
        );
    }

    #[test]
    fn call_statement_no_args() {
        assert_eq!(
            call_statement("summary", 0, DriverKind::Sqlite),
            "CALL summary()"
        );
    }

    #[test]
    fn collect_bound_params_orders_by_declaration() {
        let args = serde_json::json!({"a": 1, "b": "x", "c": null});
        let got = collect_bound_params(&args, &["b".to_string(), "a".into(), "c".into()]).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].name, "b");
        assert_eq!(got[1].name, "a");
        assert!(got[2].value.is_null());
    }

    #[test]
    fn collect_bound_params_errors_on_missing() {
        let args = serde_json::json!({"a": 1});
        let err = collect_bound_params(&args, &["a".into(), "b".into()]).unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(msg) if msg.contains("b")));
    }

    #[test]
    fn collect_bound_params_accepts_empty_for_no_args() {
        let got = collect_bound_params(&serde_json::Value::Null, &[]).unwrap();
        assert!(got.is_empty());
    }
}
