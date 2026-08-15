//! JSON Schema derivation from prepared-statement metadata.
//!
//! MCP's `tools/list` shows an `inputSchema` for every tool. Operators
//! can always hand-author one in the binding spec, but for the common
//! case — `SELECT ... WHERE a = :x AND b = :y` — the schema is
//! mechanically derivable from the prepared statement's parameter
//! types. This module owns the derivation logic.
//!
//! Currently this ships **input-schema derivation for PostgreSQL**
//! only. MySQL / SQLite / output-schema derivation are follow-ups. The
//! Postgres path uses sqlx's `Executor::describe` (via the driver
//! adapter) to extract a `Vec<PgTypeInfo>` for the placeholders, then
//! maps each to a JSON Schema fragment.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Toggle for schema auto-derivation. Default: [`SchemaDerive::Off`].
///
/// Derivation is **additive** to operator-supplied schema: operator
/// fields override the derived ones. This module only emits the
/// derived half; the merge happens at config composition time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaDerive {
    /// Skip derivation. Operator-supplied schema, if any, is used
    /// verbatim. This is the default.
    #[default]
    Off,
    /// Derive `inputSchema` from the parameter metadata.
    Input,
    /// Derive `outputSchema` from the column metadata. Accepted at
    /// parse time so operator configs written for the full feature
    /// set still load even where the derivation is not yet wired.
    Output,
    /// Derive both input and output schemas.
    Both,
}

impl SchemaDerive {
    /// Whether the operator asked for input-schema derivation.
    pub fn includes_input(self) -> bool {
        matches!(self, SchemaDerive::Input | SchemaDerive::Both)
    }

    /// Whether the operator asked for output-schema derivation.
    /// Retained so the operator surface stays stable as the feature
    /// lands.
    pub fn includes_output(self) -> bool {
        matches!(self, SchemaDerive::Output | SchemaDerive::Both)
    }
}

/// Operator-facing schema config block. Empty by default.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    /// Derivation mode. See [`SchemaDerive`].
    #[serde(default)]
    pub derive: SchemaDerive,
}

/// Build a JSON Schema object from an ordered list of parameter names
/// paired with JSON-Schema-fragment types. All parameters are marked
/// `required` — there is no context to infer defaults, since raw
/// SQL has no notion of "optional parameter".
///
/// ```ignore
/// let s = build_input_schema(&[
///   ("tenant".into(), json!({"type": "string", "format": "uuid"})),
///   ("limit".into(), json!({"type": "integer"})),
/// ]);
/// // {
/// //   "type": "object",
/// //   "additionalProperties": false,
/// //   "required": ["tenant", "limit"],
/// //   "properties": {
/// //     "tenant": {"type":"string","format":"uuid"},
/// //     "limit":  {"type":"integer"}
/// //   }
/// // }
/// ```
pub fn build_input_schema(params: &[(String, Value)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<Value> = Vec::with_capacity(params.len());
    for (name, frag) in params {
        properties.insert(name.clone(), frag.clone());
        required.push(Value::String(name.clone()));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

/// Map a PostgreSQL type *name* (as returned by
/// `sqlx::postgres::PgTypeInfo::name()`) to a JSON Schema fragment.
///
/// Unknown names fall back to `{}` (JSON Schema's "anything goes"),
/// which is safe: the plugin still performs runtime validation of the
/// bound value. The goal here is to give MCP clients enough to render
/// a form; strict type-level matching is operator-overridable.
pub fn pg_type_to_json_schema(pg_type: &str) -> Value {
    // Names follow `pg_type.typname`. Normalize to lowercase so the
    // match below can be terse.
    let t = pg_type.to_ascii_lowercase();
    match t.as_str() {
        // Booleans
        "bool" => json!({"type": "boolean"}),

        // Integers — use u64/i64 representable range. JSON numbers are
        // f64 by default, but MCP clients that care (IDE hover tips)
        // can use `minimum`/`maximum` to tell the two apart.
        "int2" | "smallint" => json!({"type": "integer", "minimum": -32_768, "maximum": 32_767}),
        "int4" | "integer" | "int" => json!({"type": "integer"}),
        "int8" | "bigint" => json!({"type": "integer"}),

        // Floating-point — `number` in JSON Schema.
        "float4" | "real" => json!({"type": "number"}),
        "float8" | "double precision" | "double" => json!({"type": "number"}),
        // `numeric` / `decimal` serialize as strings by convention
        // (JSON numbers lose precision); operator can override if they
        // know the bounds are small.
        "numeric" | "decimal" => json!({"type": "string", "format": "decimal"}),

        // Strings and string-like.
        "text" | "varchar" | "char" | "bpchar" | "name" | "citext" => {
            json!({"type": "string"})
        }

        // Temporal types — ISO 8601 strings.
        "date" => json!({"type": "string", "format": "date"}),
        "time" | "timetz" => json!({"type": "string", "format": "time"}),
        "timestamp" | "timestamptz" => json!({"type": "string", "format": "date-time"}),
        "interval" => json!({"type": "string", "format": "duration"}),

        // UUIDs.
        "uuid" => json!({"type": "string", "format": "uuid"}),

        // JSON/JSONB — structure unknown, so `{}` (anything).
        "json" | "jsonb" => json!({}),

        // Binary — base64-encoded strings in the binding's contract.
        "bytea" => json!({"type": "string", "contentEncoding": "base64"}),

        // Unknown — wide-open. Operator schema override is the escape
        // hatch.
        _ => json!({}),
    }
}

/// Assemble the full input-schema from a parallel pair of
/// `param_names` and `pg_type_names`. Lengths must match — a mismatch
/// returns `None` so the caller can fall back to operator-supplied
/// schema without failing registration.
pub fn input_schema_from_pg_params(
    param_names: &[String],
    pg_type_names: &[String],
) -> Option<Value> {
    if param_names.len() != pg_type_names.len() {
        return None;
    }
    let pairs: Vec<(String, Value)> = param_names
        .iter()
        .zip(pg_type_names.iter())
        .map(|(n, ty)| (n.clone(), pg_type_to_json_schema(ty)))
        .collect();
    Some(build_input_schema(&pairs))
}

/// One output column — what the plugin gets back from
/// `sqlx::Executor::describe`.
///
/// `nullable: None` means "the driver couldn't determine
/// nullability" (common for computed columns or outer joins where
/// sqlx can't statically prove the result is non-null). In that
/// case the emitted schema treats the column as nullable by default
/// — matches JSON Schema's accept-`null`-in-union convention.
#[derive(Debug, Clone)]
pub struct OutputColumn {
    /// Column name (alias if the operator used one).
    pub name: String,
    /// Postgres type name from `PgTypeInfo::name()`.
    pub pg_type: String,
    /// Column nullability, when sqlx could prove it.
    pub nullable: Option<bool>,
}

/// Build an `outputSchema` JSON Schema fragment from the prepared
/// statement's output column metadata.
///
/// Shape depends on the binding's `row_mode`:
///
/// - `single` → `{type: "object", properties: {col: {...}, …}, required: […]}`
/// - `many`   → `{type: "array", items: <single schema>}`
/// - `scalar` → first column's schema, unwrapped
/// - `affected_rows` → `{type: "object", properties: {rows_affected: {type: "integer"}}}`
/// - `resource_contents` → `None` (MCP protocol defines the wrapper;
///   deriving it here would fight the framework contract)
///
/// Nullable columns widen to `{type: [..., "null"]}` so clients can
/// distinguish "column exists, no value" from "column missing".
/// Unknown-nullability columns default to nullable.
pub fn output_schema_from_pg_columns(
    columns: &[OutputColumn],
    row_mode: crate::config::RowMode,
) -> Option<Value> {
    use crate::config::RowMode;
    if columns.is_empty() {
        return None;
    }
    match row_mode {
        // Output-schema derivation isn't meaningful for either of
        // these shapes:
        //  - ResourceContents builds the MCP resources/read envelope
        //    from semantic columns (uri/text/blob), not from the raw
        //    column list.
        //  - ResultSets is N untyped row arrays; per-set column
        //    introspection would require N pre-prepares which sqlx
        //    doesn't expose for `CALL` statements.
        RowMode::ResourceContents | RowMode::ResultSets => None,
        RowMode::AffectedRows => Some(json!({
            "type": "object",
            "properties": {
                "rows_affected": {"type": "integer", "minimum": 0}
            },
            "required": ["rows_affected"]
        })),
        RowMode::Scalar => {
            let col = &columns[0];
            Some(widen_to_nullable(
                pg_type_to_json_schema(&col.pg_type),
                col.nullable,
            ))
        }
        RowMode::Single | RowMode::Many | RowMode::Stream => {
            let mut properties = serde_json::Map::new();
            let mut required = Vec::new();
            for col in columns {
                let frag = widen_to_nullable(pg_type_to_json_schema(&col.pg_type), col.nullable);
                // Only non-nullable columns are required — nullable
                // or unknown-nullability columns are optional so the
                // client can distinguish absence from SQL NULL at
                // the JSON level.
                if col.nullable == Some(false) {
                    required.push(Value::String(col.name.clone()));
                }
                properties.insert(col.name.clone(), frag);
            }
            let single = json!({
                "type": "object",
                "additionalProperties": false,
                "required": required,
                "properties": properties,
            });
            match row_mode {
                RowMode::Single => Some(single),
                RowMode::Many => Some(json!({
                    "type": "array",
                    "items": single,
                })),
                RowMode::Stream => Some(json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["rows", "next_cursor", "truncated"],
                    "properties": {
                        "rows": {"type": "array", "items": single},
                        "next_cursor": {"type": ["string", "null"]},
                        "truncated": {"type": "boolean"},
                    },
                })),
                _ => unreachable!(),
            }
        }
    }
}

fn widen_to_nullable(frag: Value, nullable: Option<bool>) -> Value {
    if nullable == Some(false) {
        return frag;
    }
    let Value::Object(mut map) = frag else {
        return frag;
    };
    match map.remove("type") {
        Some(Value::String(s)) if s != "null" => {
            map.insert(
                "type".into(),
                Value::Array(vec![Value::String(s), Value::String("null".into())]),
            );
        }
        Some(other) => {
            map.insert("type".into(), other);
        }
        None => {}
    }
    Value::Object(map)
}

/// Re-export of the canonical JSON Schema merge helper so call
/// sites in this crate don't need to reach into `mcpg_plugin_protocol`
/// directly. The merge semantics (operator overlay wins, objects
/// merge key-by-key, arrays replace wholesale) are defined in the
/// plugin-api so the host uses the same behavior at tool composition.
pub use mcpg_plugin_protocol::schema::merge_schema;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_mode_defaults_to_off() {
        let cfg: SchemaConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(cfg.derive, SchemaDerive::Off);
        assert!(!cfg.derive.includes_input());
        assert!(!cfg.derive.includes_output());
    }

    #[test]
    fn derive_mode_input_only() {
        let cfg: SchemaConfig = serde_json::from_value(json!({"derive": "input"})).unwrap();
        assert!(cfg.derive.includes_input());
        assert!(!cfg.derive.includes_output());
    }

    #[test]
    fn derive_mode_both_includes_input_and_output() {
        let cfg: SchemaConfig = serde_json::from_value(json!({"derive": "both"})).unwrap();
        assert!(cfg.derive.includes_input());
        assert!(cfg.derive.includes_output());
    }

    #[test]
    fn pg_type_mapping_covers_common_cases() {
        assert_eq!(pg_type_to_json_schema("int4"), json!({"type": "integer"}));
        assert_eq!(pg_type_to_json_schema("int8"), json!({"type": "integer"}));
        assert_eq!(pg_type_to_json_schema("text"), json!({"type": "string"}));
        assert_eq!(
            pg_type_to_json_schema("uuid"),
            json!({"type": "string", "format": "uuid"})
        );
        assert_eq!(
            pg_type_to_json_schema("timestamptz"),
            json!({"type": "string", "format": "date-time"})
        );
        assert_eq!(pg_type_to_json_schema("bool"), json!({"type": "boolean"}));
        assert_eq!(pg_type_to_json_schema("json"), json!({}));
        // Unknown type → anything goes.
        assert_eq!(pg_type_to_json_schema("tsvector"), json!({}));
    }

    #[test]
    fn pg_type_mapping_is_case_insensitive() {
        assert_eq!(
            pg_type_to_json_schema("INT4"),
            pg_type_to_json_schema("int4")
        );
        assert_eq!(
            pg_type_to_json_schema("TimestampTZ"),
            pg_type_to_json_schema("timestamptz")
        );
    }

    #[test]
    fn build_input_schema_orders_required_and_properties() {
        let schema = build_input_schema(&[
            ("tenant".into(), json!({"type": "string", "format": "uuid"})),
            ("limit".into(), json!({"type": "integer"})),
        ]);
        let obj = schema.as_object().unwrap();
        assert_eq!(obj["type"], "object");
        assert_eq!(obj["additionalProperties"], false);
        assert_eq!(
            obj["required"],
            json!(["tenant", "limit"]),
            "required must preserve insertion order"
        );
        let props = obj["properties"].as_object().unwrap();
        assert_eq!(props["tenant"]["format"], "uuid");
        assert_eq!(props["limit"]["type"], "integer");
    }

    #[test]
    fn input_schema_from_pg_params_mismatched_returns_none() {
        let names = vec!["a".to_string(), "b".into()];
        let types = vec!["int4".to_string()];
        assert!(input_schema_from_pg_params(&names, &types).is_none());
    }

    #[test]
    fn input_schema_from_pg_params_happy_path() {
        let names = vec!["tenant".to_string(), "limit".into()];
        let types = vec!["uuid".to_string(), "int4".into()];
        let schema = input_schema_from_pg_params(&names, &types).unwrap();
        let props = schema["properties"].as_object().unwrap();
        assert_eq!(props["tenant"]["format"], "uuid");
        assert_eq!(props["limit"]["type"], "integer");
    }

    // ------------------------------------------------------------------
    // outputSchema derivation
    // ------------------------------------------------------------------

    use crate::config::RowMode;

    fn col(name: &str, pg_type: &str, nullable: Option<bool>) -> OutputColumn {
        OutputColumn {
            name: name.into(),
            pg_type: pg_type.into(),
            nullable,
        }
    }

    #[test]
    fn output_empty_columns_is_none() {
        assert!(output_schema_from_pg_columns(&[], RowMode::Single).is_none());
    }

    #[test]
    fn output_resource_contents_is_none() {
        // The MCP protocol defines the `{contents: [...]}` shape —
        // deriving it would fight the framework contract.
        let cols = vec![col("uri", "text", Some(false))];
        assert!(output_schema_from_pg_columns(&cols, RowMode::ResourceContents).is_none());
    }

    #[test]
    fn output_affected_rows_has_fixed_shape() {
        let cols = vec![col("rows_affected", "int8", Some(false))];
        let schema = output_schema_from_pg_columns(&cols, RowMode::AffectedRows).unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["rows_affected"]["type"], "integer");
    }

    #[test]
    fn output_scalar_unwraps_first_column() {
        let cols = vec![col("count", "int8", Some(false))];
        let schema = output_schema_from_pg_columns(&cols, RowMode::Scalar).unwrap();
        assert_eq!(schema["type"], "integer");
    }

    #[test]
    fn output_scalar_widens_nullable_to_union() {
        let cols = vec![col("latest_order_id", "uuid", Some(true))];
        let schema = output_schema_from_pg_columns(&cols, RowMode::Scalar).unwrap();
        assert_eq!(schema["type"], json!(["string", "null"]));
        assert_eq!(schema["format"], "uuid");
    }

    #[test]
    fn output_single_builds_object_schema() {
        let cols = vec![
            col("id", "int8", Some(false)),
            col("name", "text", Some(false)),
            col("note", "text", Some(true)),
        ];
        let schema = output_schema_from_pg_columns(&cols, RowMode::Single).unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        // Non-null columns are required; nullable column isn't.
        assert_eq!(schema["required"], json!(["id", "name"]));
        // Nullable column's type widens to a union.
        assert_eq!(
            schema["properties"]["note"]["type"],
            json!(["string", "null"])
        );
        // Non-null column stays scalar.
        assert_eq!(schema["properties"]["id"]["type"], "integer");
    }

    #[test]
    fn output_many_wraps_single_as_array() {
        let cols = vec![col("id", "int8", Some(false))];
        let schema = output_schema_from_pg_columns(&cols, RowMode::Many).unwrap();
        assert_eq!(schema["type"], "array");
        assert_eq!(schema["items"]["type"], "object");
    }

    #[test]
    fn output_unknown_nullability_widens_to_union() {
        // sqlx returns `None` nullability for computed columns,
        // outer joins, etc. Treat as nullable by default.
        let cols = vec![col("full_name", "text", None)];
        let schema = output_schema_from_pg_columns(&cols, RowMode::Scalar).unwrap();
        assert_eq!(schema["type"], json!(["string", "null"]));
    }
}
