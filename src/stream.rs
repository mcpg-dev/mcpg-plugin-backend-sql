//! Keyset stream cursor for `row_mode: stream`.
//!
//! When a binding declares `row_mode: stream` plus a `stream:` block,
//! the plugin auto-pages large result sets via *keyset* cursors. The
//! operator names one or more cursor columns (typically a primary
//! key), and the plugin tracks the last row's cursor-column values.
//! On continuation, the plugin re-runs the same SQL with the previous
//! row's values bound to `:_after_<col>` placeholders.
//!
//! ## Why keyset, not `DECLARE CURSOR`
//!
//! `DECLARE ... CURSOR` (Postgres) pins the cursor to a specific
//! database session — the same gateway *and* the same sqlx connection.
//! That works for single-instance deployments but breaks under cluster
//! mode: a follow-up tool call routed to a different gateway instance
//! would find no cursor. Keyset cursors carry their state in the
//! token itself; any gateway instance can decode and resume.
//!
//! Trade-off: the operator MUST author the SQL with stable
//! `ORDER BY <cursor_cols>` matching the configured columns, plus
//! `WHERE (cursor_cols) > (:_after_*)` filters. The plugin enforces
//! placeholder presence at config-load time so misconfiguration is
//! caught before any traffic flows.
//!
//! ## Token format
//!
//! `s.<base64url(payload)>.<base64url(hmac)>` — `s.` prefix
//! distinguishes from the gateway's `c.` composite-cursor tokens.
//! Payload is JSON: `{"v":1,"b":"<binding>","p":"<profile>",
//! "k":[<col1_value>, <col2_value>, ...]}`. HMAC-SHA-256 over the
//! base64-encoded payload binds the token to the signing key —
//! tampered payloads, or tokens minted on another binding, fail
//! verification.
//!
//! ## Cluster correctness
//!
//! Keyset cursors are stateless (no server-side cursor table), so
//! any gateway instance can decode and continue. The HMAC signing
//! key MUST be shared across instances — operators set it via
//! `stream.signing_key` (recommended for clustered deploys), using
//! `${env.X}` or `cred://…` which the gateway substitutes at config
//! load. Without it the plugin generates a per-process key at
//! boot; a follow-up call routed to a different node will fail
//! cursor verification with a clear error. Multi-node deployments
//! that omit `signing_key` should expect cursor failures on
//! cross-node continuation.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use mcpg_sensitive::Sensitive;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::SqlError;

/// Operator-facing stream config. Only meaningful when the parent
/// `query.row_mode` is `Stream`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    /// Columns that form the keyset key — typically a unique
    /// primary or composite key. Cursor encodes the last row's
    /// values for these columns; on continuation the plugin binds
    /// them to `:_after_<col>` placeholders.
    pub cursor_columns: Vec<String>,

    /// Initial keyset values for the first page. The plugin binds
    /// these to `:_after_<col>` placeholders when no cursor is
    /// present. Defaults to `null` per column — operators relying on
    /// the default must use SQL like `WHERE id > COALESCE(:_after_id, 0)`.
    /// Explicit `initial` values let the operator pass clean
    /// non-null bootstraps (e.g. `initial: { id: 0 }` paired with
    /// `WHERE id > :_after_id`).
    #[serde(default)]
    pub initial: serde_json::Map<String, Value>,

    /// HMAC signing key value (raw bytes, any length — hashed to 32
    /// bytes). Operators supply it as `${env.X}` or `cred://…`; the
    /// gateway substitutes the literal value at config load before the
    /// plugin sees it. Used as the per-binding cursor signing key.
    /// Required for cluster-correct stream cursors: all gateway
    /// instances must share the same key for a cursor minted on
    /// instance A to verify on instance B. When unset the plugin
    /// generates a per-process random key — a multi-node deploy
    /// without it will see cursor verification failures on cross-node
    /// continuation calls.
    #[serde(default)]
    pub signing_key: Option<Sensitive<String>>,
}

impl StreamConfig {
    /// Validate the static contents of a `StreamConfig`. Called from
    /// the parent `SqlBackendConfig::validate` after serde populates
    /// the struct.
    pub fn validate(&self) -> Result<(), SqlError> {
        if self.cursor_columns.is_empty() {
            return Err(SqlError::InvalidSpec(
                "stream.cursor_columns must not be empty when row_mode is stream".into(),
            ));
        }
        for col in &self.cursor_columns {
            if !is_safe_column_name(col) {
                return Err(SqlError::InvalidSpec(format!(
                    "stream.cursor_columns: '{col}' is not a safe column name \
                     (allowed: ASCII letters, digits, `_`)"
                )));
            }
        }
        // initial keys (when present) must match a declared cursor column.
        for k in self.initial.keys() {
            if !self.cursor_columns.iter().any(|c| c == k) {
                return Err(SqlError::InvalidSpec(format!(
                    "stream.initial['{k}'] is not a declared cursor column \
                     (cursor_columns: {:?})",
                    self.cursor_columns,
                )));
            }
        }
        Ok(())
    }

    /// The names of the placeholders the plugin auto-binds at execute
    /// time, in declared order. E.g. `cursor_columns = ["id"]` →
    /// `["_after_id"]`. The operator's SQL must reference these.
    #[must_use]
    pub fn placeholder_names(&self) -> Vec<String> {
        self.cursor_columns
            .iter()
            .map(|c| format!("_after_{c}"))
            .collect()
    }
}

fn is_safe_column_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Per-binding cursor signing key. Held inside `Arc` so the runtime
/// can clone it cheaply onto each profile.
#[derive(Debug, Clone)]
pub struct CursorSigningKey(Arc<[u8; 32]>);

impl CursorSigningKey {
    /// Generate a fresh random key from OS entropy. Used when the
    /// operator does not set `signing_key` (per-process key —
    /// works for single-node, breaks under cluster routing).
    #[must_use]
    pub fn generate() -> Self {
        use uuid::Uuid;
        let mut bytes = [0u8; 32];
        let a = *Uuid::new_v4().as_bytes();
        let b = *Uuid::new_v4().as_bytes();
        bytes[..16].copy_from_slice(&a);
        bytes[16..].copy_from_slice(&b);
        Self(Arc::new(bytes))
    }

    /// Derive a signing key from caller-supplied bytes (the
    /// resolved `signing_key` value). Hashes the input to a
    /// fixed-width 32 bytes via
    /// blake3 so any input length works while keeping the key
    /// material a constant size.
    #[must_use]
    pub fn from_bytes(input: &[u8]) -> Self {
        let h = blake3::hash(input);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(h.as_bytes());
        Self(Arc::new(bytes))
    }

    fn key(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Decoded cursor payload — the values needed to resume a paged
/// stream query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCursorPayload {
    /// Format version. Always `1` for the current shape.
    #[serde(rename = "v")]
    pub version: u32,
    /// Binding name the cursor was minted for. Continuation calls
    /// against a different binding fail verification — prevents
    /// replay across bindings even with the same signing key.
    #[serde(rename = "b")]
    pub binding: String,
    /// Profile name (when the binding has multiple profiles).
    /// Empty string when no profile distinction.
    #[serde(rename = "p", default)]
    pub profile: String,
    /// Last-row values, in the order declared by
    /// `StreamConfig.cursor_columns`. Each entry is a JSON value the
    /// plugin will bind to the matching `:_after_<col>` placeholder.
    #[serde(rename = "k")]
    pub keyset: Vec<Value>,
}

/// Encode an opaque, HMAC-bound cursor token from a payload.
///
/// Format: `s.<base64url(payload_json)>.<base64url(hmac)>`.
/// Token always carries the MAC (no unsigned variant) — stream
/// cursors must be tamper-proof to prevent forged values bound to
/// `:_after_<col>` placeholders that could leak rows the operator
/// would otherwise gate via `WHERE`.
#[must_use]
pub fn encode_cursor(payload: &StreamCursorPayload, key: &CursorSigningKey) -> String {
    let json = serde_json::to_vec(payload).expect("StreamCursorPayload serializes");
    let payload_b64 = URL_SAFE_NO_PAD.encode(&json);
    let mac = hmac_sha256::HMAC::mac(payload_b64.as_bytes(), key.key());
    let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
    format!("s.{payload_b64}.{mac_b64}")
}

/// Decode + verify a cursor token. Returns the payload on success;
/// returns `None` for any failure mode (malformed prefix, base64
/// decode error, HMAC mismatch, JSON shape mismatch). The plugin
/// surfaces a generic `InvalidSpec` error on `None` — leaking
/// failure mode details would help an attacker probe the format.
#[must_use]
pub fn decode_cursor(token: &str, key: &CursorSigningKey) -> Option<StreamCursorPayload> {
    let body = token.strip_prefix("s.")?;
    let (payload_b64, mac_b64) = body.split_once('.')?;
    let expected = hmac_sha256::HMAC::mac(payload_b64.as_bytes(), key.key());
    let actual = URL_SAFE_NO_PAD.decode(mac_b64).ok()?;
    if !constant_time_eq(&expected, &actual) {
        return None;
    }
    let json_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: StreamCursorPayload = serde_json::from_slice(&json_bytes).ok()?;
    if payload.version != 1 {
        return None;
    }
    Some(payload)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(cols: &[&str]) -> StreamConfig {
        StreamConfig {
            cursor_columns: cols.iter().map(|s| (*s).into()).collect(),
            initial: serde_json::Map::new(),
            signing_key: None,
        }
    }

    #[test]
    fn validate_rejects_empty_cursor_columns() {
        let err = StreamConfig {
            cursor_columns: vec![],
            initial: serde_json::Map::new(),
            signing_key: None,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(_)));
    }

    #[test]
    fn validate_rejects_unsafe_column_name() {
        let err = cfg(&["id; DROP TABLE x"]).validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a safe column name"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_initial_key_not_in_columns() {
        let mut c = cfg(&["id"]);
        c.initial.insert("created_at".into(), json!(0));
        let err = c.validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a declared cursor column"), "got: {msg}");
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        let mut c = cfg(&["id", "created_at"]);
        c.initial.insert("id".into(), json!(0));
        assert!(c.validate().is_ok());
    }

    #[test]
    fn placeholder_names_match_cursor_columns() {
        let c = cfg(&["id", "created_at"]);
        assert_eq!(
            c.placeholder_names(),
            vec!["_after_id", "_after_created_at"]
        );
    }

    #[test]
    fn cursor_roundtrip_succeeds() {
        let key = CursorSigningKey::generate();
        let p = StreamCursorPayload {
            version: 1,
            binding: "users.list".into(),
            profile: "default".into(),
            keyset: vec![json!(42), json!("2026-05-08T00:00:00Z")],
        };
        let token = encode_cursor(&p, &key);
        assert!(token.starts_with("s."));
        let decoded = decode_cursor(&token, &key).expect("verifies");
        assert_eq!(decoded, p);
    }

    #[test]
    fn cursor_with_different_key_fails_verification() {
        let key_a = CursorSigningKey::from_bytes(b"key-a-input");
        let key_b = CursorSigningKey::from_bytes(b"key-b-input");
        let p = StreamCursorPayload {
            version: 1,
            binding: "users.list".into(),
            profile: String::new(),
            keyset: vec![json!(1)],
        };
        let token = encode_cursor(&p, &key_a);
        assert!(decode_cursor(&token, &key_b).is_none());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = CursorSigningKey::generate();
        let p = StreamCursorPayload {
            version: 1,
            binding: "users.list".into(),
            profile: String::new(),
            keyset: vec![json!(1)],
        };
        let token = encode_cursor(&p, &key);
        // Flip a byte in the payload portion.
        let parts: Vec<&str> = token.split('.').collect();
        let mut bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        bytes[0] ^= 0x01;
        let tampered_payload = URL_SAFE_NO_PAD.encode(&bytes);
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
        assert!(decode_cursor(&tampered, &key).is_none());
    }

    #[test]
    fn malformed_token_returns_none() {
        let key = CursorSigningKey::generate();
        assert!(decode_cursor("", &key).is_none());
        assert!(decode_cursor("not-a-cursor", &key).is_none());
        assert!(decode_cursor("s.no-mac", &key).is_none());
        assert!(decode_cursor("s.bad-base64.bad-base64", &key).is_none());
        // Right prefix + valid base64 but wrong MAC.
        let bogus_payload = URL_SAFE_NO_PAD.encode(br#"{"v":1,"b":"x","p":"","k":[]}"#);
        let bogus_mac = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(decode_cursor(&format!("s.{bogus_payload}.{bogus_mac}"), &key).is_none());
    }

    #[test]
    fn version_mismatch_rejected_even_with_valid_mac() {
        // Forge a token for version 99 and re-MAC it with the
        // signing key — decode_cursor must still reject because
        // the version field is verified after MAC.
        let key = CursorSigningKey::generate();
        let payload_json = br#"{"v":99,"b":"x","p":"","k":[]}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
        let mac = hmac_sha256::HMAC::mac(payload_b64.as_bytes(), key.key());
        let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
        let token = format!("s.{payload_b64}.{mac_b64}");
        assert!(decode_cursor(&token, &key).is_none());
    }

    #[test]
    fn cursor_signing_key_from_bytes_is_deterministic() {
        let a = CursorSigningKey::from_bytes(b"shared-secret");
        let b = CursorSigningKey::from_bytes(b"shared-secret");
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn cursor_signing_key_generate_is_random() {
        let a = CursorSigningKey::generate();
        let b = CursorSigningKey::generate();
        assert_ne!(a.key(), b.key());
    }

    #[test]
    fn keyset_with_heterogeneous_value_types_roundtrips() {
        // Integer + string + null + bool + float — covers every
        // serde_json::Value scalar we care about for cursor cols.
        let key = CursorSigningKey::generate();
        let p = StreamCursorPayload {
            version: 1,
            binding: "x".into(),
            profile: "y".into(),
            keyset: vec![
                json!(42i64),
                json!("hello"),
                json!(null),
                json!(true),
                json!(2.5_f64),
            ],
        };
        let token = encode_cursor(&p, &key);
        let decoded = decode_cursor(&token, &key).unwrap();
        assert_eq!(decoded.keyset, p.keyset);
    }
}
