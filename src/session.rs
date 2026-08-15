//! Session variables — the operator-declared GUCs/user variables that
//! the binding would apply per call (`SET LOCAL` etc.).
//!
//! This struct is the parse-time carrier. Each driver applies the
//! variables on its own pinned-connection path. The struct lives
//! here so the driver trait can accept it without a signature change.

use std::collections::BTreeMap;

/// Resolved session variables to apply to a connection before the
/// primary statement runs.
///
/// Values are always bound (never interpolated) into the driver's
/// `SET` statement. Keys must be valid SQL identifiers; this is
/// enforced at config parse time — by construction the map here
/// cannot contain invalid keys.
#[derive(Debug, Clone, Default)]
pub struct SessionVars {
    /// Map of identifier → bound value.
    pub values: BTreeMap<String, String>,
}

impl SessionVars {
    /// Construct from a raw map. Does not validate — validation lives
    /// at the config-parse layer (`SqlBackendConfig::validate`).
    pub fn from_map(values: BTreeMap<String, String>) -> Self {
        Self { values }
    }

    /// True if no variables would be applied. Lets drivers skip the
    /// extra round trip entirely.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_empty() {
        assert!(SessionVars::default().is_empty());
    }

    #[test]
    fn non_empty_reports_non_empty() {
        let mut m = BTreeMap::new();
        m.insert("app.current_tenant".into(), "acme".into());
        let s = SessionVars::from_map(m);
        assert!(!s.is_empty());
    }
}
