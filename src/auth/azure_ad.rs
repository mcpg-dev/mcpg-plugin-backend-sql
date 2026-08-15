//! Azure AD auth scaffold (stub).
//!
//! Placeholder so operator YAML can declare `auth: { kind: azure_ad,
//! ... }` today, even though `fetch_token` is not yet wired. Returns
//! [`AuthError::NotImplemented`]. When
//! this scheme ships, this file gains the actual `azure_identity`-backed
//! `DefaultAzureCredential` flow + `aad_token_for_postgres()` — every
//! other layer (rotator, driver wiring, config schema) stays the same.

use std::time::Duration;

use async_trait::async_trait;

use super::{AuthError, AuthProvider, SecretToken};

/// Azure AD provider stub. Holds the parsed knobs so a future
/// implementation has the wiring already in place. Construction is
/// fallible (`Result`) for symmetry with the real providers.
#[derive(Debug)]
pub struct AzureAdAuthProvider {
    #[allow(dead_code)]
    scope: String,
    #[allow(dead_code)]
    tenant_id: Option<String>,
}

impl AzureAdAuthProvider {
    /// Build the stub. Always succeeds — no I/O, no pre-validation
    /// beyond what `AuthConfig::validate` already did.
    pub async fn new(scope: String, tenant_id: Option<String>) -> Result<Self, AuthError> {
        Ok(Self { scope, tenant_id })
    }
}

#[async_trait]
impl AuthProvider for AzureAdAuthProvider {
    fn scheme(&self) -> &'static str {
        "azure_ad"
    }

    async fn fetch_token(&self) -> Result<SecretToken, AuthError> {
        Err(AuthError::NotImplemented { scheme: "azure_ad" })
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(900)
    }
}
