//! GCP CloudSQL IAM auth scaffold (stub).
//!
//! Placeholder so `auth: { kind: gcp_iam, ... }` parses today. Real
//! impl will use `gcloud-auth` (or `google-cloud-auth`) for ADC token
//! fetch; CloudSQL's `IAM Authentication` accepts the OAuth access
//! token as the password.

use std::time::Duration;

use async_trait::async_trait;

use super::{AuthError, AuthProvider, SecretToken};

/// GCP CloudSQL IAM provider stub.
#[derive(Debug)]
pub struct GcpIamAuthProvider {
    #[allow(dead_code)]
    username: String,
}

impl GcpIamAuthProvider {
    /// Build the stub. No I/O.
    pub async fn new(username: String) -> Result<Self, AuthError> {
        Ok(Self { username })
    }
}

#[async_trait]
impl AuthProvider for GcpIamAuthProvider {
    fn scheme(&self) -> &'static str {
        "gcp_iam"
    }

    async fn fetch_token(&self) -> Result<SecretToken, AuthError> {
        Err(AuthError::NotImplemented { scheme: "gcp_iam" })
    }

    fn token_ttl(&self) -> Duration {
        // GCP OAuth access tokens are 1h.
        Duration::from_secs(3600)
    }
}
