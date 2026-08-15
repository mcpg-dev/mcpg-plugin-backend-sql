//! Aurora multi-endpoint failover scaffold (stub).
//!
//! Aurora exposes a writer endpoint + multiple reader endpoints; on
//! failover the writer DNS flips. This provider's eventual job is to
//! cycle across `endpoints` on connection failure with exponential
//! backoff and re-resolve DNS aggressively. The token-fetch protocol
//! itself is identical to RDS IAM — the eventual impl will compose
//! with [`super::rds_iam::RdsIamAuthProvider`] rather than duplicate
//! it. This stub is here so YAML parses today.

use std::time::Duration;

use async_trait::async_trait;

use super::{AuthError, AuthProvider, SecretToken};

/// Aurora failover provider stub.
#[derive(Debug)]
pub struct AuroraFailoverAuthProvider {
    #[allow(dead_code)]
    endpoints: Vec<String>,
}

impl AuroraFailoverAuthProvider {
    /// Build the stub. No I/O.
    pub async fn new(endpoints: Vec<String>) -> Result<Self, AuthError> {
        Ok(Self { endpoints })
    }
}

#[async_trait]
impl AuthProvider for AuroraFailoverAuthProvider {
    fn scheme(&self) -> &'static str {
        "aurora_failover"
    }

    async fn fetch_token(&self) -> Result<SecretToken, AuthError> {
        Err(AuthError::NotImplemented {
            scheme: "aurora_failover",
        })
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(900)
    }
}
