//! Cloud-DB token auth providers.
//!
//! Cloud-managed databases (AWS RDS, Azure SQL, GCP CloudSQL, …)
//! increasingly disable static-password auth and require short-lived
//! IAM/AAD tokens. This module supplies an [`AuthProvider`] trait that
//! every cloud-auth scheme implements, plus a [`TokenRotator`] that
//! wires the provider into a live `sqlx` pool — refreshes the token
//! ahead of expiry and calls `set_connect_options` so new physical
//! connections pick up the fresh password without disrupting in-flight
//! queries on the old ones (those are recycled by the pool's
//! `max_lifetime`, capped to `token_ttl - safety_margin`).
//!
//! Concrete providers live in sibling modules, each behind its own
//! Cargo feature flag so flagship `mcpg-plugin-backend-sql` builds
//! with no AWS/Azure/GCP dependency surface:
//!
//! * [`rds_iam`] — AWS RDS / Aurora IAM (`sql-rds-iam`). Shipped.
//! * [`azure_ad`] — Azure SQL / Postgres Flexible Server AAD
//!   (`sql-azure-ad`). Scaffolded; `fetch_token` returns
//!   `AuthError::NotImplemented` until the impl lands.
//! * [`gcp_iam`] — CloudSQL IAM (`sql-gcp-iam`). Scaffolded.
//! * [`aurora_failover`] — Aurora multi-endpoint failover wrapper
//!   (`sql-aurora-failover`). Scaffolded.
//!
//! Adding the next scheme is a leaf change: implement
//! `AuthProvider` for the new struct and wire its `AuthConfig` variant
//! to the constructor under its feature flag. The driver layer
//! (`driver/postgres.rs`) and rotator (`TokenRotator`) stay untouched.
//!
//! ## Design notes
//!
//! * `fetch_token` is async + may do network I/O — RDS IAM presigns a
//!   URL via the AWS signer chain; that chain may probe IMDS / SSO.
//! * Tokens are wrapped in [`SecretToken`] — a `String` newtype with a
//!   `Debug` impl that elides the value, so a stray `format!("{:?}")`
//!   in tracing or panic output never spills the bearer.
//! * `token_ttl` is a hint, not a contract: the rotator schedules a
//!   refresh at `ttl - safety_margin`. Providers that hand out tokens
//!   with no fixed lifetime (e.g. a dev mock) return `Duration::MAX`
//!   and the rotator won't schedule one.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::errors::SqlError;

#[cfg(feature = "sql-rds-iam")]
pub mod rds_iam;

#[cfg(feature = "sql-azure-ad")]
pub mod azure_ad;

#[cfg(feature = "sql-gcp-iam")]
pub mod gcp_iam;

#[cfg(feature = "sql-aurora-failover")]
pub mod aurora_failover;

pub mod rotator;

pub use rotator::TokenRotator;

/// Bearer-style secret newtype. The inner value is kept private so it
/// can only be exposed via [`SecretToken::expose`]; `Debug` elides it.
#[derive(Clone)]
pub struct SecretToken(String);

impl SecretToken {
    /// Wrap a freshly fetched token. Callers should immediately move
    /// it into a `SecretToken` to keep stray copies of the raw value
    /// off the heap.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// Expose the raw token. Use only at the actual driver boundary
    /// (e.g. `PgConnectOptions::password`); never log or stringify.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretToken").field(&"<redacted>").finish()
    }
}

/// Provider-side errors. Mapped to [`SqlError::Connect`] /
/// [`SqlError::InvalidSpec`] at the driver boundary so the existing
/// error funnel surfaces them unchanged.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Provider variant compiled out under feature gating, or marked
    /// scaffolded-only. Returned by the not-yet-implemented scheme
    /// stubs (Azure AD, GCP IAM, Aurora failover) until those
    /// schemes ship.
    #[error("auth scheme '{scheme}' is scaffolded but not yet supported")]
    NotImplemented {
        /// Discriminator that was selected, e.g. `azure_ad`.
        scheme: &'static str,
    },
    /// Required config field missing or invalid (region, username, …).
    /// Surfaced at config-validate time when possible; at fetch time
    /// otherwise.
    #[error("auth config: {0}")]
    InvalidConfig(String),
    /// Token-fetch failed. Wraps the underlying source error as a
    /// boxed `dyn Error` to keep `AuthError` provider-agnostic.
    #[error("auth fetch: {message}")]
    Fetch {
        /// Operator-facing summary; the wrapped source carries the
        /// raw provider error.
        message: String,
        /// Underlying provider error. Not consulted by the driver
        /// path — the message is enough.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl From<AuthError> for SqlError {
    fn from(e: AuthError) -> Self {
        // Auth failures ride on `Connect` because they manifest as a
        // failed `connect()` call — same operator-facing meaning as a
        // bad password or unreachable host. Validation-shape errors
        // become `InvalidSpec` so they fail config load, not a request.
        match e {
            AuthError::InvalidConfig(_) => SqlError::InvalidSpec(e.to_string()),
            AuthError::NotImplemented { .. } => SqlError::InvalidSpec(e.to_string()),
            AuthError::Fetch { .. } => {
                // Build a synthetic sqlx::Error::Configuration so the
                // existing `Connect` arm carries the message verbatim.
                SqlError::Connect(sqlx::Error::Configuration(e.to_string().into()))
            }
        }
    }
}

/// The sole abstraction every cloud-auth scheme implements. Pool
/// construction (driver layer) calls `fetch_token` once to seed the
/// initial password; [`TokenRotator`] then drives subsequent refreshes
/// on its own schedule.
#[async_trait]
pub trait AuthProvider: Send + Sync + fmt::Debug {
    /// Discriminator label used in metrics / tracing
    /// (`mcpg_sql_auth_token_refresh_total{scheme=…}`). Static so the
    /// label allocates once.
    fn scheme(&self) -> &'static str;

    /// Fetch a fresh authentication token. May perform network I/O
    /// (presign + AWS credential-chain probe in the RDS case).
    async fn fetch_token(&self) -> Result<SecretToken, AuthError>;

    /// How long the most recently issued token is valid. The rotator
    /// schedules refresh at `ttl - safety_margin`, where the margin
    /// is the rotator's [`RotatorConfig::safety_margin`] (default
    /// 60 s). Providers with no fixed TTL return `Duration::MAX` to
    /// disable rotation entirely.
    fn token_ttl(&self) -> Duration;

    /// Tell the provider which DB endpoint these tokens authenticate
    /// against. Called once by the driver after parsing the operator
    /// URL — RDS IAM presigning needs the host:port; Azure AD / GCP
    /// IAM are endpoint-agnostic. Default impl is a no-op so most
    /// providers don't need to override.
    ///
    /// Idempotent for the same host:port; returns
    /// [`AuthError::InvalidConfig`] on a conflicting re-bind so an
    /// operator that hot-edits a binding URL gets a clear error.
    fn bind_endpoint(&self, _host: &str, _port: u16) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Operator-facing auth-block selection. Lives alongside `password` /
/// `cred://` references inside [`crate::config::SqlBackendConfig`].
/// Each variant carries its scheme-specific knobs; an absent block
/// keeps the legacy URL-embedded-password path unchanged.
///
/// Validation rejects more than one of `auth:` / `password_in_url` /
/// `cred://` references at startup — exactly one credential surface
/// per binding.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthConfig {
    /// AWS RDS / Aurora IAM. Generates a 15 min auth token via
    /// `aws-sigv4` presigning.
    RdsIam {
        /// AWS region (e.g. `us-east-1`). Required — the signer needs
        /// it to derive the signing key.
        region: String,
        /// DB user the token authenticates as. Required.
        username: String,
        /// Optional shared-config profile name. When unset, the AWS
        /// default credential provider chain is used (env vars → SSO
        /// → IMDS / IRSA).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
    },
    /// Azure SQL / Postgres Flexible Server AAD. Scaffolded.
    AzureAd {
        /// Token-audience scope, e.g.
        /// `https://ossrdbms-aad.database.windows.net/.default` for
        /// Postgres Flexible Server.
        #[serde(default = "default_azure_ad_scope")]
        scope: String,
        /// Optional explicit tenant id; default-credential chain
        /// resolves it otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tenant_id: Option<String>,
    },
    /// GCP CloudSQL IAM. Scaffolded.
    GcpIam {
        /// IAM database user (typically `<sa-name>@<project>.iam`).
        username: String,
    },
    /// Aurora multi-endpoint failover wrapper. Scaffolded.
    AuroraFailover {
        /// Comma-separated reader endpoints. The wrapper rotates
        /// across them on connection failure with exponential backoff.
        endpoints: Vec<String>,
    },
}

fn default_azure_ad_scope() -> String {
    "https://ossrdbms-aad.database.windows.net/.default".to_owned()
}

impl AuthConfig {
    /// Discriminator label used in errors / metrics. Matches the
    /// serde tag on each variant.
    #[must_use]
    pub fn scheme(&self) -> &'static str {
        match self {
            AuthConfig::RdsIam { .. } => "rds_iam",
            AuthConfig::AzureAd { .. } => "azure_ad",
            AuthConfig::GcpIam { .. } => "gcp_iam",
            AuthConfig::AuroraFailover { .. } => "aurora_failover",
        }
    }

    /// Lightweight shape validation. Called at config-load time so
    /// missing-region / empty-username errors fire before the plugin
    /// builds any I/O.
    pub fn validate(&self) -> Result<(), AuthError> {
        match self {
            AuthConfig::RdsIam {
                region, username, ..
            } => {
                if region.trim().is_empty() {
                    return Err(AuthError::InvalidConfig(
                        "rds_iam.region is required (e.g. 'us-east-1')".into(),
                    ));
                }
                if username.trim().is_empty() {
                    return Err(AuthError::InvalidConfig(
                        "rds_iam.username is required".into(),
                    ));
                }
                Ok(())
            }
            AuthConfig::AzureAd { scope, .. } => {
                if scope.trim().is_empty() {
                    return Err(AuthError::InvalidConfig(
                        "azure_ad.scope must be non-empty".into(),
                    ));
                }
                Ok(())
            }
            AuthConfig::GcpIam { username } => {
                if username.trim().is_empty() {
                    return Err(AuthError::InvalidConfig(
                        "gcp_iam.username is required".into(),
                    ));
                }
                Ok(())
            }
            AuthConfig::AuroraFailover { endpoints } => {
                if endpoints.is_empty() {
                    return Err(AuthError::InvalidConfig(
                        "aurora_failover.endpoints must list at least one host".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Build a concrete [`AuthProvider`] for the configured variant.
    /// Each enabled feature flag adds the corresponding constructor;
    /// disabled-feature variants return `NotImplemented` with a clear
    /// pointer at the operator.
    ///
    /// Fallibility: for RDS the constructor itself does no network I/O
    /// (lazy AWS-config load deferred to `fetch_token`), but reserving
    /// `Result` keeps room for future providers that need a sync probe.
    pub async fn build_provider(&self) -> Result<Arc<dyn AuthProvider>, AuthError> {
        match self {
            AuthConfig::RdsIam {
                region,
                username,
                profile,
            } => {
                #[cfg(feature = "sql-rds-iam")]
                {
                    let p = rds_iam::RdsIamAuthProvider::new(
                        region.clone(),
                        username.clone(),
                        profile.clone(),
                    )
                    .await?;
                    Ok(Arc::new(p))
                }
                #[cfg(not(feature = "sql-rds-iam"))]
                {
                    let _ = (region, username, profile);
                    Err(AuthError::NotImplemented { scheme: "rds_iam" })
                }
            }
            AuthConfig::AzureAd { scope, tenant_id } => {
                #[cfg(feature = "sql-azure-ad")]
                {
                    let p = azure_ad::AzureAdAuthProvider::new(scope.clone(), tenant_id.clone())
                        .await?;
                    Ok(Arc::new(p))
                }
                #[cfg(not(feature = "sql-azure-ad"))]
                {
                    let _ = (scope, tenant_id);
                    Err(AuthError::NotImplemented { scheme: "azure_ad" })
                }
            }
            AuthConfig::GcpIam { username } => {
                #[cfg(feature = "sql-gcp-iam")]
                {
                    let p = gcp_iam::GcpIamAuthProvider::new(username.clone()).await?;
                    Ok(Arc::new(p))
                }
                #[cfg(not(feature = "sql-gcp-iam"))]
                {
                    let _ = username;
                    Err(AuthError::NotImplemented { scheme: "gcp_iam" })
                }
            }
            AuthConfig::AuroraFailover { endpoints } => {
                #[cfg(feature = "sql-aurora-failover")]
                {
                    let p =
                        aurora_failover::AuroraFailoverAuthProvider::new(endpoints.clone()).await?;
                    Ok(Arc::new(p))
                }
                #[cfg(not(feature = "sql-aurora-failover"))]
                {
                    let _ = endpoints;
                    Err(AuthError::NotImplemented {
                        scheme: "aurora_failover",
                    })
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// In-memory `AuthProvider` used by the rotator + driver-plumbing
/// tests. Returns a fixed token with a configurable TTL; an atomic
/// counter records every `fetch_token` call so tests can assert
/// rotation behavior without a real cloud round trip.
#[derive(Debug)]
pub struct MockAuthProvider {
    token: SecretToken,
    ttl: Duration,
    fetches: std::sync::atomic::AtomicUsize,
}

impl MockAuthProvider {
    /// New mock with the given fixed token + TTL.
    #[must_use]
    pub fn new(token: impl Into<String>, ttl: Duration) -> Self {
        Self {
            token: SecretToken::new(token),
            ttl,
            fetches: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Number of times `fetch_token` has been called. Tests assert
    /// this to verify rotation fires on schedule.
    #[must_use]
    pub fn fetch_count(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl AuthProvider for MockAuthProvider {
    fn scheme(&self) -> &'static str {
        "mock"
    }

    async fn fetch_token(&self) -> Result<SecretToken, AuthError> {
        self.fetches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.token.clone())
    }

    fn token_ttl(&self) -> Duration {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_provider_returns_fixed_token() {
        let p = MockAuthProvider::new("hunter2", Duration::from_secs(900));
        let t1 = p.fetch_token().await.unwrap();
        let t2 = p.fetch_token().await.unwrap();
        assert_eq!(t1.expose(), "hunter2");
        assert_eq!(t2.expose(), "hunter2");
        assert_eq!(p.fetch_count(), 2);
        assert_eq!(p.token_ttl(), Duration::from_secs(900));
        assert_eq!(p.scheme(), "mock");
    }

    #[test]
    fn secret_token_debug_redacts() {
        let s = SecretToken::new("super-secret-bearer");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret-bearer"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_config_rds_iam_validates_required_fields() {
        let bad = AuthConfig::RdsIam {
            region: "".into(),
            username: "app".into(),
            profile: None,
        };
        assert!(matches!(bad.validate(), Err(AuthError::InvalidConfig(_))));

        let bad = AuthConfig::RdsIam {
            region: "us-east-1".into(),
            username: "  ".into(),
            profile: None,
        };
        assert!(matches!(bad.validate(), Err(AuthError::InvalidConfig(_))));

        let good = AuthConfig::RdsIam {
            region: "us-east-1".into(),
            username: "app".into(),
            profile: None,
        };
        assert!(good.validate().is_ok());
        assert_eq!(good.scheme(), "rds_iam");
    }

    #[test]
    fn auth_config_serde_roundtrip() {
        let cfg = AuthConfig::RdsIam {
            region: "us-east-1".into(),
            username: "app".into(),
            profile: Some("prod".into()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        // Tagged enum: `"kind"` discriminator + flattened fields.
        assert!(json.contains("\"kind\":\"rds_iam\""));
        let back: AuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[tokio::test]
    async fn auth_error_into_sqlerror() {
        let e = AuthError::NotImplemented { scheme: "azure_ad" };
        let s: SqlError = e.into();
        match s {
            SqlError::InvalidSpec(msg) => {
                assert!(msg.contains("azure_ad"));
                assert!(msg.contains("not yet supported"));
            }
            _ => panic!("expected InvalidSpec"),
        }
    }
}
