//! AWS RDS IAM token auth provider.
//!
//! Generates a 15 min connection-auth token by sigv4-presigning the
//! `connect` action against an RDS endpoint. Equivalent of the AWS
//! CLI's `aws rds generate-db-auth-token`. The signed URL is the
//! token — Postgres passes it as the password and the RDS endpoint
//! verifies the signature.
//!
//! The provider does NOT call into `aws-sdk-rds` (a much larger crate
//! that pulls the full RDS control-plane API surface for a single
//! credential operation). Instead it composes the lower-level
//! `aws-config` + `aws-credential-types` + `aws-sigv4` crates that are
//! already present in the workspace via the `s3-content-store`
//! plugin — no new transitive bloat.
//!
//! Token TTL: hardcoded 900 s (15 min) — the AWS-side limit. The
//! rotator schedules refresh at `900 - safety_margin` seconds.
//!
//! Postgres-only initially. RDS supports IAM auth on MySQL too but
//! the wire-protocol bridge differs slightly — left as a small
//! follow-up; the trait + rotator layer are unchanged.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_config::Region;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_sigv4::http_request::{
    SignableBody, SignableRequest, SignatureLocation, SigningSettings, sign,
};
use aws_sigv4::sign::v4;

use super::{AuthError, AuthProvider, SecretToken};

/// 15 min — fixed by AWS RDS. Tokens older than this are rejected.
const RDS_TOKEN_TTL: Duration = Duration::from_secs(900);

/// Lazy-loaded AWS credentials provider chain.
#[derive(Clone)]
struct LoadedConfig {
    region: Region,
    creds: SharedCredentialsProvider,
}

/// AWS RDS / Aurora IAM token provider.
///
/// Construction is async because the AWS default-credential chain
/// load is async (env vars are sync, but the chain may probe IMDS /
/// SSO sources). The probe runs once at `register_profile` time —
/// runtime `fetch_token` calls re-read the cached chain and ask it
/// for fresh credentials, picking up any rotation under the gateway's
/// feet (e.g. EKS Pod Identity / IRSA token expiry).
pub struct RdsIamAuthProvider {
    region: String,
    username: String,
    /// Endpoint host:port — populated on first `fetch_token` from the
    /// connect URL via the rotator. We don't take it at construction
    /// because the operator may rotate the URL without changing the
    /// auth block (e.g. cert rotation pushed a new endpoint string).
    /// Captured into an `ArcSwap`-style cell on first use.
    endpoint: Arc<tokio::sync::OnceCell<RdsEndpoint>>,
    config: Arc<tokio::sync::OnceCell<LoadedConfig>>,
    /// Optional explicit profile name. When `Some`, overrides the env
    /// AWS_PROFILE for this provider's chain — useful when one
    /// gateway hosts multiple bindings each authenticating as
    /// different IAM principals.
    profile: Option<String>,
}

#[derive(Clone, Debug)]
struct RdsEndpoint {
    host: String,
    port: u16,
}

impl std::fmt::Debug for RdsIamAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdsIamAuthProvider")
            .field("region", &self.region)
            .field("username", &self.username)
            .field("profile", &self.profile)
            .finish()
    }
}

impl RdsIamAuthProvider {
    /// Build a new provider. Does not perform any AWS network I/O —
    /// the credential chain is loaded lazily on first `fetch_token`.
    /// `region` and `username` are validated at the [`AuthConfig`]
    /// layer before this is called; validation here is defensive.
    pub async fn new(
        region: String,
        username: String,
        profile: Option<String>,
    ) -> Result<Self, AuthError> {
        if region.trim().is_empty() {
            return Err(AuthError::InvalidConfig("rds_iam.region empty".into()));
        }
        if username.trim().is_empty() {
            return Err(AuthError::InvalidConfig("rds_iam.username empty".into()));
        }
        Ok(Self {
            region,
            username,
            endpoint: Arc::new(tokio::sync::OnceCell::new()),
            config: Arc::new(tokio::sync::OnceCell::new()),
            profile,
        })
    }

    /// Tell the provider which RDS endpoint these tokens authenticate
    /// against. Called by the driver layer once at pool-construction
    /// time after parsing the operator's URL. Idempotent: subsequent
    /// calls with the same endpoint are no-ops; a different endpoint
    /// fails with `InvalidConfig` (the binding's URL changed under
    /// the auth block — operators should restart the binding).
    pub fn set_endpoint(&self, host: String, port: u16) -> Result<(), AuthError> {
        let new = RdsEndpoint { host, port };
        match self.endpoint.set(new.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                let cur = self
                    .endpoint
                    .get()
                    .expect("OnceCell was set on the contended path");
                if cur.host == new.host && cur.port == new.port {
                    Ok(())
                } else {
                    Err(AuthError::InvalidConfig(format!(
                        "rds_iam: endpoint changed from {}:{} to {}:{}; \
                         re-register the binding to pick up the new URL",
                        cur.host, cur.port, new.host, new.port
                    )))
                }
            }
        }
    }

    async fn loaded_config(&self) -> Result<&LoadedConfig, AuthError> {
        self.config
            .get_or_try_init(|| async {
                let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(Region::new(self.region.clone()));
                if let Some(profile) = &self.profile {
                    loader = loader.profile_name(profile.clone());
                }
                let conf = loader.load().await;
                let creds = conf.credentials_provider().ok_or_else(|| {
                    AuthError::InvalidConfig(
                        "rds_iam: AWS default credential chain returned no provider \
                         — set AWS_ACCESS_KEY_ID / IRSA / instance profile / SSO"
                            .into(),
                    )
                })?;
                Ok::<LoadedConfig, AuthError>(LoadedConfig {
                    region: Region::new(self.region.clone()),
                    creds,
                })
            })
            .await
    }

    /// Pull a fresh set of AWS credentials from the cached chain, then
    /// sigv4-presign the RDS connect URL. The result IS the token —
    /// it's what sqlx feeds in as the password.
    async fn presign(&self) -> Result<String, AuthError> {
        let endpoint = self.endpoint.get().ok_or_else(|| {
            AuthError::InvalidConfig(
                "rds_iam: pool builder did not register a target endpoint with \
                 the auth provider; this is an internal wiring bug — file an issue"
                    .into(),
            )
        })?;
        let conf = self.loaded_config().await?;

        let creds = conf
            .creds
            .provide_credentials()
            .await
            .map_err(|e| AuthError::Fetch {
                message: "AWS credential chain refused to issue credentials".into(),
                source: Box::new(e),
            })?;

        // Build a `Signing` identity from the AWS Credentials. The
        // sigv4 presign API takes the identity directly.
        let identity = creds.into();
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(conf.region.as_ref())
            .name("rds-db")
            .time(SystemTime::now())
            .settings({
                let mut s = SigningSettings::default();
                s.signature_location = SignatureLocation::QueryParams;
                s.expires_in = Some(RDS_TOKEN_TTL);
                s
            })
            .build()
            .map_err(|e| AuthError::Fetch {
                message: "sigv4 signing params: build failed".into(),
                source: Box::new(e),
            })?;

        let url = format!(
            "https://{host}:{port}/?Action=connect&DBUser={user}",
            host = endpoint.host,
            port = endpoint.port,
            user = urlencoding::encode(&self.username)
        );
        let signable = SignableRequest::new(
            "GET",
            &url,
            std::iter::empty::<(&str, &str)>(),
            SignableBody::Bytes(b""),
        )
        .map_err(|e| AuthError::Fetch {
            message: "sigv4 signable request: build failed".into(),
            source: Box::new(e),
        })?;

        let (signing_instructions, _signature) = sign(signable, &signing_params.into())
            .map_err(|e| AuthError::Fetch {
                message: "sigv4 sign: failed".into(),
                source: Box::new(e),
            })?
            .into_parts();

        // Apply the signing instructions to a mutable URL copy and
        // strip the leading `https://` — RDS expects the bare host
        // segment + signed query.
        let mut url_buf = url::Url::parse(&url).map_err(|e| AuthError::Fetch {
            message: "parsing presigned URL: failed".into(),
            source: Box::new(e),
        })?;
        for (name, value) in signing_instructions.params() {
            url_buf.query_pairs_mut().append_pair(name, value);
        }

        // RDS expects the token as `<host>:<port>/?<signed query>`,
        // without scheme. Drop `https://`.
        let host = url_buf
            .host_str()
            .ok_or_else(|| AuthError::InvalidConfig("rds_iam: presigned URL has no host".into()))?;
        let token = match url_buf.query() {
            Some(q) => format!("{host}:{port}/?{q}", port = endpoint.port),
            None => format!("{host}:{port}/", port = endpoint.port),
        };
        Ok(token)
    }
}

#[async_trait]
impl AuthProvider for RdsIamAuthProvider {
    fn scheme(&self) -> &'static str {
        "rds_iam"
    }

    async fn fetch_token(&self) -> Result<SecretToken, AuthError> {
        let token = self.presign().await?;
        Ok(SecretToken::new(token))
    }

    fn token_ttl(&self) -> Duration {
        RDS_TOKEN_TTL
    }

    fn bind_endpoint(&self, host: &str, port: u16) -> Result<(), AuthError> {
        self.set_endpoint(host.to_owned(), port)
    }
}

// `urlencoding` and `url` are pulled transitively in the workspace; we
// only re-use them rather than adding new deps.
mod urlencoding {
    /// Minimal RFC 3986 path-segment encoder for the DB user. We only
    /// need to handle `+`, `=`, `&`, `/`, `?`, ` ` — RDS usernames in
    /// practice use `[a-zA-Z0-9_]`, but defensive encoding lets the
    /// operator paste a name verbatim without ambiguity.
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => {
                    out.push('%');
                    out.push_str(&format!("{b:02X}"));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn construction_rejects_empty_inputs() {
        assert!(matches!(
            RdsIamAuthProvider::new("".into(), "app".into(), None).await,
            Err(AuthError::InvalidConfig(_))
        ));
        assert!(matches!(
            RdsIamAuthProvider::new("us-east-1".into(), "  ".into(), None).await,
            Err(AuthError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn ttl_is_fifteen_minutes() {
        let p = RdsIamAuthProvider::new("us-east-1".into(), "app".into(), None)
            .await
            .unwrap();
        assert_eq!(p.token_ttl(), Duration::from_secs(900));
        assert_eq!(p.scheme(), "rds_iam");
    }

    #[tokio::test]
    async fn endpoint_idempotent_set_succeeds() {
        let p = RdsIamAuthProvider::new("us-east-1".into(), "app".into(), None)
            .await
            .unwrap();
        p.set_endpoint("db.example.com".into(), 5432).unwrap();
        // Same value: ok.
        p.set_endpoint("db.example.com".into(), 5432).unwrap();
        // Different host: refused.
        assert!(matches!(
            p.set_endpoint("other.example.com".into(), 5432),
            Err(AuthError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn fetch_without_endpoint_errors_clearly() {
        let p = RdsIamAuthProvider::new("us-east-1".into(), "app".into(), None)
            .await
            .unwrap();
        // No endpoint set → presign should refuse with InvalidConfig.
        let res = p.presign().await;
        match res {
            Err(AuthError::InvalidConfig(msg)) => {
                assert!(msg.contains("endpoint"));
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
}
