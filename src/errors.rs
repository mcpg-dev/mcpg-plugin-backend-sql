//! SQL-specific error taxonomy and projection to [`BackendError`].
//!
//! Internal code uses [`SqlError`] so we keep the driver error source
//! chain around for tracing fields. At the plugin boundary the error is
//! projected to [`BackendError`].

use mcpg_plugin_protocol::BackendError;
use thiserror::Error;

use crate::redact::redact_in_text;

/// SQL driver / binding error.
///
/// Preserves the source chain via `#[source]` so upstream can attach
/// the underlying driver error to a `tracing` span. Converted to the
/// coarser [`BackendError`] at the plugin's public surface.
#[derive(Debug, Error)]
pub enum SqlError {
    /// Pool acquire exceeded its wait timeout.
    #[error("pool acquire timeout after {0}ms")]
    PoolTimeout(u64),

    /// Failed to open a new driver connection.
    #[error("connect failed: {0}")]
    Connect(#[source] sqlx::Error),

    /// Statement PREPARE failed (syntax error, missing column, etc).
    #[error("prepare failed: {0}")]
    Prepare(#[source] sqlx::Error),

    /// Statement EXECUTE failed (constraint violation, privilege error, …).
    #[error("execute failed: {0}")]
    Execute(#[source] sqlx::Error),

    /// Serialization/type error decoding a row into JSON.
    #[error("serialize row failed: {0}")]
    Serialize(String),

    /// Query ran longer than the configured `timeout_ms`.
    #[error("query timed out after {0}ms")]
    Timeout(u64),

    /// The binding was asked to run with a name that was never registered.
    #[error("no execution profile registered for '{0}'")]
    ProfileNotFound(String),

    /// Operator-facing spec was malformed or internally inconsistent.
    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    /// Driver error not otherwise classified. Prefer a specific variant.
    #[error("driver error: {0}")]
    Driver(#[source] sqlx::Error),
}

impl SqlError {
    /// Classify a `sqlx::Error` into the most specific [`SqlError`]
    /// variant the plugin can map. Used by driver adapters after a
    /// failed `prepare`/`execute`.
    pub fn from_execute(err: sqlx::Error) -> Self {
        // Very conservative mapping — we currently bucket database
        // errors into `Execute` and let [`BackendError`] handle the
        // retryability signal. A richer SQLSTATE-aware classifier is
        // future work.
        match err {
            sqlx::Error::PoolTimedOut => SqlError::PoolTimeout(0),
            sqlx::Error::PoolClosed => SqlError::Driver(sqlx::Error::PoolClosed),
            other => SqlError::Execute(other),
        }
    }
}

/// True when the underlying database error indicates a stale
/// prepared-statement cache — typically triggered by a
/// concurrent DDL change to a referenced table or function. The
/// driver safely retries the statement once on a fresh connection;
/// sqlx's per-connection cache evicts the stale entry on the retry
/// so the second attempt succeeds.
///
/// SQLSTATE codes we treat as stale-statement signals:
///
/// | Code    | Engine   | Meaning                                                      |
/// |---------|----------|--------------------------------------------------------------|
/// | `26000` | Postgres | Invalid prepared-statement name (cache drift)                |
/// | `42P18` | Postgres | Indeterminate datatype after DDL                             |
/// | `0A000` | Postgres | Cached plan must not change result type (row-shape drift)    |
/// | MySQL 1615 | MySQL | `ER_NEED_REPREPARE` — prepared statement must be re-prepared |
///
/// Anything else is propagated unchanged.
pub fn is_stale_statement_error(err: &sqlx::Error) -> bool {
    use sqlx::error::DatabaseError;
    let Some(db_err): Option<&dyn DatabaseError> = err.as_database_error() else {
        return false;
    };
    // `code()` returns a `Cow<str>` of the SQLSTATE for Postgres /
    // the MySQL error number for MySQL. Both are compared against
    // the stale-statement set below.
    let Some(code) = db_err.code() else {
        return false;
    };
    matches!(code.as_ref(), "26000" | "42P18" | "0A000" | "1615")
}

#[cfg(test)]
mod stale_tests {
    use super::is_stale_statement_error;

    #[test]
    fn non_database_errors_are_not_stale() {
        assert!(!is_stale_statement_error(&sqlx::Error::PoolTimedOut));
        assert!(!is_stale_statement_error(&sqlx::Error::PoolClosed));
    }
}

impl From<SqlError> for BackendError {
    fn from(err: SqlError) -> Self {
        match err {
            SqlError::PoolTimeout(ms) => BackendError::Timeout { timeout_ms: ms },
            SqlError::Timeout(ms) => BackendError::Timeout { timeout_ms: ms },
            SqlError::ProfileNotFound(name) => BackendError::ProfileNotFound { backend_name: name },
            SqlError::InvalidSpec(message) => BackendError::InvalidSpec {
                message: redact_in_text(&message),
            },
            SqlError::Serialize(message) => BackendError::Transport {
                message: format!("row serialization failed: {}", redact_in_text(&message)),
            },
            // Connection-class failures project to `Transport`
            // (retryable). Error text flows through `redact_in_text`
            // as defense in depth — if sqlx ever embeds a
            // password-bearing URL in its error, we strip it before
            // emission.
            SqlError::Connect(inner) => BackendError::Transport {
                message: format!("connect: {}", redact_in_text(&inner.to_string())),
            },
            SqlError::Driver(inner) => BackendError::Transport {
                message: format!("driver: {}", redact_in_text(&inner.to_string())),
            },
            SqlError::Prepare(inner) => BackendError::Transport {
                message: format!("prepare: {}", redact_in_text(&inner.to_string())),
            },
            SqlError::Execute(inner) => BackendError::Transport {
                message: format!("execute: {}", redact_in_text(&inner.to_string())),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_not_found_projects_to_binding_error() {
        let err: BackendError = SqlError::ProfileNotFound("orders".into()).into();
        assert!(matches!(
            err,
            BackendError::ProfileNotFound { ref backend_name } if backend_name == "orders"
        ));
    }

    #[test]
    fn invalid_spec_projects_to_binding_error() {
        let err: BackendError = SqlError::InvalidSpec("bad".into()).into();
        assert!(matches!(err, BackendError::InvalidSpec { ref message } if message == "bad"));
    }

    #[test]
    fn timeout_projects_to_binding_error() {
        let err: BackendError = SqlError::Timeout(1234).into();
        assert!(matches!(err, BackendError::Timeout { timeout_ms: 1234 }));
    }
}
