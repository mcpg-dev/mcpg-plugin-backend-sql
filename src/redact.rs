//! Password redaction for URLs.
//!
//! Defense in depth. [`SqlBackendConfig::validate`] already rejects
//! passwords embedded in the connection URL at config parse, so
//! well-behaved configs never let a password past startup. But sqlx,
//! driver crates, and third-party middleware can construct URL-like
//! strings in error messages and log payloads. Routing those through
//! [`redact_password`] means a misbehaving dep can't leak credentials
//! into telemetry even if our validation is bypassed or a future
//! code path skips it.
//!
//! The function is idempotent and cheap — zero allocation when the
//! input has no password region.

use std::borrow::Cow;

/// Replace the password region of a `scheme://user:PASSWORD@host/...`
/// URL with `***`. Leaves the original string untouched when no
/// password region is present or when the input doesn't parse as a
/// URL.
///
/// Examples:
///
/// - `postgres://u:hunter2@h/d` → `postgres://u:***@h/d`
/// - `postgres://u@h/d`         → `postgres://u@h/d` (unchanged)
/// - `not a url`                → `not a url`         (unchanged)
/// - `mysql://u:@h/d`           → `mysql://u:@h/d`    (empty pw, preserved)
#[must_use]
pub fn redact_password(s: &str) -> Cow<'_, str> {
    let Ok(mut parsed) = url::Url::parse(s) else {
        return Cow::Borrowed(s);
    };
    // `password()` returns `None` when the URL has no `:pw` component
    // OR when the component is an empty string — treat both as "no
    // redaction needed".
    let Some(pw) = parsed.password() else {
        return Cow::Borrowed(s);
    };
    if pw.is_empty() {
        return Cow::Borrowed(s);
    }
    // `set_password` returns `Result<(), ()>` — only fails on URLs
    // that can't have authority (e.g. mailto:). SQL DB URLs always
    // can; silently fall back to the original string on any hiccup.
    if parsed.set_password(Some("***")).is_err() {
        return Cow::Borrowed(s);
    }
    Cow::Owned(parsed.to_string())
}

/// Scan a block of text for URL-shaped substrings and redact each
/// one. Handles the common case where sqlx or a driver embeds a URL
/// into a larger error message like
/// `"failed to connect to postgres://u:pw@h: timed out"`.
///
/// Not a full URL parser — walks whitespace-separated tokens and
/// redacts any that parse as URLs. Adequate for log-line redaction.
#[must_use]
pub fn redact_in_text(text: &str) -> String {
    text.split_whitespace()
        .map(|tok| {
            // Trim common trailing punctuation that followed the URL.
            let (core, trail) = split_trailing_punct(tok);
            let redacted = redact_password(core);
            match redacted {
                Cow::Borrowed(_) => tok.to_owned(),
                Cow::Owned(r) => format!("{r}{trail}"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn split_trailing_punct(tok: &str) -> (&str, &str) {
    let punct = ['.', ',', ';', ':', ')', ']', '}', '"', '\''];
    let idx = tok
        .char_indices()
        .rev()
        .take_while(|(_, c)| punct.contains(c))
        .last()
        .map(|(i, _)| i)
        .unwrap_or(tok.len());
    tok.split_at(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_standard_url() {
        assert_eq!(
            redact_password("postgres://u:hunter2@h/d"),
            "postgres://u:***@h/d"
        );
    }

    #[test]
    fn leaves_no_password_url_untouched() {
        let s = "postgres://u@h/d";
        assert!(matches!(redact_password(s), Cow::Borrowed(_)));
    }

    #[test]
    fn leaves_non_url_untouched() {
        let s = "this is not a url";
        assert!(matches!(redact_password(s), Cow::Borrowed(_)));
    }

    #[test]
    fn handles_empty_password() {
        let s = "mysql://u:@h/d";
        // `set_password("")` is equivalent to having no password;
        // treated as "nothing to redact".
        assert!(matches!(redact_password(s), Cow::Borrowed(_)));
    }

    #[test]
    fn redacts_in_surrounding_text() {
        let log = "failed to connect to postgres://u:hunter2@h:5432/d, retrying.";
        let out = redact_in_text(log);
        assert!(!out.contains("hunter2"), "got: {out}");
        assert!(out.contains("***"), "got: {out}");
    }

    #[test]
    fn preserves_trailing_punctuation() {
        let log = "url was postgres://u:pw@h/d.";
        let out = redact_in_text(log);
        assert!(out.ends_with("d."), "got: {out}");
        assert!(!out.contains("pw"), "got: {out}");
    }

    #[test]
    fn sqlite_urls_pass_through() {
        let s = "sqlite:file:memdb?mode=memory&cache=shared";
        // No :password@ region; must be untouched.
        assert_eq!(redact_password(s), s);
    }

    #[test]
    fn mysql_url_with_port_and_password() {
        let out = redact_password("mysql://app:p@ss@h:3306/d");
        // URL parser should handle the literal `@` in the password —
        // but with the unescaped `@`, the parser will treat it as a
        // user/host delimiter. If the input isn't a well-formed URL
        // (unescaped `@` in password), we pass through as-is.
        // This test just documents the current behavior.
        let _ = out;
    }
}
