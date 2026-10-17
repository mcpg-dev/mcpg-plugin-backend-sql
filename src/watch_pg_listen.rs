//! PostgreSQL LISTEN/NOTIFY watch strategy.
//!
//! Implements [`WatchStrategyPlugin`] with `kind:
//! "postgres_listen_notify"`. Far lower overhead than polling for
//! change-notification workloads — the database pushes a NOTIFY only
//! when something changes, and the plugin re-emits it as a
//! [`WatchEvent`] without burning any idle CPU or round trips.
//!
//! # Typical trigger
//!
//! Operators pair this watch with a Postgres trigger that fires
//! `NOTIFY <channel>, <payload>` on row changes they care about:
//!
//! ```sql
//! CREATE OR REPLACE FUNCTION notify_orders_changed() RETURNS trigger AS $$
//! BEGIN
//!     PERFORM pg_notify('orders_changed', row_to_json(NEW)::text);
//!     RETURN NEW;
//! END;
//! $$ LANGUAGE plpgsql;
//!
//! CREATE TRIGGER orders_changed_trigger
//! AFTER INSERT OR UPDATE ON orders
//! FOR EACH ROW EXECUTE FUNCTION notify_orders_changed();
//! ```
//!
//! # Connection lifecycle
//!
//! Each watcher holds one dedicated connection for the lifetime of
//! the subscription — `pg_notify` only delivers to sessions that
//! `LISTEN`ed before the NOTIFY fired, and connection pooling would
//! lose events between checkouts. The underlying sqlx `PgListener`
//! re-connects transparently on disconnection and re-issues `LISTEN`
//! for the subscribed channel.
//!
//! # Payload handling
//!
//! The NOTIFY payload is forwarded in the [`WatchEvent`]'s `user_id`
//! field if it parses as a small JSON object with a `user_id` key —
//! this lets subject-scoped notification filters fan out only to the
//! owning subscriber. Any other payload shape results in a generic
//! broadcast event.
//!
//! # Transactional visibility
//!
//! Postgres `NOTIFY` is **buffered until the producing transaction
//! commits** — listeners never observe a NOTIFY whose transaction
//! later rolled back. This means the trigger above only fires the
//! `pg_notify(...)` call when the row write itself succeeds; there
//! is no extra suppression to wire on the gateway side.
//!
//! Two operator-facing implications:
//!
//! 1. **Use `AFTER` triggers**, not `BEFORE` — the conventional
//!    shape and matches operator intent ("the row exists, tell
//!    subscribers"). NOTIFY queues either way and delivers on COMMIT,
//!    but `AFTER` ensures the trigger sees the final NEW row.
//! 2. **Long open transactions delay delivery**, since the NOTIFY
//!    queue only flushes on COMMIT. If a transaction stays open
//!    waiting on an `await:` block and the `await` predicate
//!    polls the same row the trigger fires on, the listener will
//!    not see the NOTIFY until the outer tx commits — usually fine,
//!    but worth knowing when debugging "NOTIFY didn't fire" reports.
//!
//! No coordination knob exists for this: it's a Postgres-protocol
//! property, and the right answer is to keep transactions short.

use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    PluginManifest, WatchError, WatchEvent, WatchEventSink, WatchHandle, WatchStrategyPlugin,
    firstparty_manifest,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::errors::SqlError;

/// Per-watch spec.
///
/// Example TOML:
/// ```toml
/// [watch.orders_changes]
/// strategy = "postgres_listen_notify"
/// url      = "postgres://app:${env.ORDERS_DB_PW}@db/orders"
/// channel  = "orders_changed"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresListenNotifyWatchSpec {
    /// Connection URL. Credential interpolation (`${env.VAR}`,
    /// future `vault:…` / `aws-sm:…`) happens at the gateway before
    /// the spec reaches this plugin.
    pub url: String,
    /// Channel to LISTEN on. Quoted at the driver layer so
    /// case-sensitive names work.
    pub channel: String,
}

impl PostgresListenNotifyWatchSpec {
    fn validate(&self) -> Result<(), SqlError> {
        if self.url.trim().is_empty() {
            return Err(SqlError::InvalidSpec("watch.url must not be empty".into()));
        }
        if self.channel.trim().is_empty() {
            return Err(SqlError::InvalidSpec(
                "watch.channel must not be empty".into(),
            ));
        }
        // Basic sanity on the channel name — PgListener quotes it so
        // arbitrary characters technically work, but mcpg reserves
        // plain-ASCII names for operational clarity.
        if !self
            .channel
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(SqlError::InvalidSpec(format!(
                "watch.channel must be ASCII alphanumeric + underscore; got '{}'",
                self.channel
            )));
        }
        Ok(())
    }
}

/// `WatchStrategyPlugin` for `kind: "postgres_listen_notify"`.
pub struct PostgresListenNotifyWatchPlugin {
    manifest: PluginManifest,
}

impl std::fmt::Debug for PostgresListenNotifyWatchPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresListenNotifyWatchPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

impl Default for PostgresListenNotifyWatchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresListenNotifyWatchPlugin {
    /// Build a watch plugin using the default manifest.
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.watch.postgres_listen_notify",
                name: "Postgres LISTEN/NOTIFY Watch",
                class: WatchStrategy,
            },
        }
    }
}

/// Handle returned to the host. Cancellation tears down the LISTEN
/// task and closes the pinned connection.
struct PostgresListenNotifyWatchHandle {
    cancel: CancellationToken,
}

#[async_trait]
impl WatchHandle for PostgresListenNotifyWatchHandle {
    async fn cancel(&self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl WatchStrategyPlugin for PostgresListenNotifyWatchPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "postgres_listen_notify"
    }

    async fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError> {
        let parsed: PostgresListenNotifyWatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("postgres_listen_notify watch spec: {e}"),
            })?;
        parsed.validate().map_err(|e| WatchError::InvalidSpec {
            message: e.to_string(),
        })?;

        #[cfg(not(feature = "postgres"))]
        {
            return Err(WatchError::InvalidSpec {
                message: "postgres_listen_notify watch requires the \
                          mcpg-plugin-backend-sql `postgres` feature"
                    .into(),
            });
        }

        #[cfg(feature = "postgres")]
        {
            let mut listener = sqlx::postgres::PgListener::connect(&parsed.url)
                .await
                .map_err(|e| WatchError::Subscribe {
                    message: format!("open LISTEN connection: {e}"),
                })?;
            listener
                .listen(&parsed.channel)
                .await
                .map_err(|e| WatchError::Subscribe {
                    message: format!("LISTEN {}: {e}", parsed.channel),
                })?;
            info!(
                uri = %resource_uri,
                channel = %parsed.channel,
                "postgres_listen_notify: subscribed"
            );

            let cancel = CancellationToken::new();
            let cancel_child = cancel.clone();
            let uri_owned = resource_uri.to_owned();
            let channel_owned = parsed.channel.clone();
            let event_source = mcpg_plugin_protocol::is_event_source(resource_uri);

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_child.cancelled() => {
                            debug!(uri = %uri_owned, "postgres_listen_notify: cancelled");
                            return;
                        }
                        recv_res = listener.recv() => {
                            match recv_res {
                                Ok(notif) => {
                                    let event = event_from_payload(
                                        notif.channel(),
                                        notif.payload(),
                                        event_source,
                                    );
                                    sink.emit(event).await;
                                }
                                Err(e) => {
                                    // PgListener reconnects transparently; a
                                    // `recv` error usually means the pool is
                                    // closing. Log and let the outer cancel
                                    // path handle teardown.
                                    warn!(
                                        uri = %uri_owned,
                                        channel = %channel_owned,
                                        error = %e,
                                        "postgres_listen_notify: recv error; \
                                         awaiting cancel"
                                    );
                                    cancel_child.cancelled().await;
                                    return;
                                }
                            }
                        }
                    }
                }
            });

            Ok(Box::new(PostgresListenNotifyWatchHandle { cancel }))
        }
    }
}

/// The MCP Events type every NOTIFY is emitted as.
pub const NOTIFICATION_EVENT_TYPE: &str = "postgres.notification";

/// Build a `WatchEvent` from a NOTIFY on `channel`. If the payload is a
/// JSON object with a string `user_id` / `session_id`, those propagate so
/// subject-scoped resource filters can fan out selectively. For an MCP
/// Events source (`event_source`) the event also carries
/// `{channel, payload, payloadEncoding}` as its data: the payload's JSON
/// when it is JSON, else its text. A resource watch wants only the change.
fn event_from_payload(channel: &str, payload: &str, event_source: bool) -> WatchEvent {
    let parsed = serde_json::from_str::<serde_json::Value>(payload).ok();
    let field = |name: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.get(name))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    let mut event = WatchEvent {
        user_id: field("user_id"),
        session_id: field("session_id"),
        ..WatchEvent::default()
    };
    if event_source {
        let (body, encoding) = mcpg_plugin_protocol::event_body(payload.as_bytes());
        event.event_type = Some(NOTIFICATION_EVENT_TYPE.to_owned());
        event.data = Some(serde_json::json!({
            "channel": channel,
            "payload": body,
            "payloadEncoding": encoding,
        }));
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spec_parses_minimal() {
        let s: PostgresListenNotifyWatchSpec = serde_json::from_value(json!({
            "url": "postgres://app@localhost/db",
            "channel": "orders_changed"
        }))
        .unwrap();
        assert_eq!(s.channel, "orders_changed");
    }

    #[test]
    fn validate_rejects_empty_url() {
        let s: PostgresListenNotifyWatchSpec = serde_json::from_value(json!({
            "url": "",
            "channel": "x"
        }))
        .unwrap();
        let err = s.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("url")));
    }

    #[test]
    fn validate_rejects_empty_channel() {
        let s: PostgresListenNotifyWatchSpec = serde_json::from_value(json!({
            "url": "postgres://app@localhost/db",
            "channel": ""
        }))
        .unwrap();
        let err = s.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("channel")));
    }

    #[test]
    fn validate_rejects_channel_with_suspicious_chars() {
        // The pg side quotes channel names, but mcpg restricts to
        // plain ASCII for operational clarity — unusual characters
        // usually mean a config typo or an injection attempt.
        let s: PostgresListenNotifyWatchSpec = serde_json::from_value(json!({
            "url": "postgres://app@localhost/db",
            "channel": "ordersxDROP TABLE"
        }))
        .unwrap();
        let err = s.validate().unwrap_err();
        assert!(matches!(err, SqlError::InvalidSpec(m) if m.contains("channel")));
    }

    #[test]
    fn event_from_payload_empty_is_default() {
        let e = event_from_payload("orders", "", true);
        assert!(e.user_id.is_none());
        assert!(e.session_id.is_none());
        assert_eq!(
            e.data,
            Some(json!({ "channel": "orders", "payload": "", "payloadEncoding": "text" }))
        );
    }

    #[test]
    fn event_from_payload_extracts_user_id() {
        let e = event_from_payload("orders", r#"{"user_id": "u-42", "data": {}}"#, false);
        assert_eq!(e.user_id.as_deref(), Some("u-42"));
        assert!(e.session_id.is_none());
    }

    #[test]
    fn event_from_payload_extracts_session_id() {
        let e = event_from_payload("orders", r#"{"session_id": "sess-abc"}"#, false);
        assert_eq!(e.session_id.as_deref(), Some("sess-abc"));
    }

    #[test]
    fn event_from_payload_ignores_unparseable_payload() {
        // Trigger authors sometimes use `NOTIFY channel, 'free text'`
        // — not JSON. Plugin should still emit a broadcast event.
        let e = event_from_payload("orders", "row 42 changed", true);
        assert!(e.user_id.is_none());
        assert_eq!(
            e.data,
            Some(json!({
                "channel": "orders", "payload": "row 42 changed", "payloadEncoding": "text"
            }))
        );
    }

    #[test]
    fn a_notification_is_an_mcp_events_occurrence_with_its_json_payload() {
        let e = event_from_payload("orders", r#"{"id": 7, "total": 12}"#, true);
        assert_eq!(e.event_type.as_deref(), Some(NOTIFICATION_EVENT_TYPE));
        assert_eq!(
            e.data,
            Some(json!({
                "channel": "orders",
                "payload": { "id": 7, "total": 12 },
                "payloadEncoding": "json",
            }))
        );
    }

    /// A resource watch wants only the change; the payload is an event
    /// source's alone.
    #[test]
    fn a_resource_watch_gets_no_payload() {
        let e = event_from_payload("orders", r#"{"id": 7, "user_id": "u-1"}"#, false);
        assert_eq!(e.user_id.as_deref(), Some("u-1"));
        assert!(e.event_type.is_none() && e.data.is_none());
    }
}
