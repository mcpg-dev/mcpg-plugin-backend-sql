//! In-flight query registry.
//!
//! Tracks every `execute` call from first line of the plugin entry
//! point through response emission. Each entry is keyed by the
//! gateway-assigned `request_id` and carries the binding name, driver
//! kind, and start timestamp.
//!
//! The registry is the hook point for:
//!
//! - **Observability** — `mcpg_sql_requests_in_flight` gauge tracks
//!   how many queries the plugin is actively running. Operator admin
//!   tooling can snapshot the table for age / slow-query surfacing.
//! - **Cancellation** — when MCP cancel delivery lands,
//!   each entry will carry a driver-level backend identifier
//!   (Postgres PID / MySQL connection ID / SQLite handle) so a side
//!   channel can send `pg_cancel_backend` / `KILL QUERY` /
//!   `sqlite3_interrupt`. That field is wired up here but populated
//!   lazily — first implementation lands with the cancel driver hooks
//!   themselves in the next phase.
//!
//! # RAII contract
//!
//! Registration happens through [`InFlightGuard`]. The guard inserts
//! into the map on construction and removes on drop — panics and
//! early returns both cause removal, so the map cannot leak entries.
//! Do not call [`InFlightRegistry::register`] or `unregister` directly
//! from outside this module; use the guard.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use dashmap::DashMap;
use serde::Serialize;

use crate::config::DriverKind;

/// Driver-level backend identifier used for targeted cancel in later
/// phases. Kept behind an `Arc<parking_lot::Mutex<_>>` on the entry so
/// the driver can fill it in asynchronously after the connection is
/// acquired, without blocking registration.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "driver", rename_all = "snake_case")]
#[allow(missing_docs)] // Variants documented; field docs are trivial.
pub enum BackendId {
    /// Postgres backend PID (from `pg_backend_pid()`).
    Postgres { pid: i32 },
    /// MySQL connection identifier (from `CONNECTION_ID()`).
    Mysql { connection_id: u64 },
    /// SQLite has no server-side id; stored as a handle nonce so we
    /// can disambiguate concurrent calls on the same pool.
    Sqlite { handle: u64 },
}

/// Per-call registry entry.
#[derive(Debug)]
pub struct InFlightEntry {
    /// Operator-declared binding name this call targets.
    pub backend_name: String,
    /// Engine the call hit.
    pub driver: DriverKind,
    /// Wall-clock start (for telemetry).
    pub started_at_wall: SystemTime,
    /// Monotonic start (for age computation — survives wall-clock
    /// skew).
    pub started_at_mono: Instant,
    /// Populated by the driver after it acquires a connection and
    /// resolves the backend identifier. `None` before the driver
    /// reaches that point; never reverts from `Some` back to `None`.
    pub backend_id: parking_lot::Mutex<Option<BackendId>>,
}

/// Plugin-owned registry. Cloned as an `Arc<InFlightRegistry>` into
/// the [`crate::SqlBackendPlugin`] and into each [`InFlightGuard`].
#[derive(Debug, Default)]
pub struct InFlightRegistry {
    entries: DashMap<String, Arc<InFlightEntry>>,
}

impl InFlightRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of currently-in-flight requests. Used by
    /// the gauge metric.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff the registry has no in-flight entries. Primarily for
    /// tests; production callers use [`len`](Self::len).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Attach a backend identifier to an entry. Called by the driver
    /// once it has acquired a connection and resolved the id.
    /// No-op if the entry is no longer in the map (the request
    /// already completed).
    pub fn set_backend_id(&self, request_id: &str, id: BackendId) {
        if let Some(entry) = self.entries.get(request_id) {
            *entry.backend_id.lock() = Some(id);
        }
    }

    /// Read a request's backend id. Returns `None` if the request is
    /// no longer registered or the driver hasn't yet captured the
    /// backend id. Used by cancel paths and by tests that need to
    /// observe id population without holding a registry lock.
    #[must_use]
    pub fn backend_id_for(&self, request_id: &str) -> Option<BackendId> {
        self.entries
            .get(request_id)
            .and_then(|entry| *entry.backend_id.lock())
    }

    /// Snapshot the in-flight table for observability tooling. Each
    /// entry is captured with its current age.
    pub fn snapshot(&self) -> Vec<InFlightSnapshot> {
        let now_mono = Instant::now();
        self.entries
            .iter()
            .map(|kv| {
                let entry = kv.value();
                InFlightSnapshot {
                    request_id: kv.key().clone(),
                    backend_name: entry.backend_name.clone(),
                    driver: entry.driver,
                    started_at_wall: entry.started_at_wall,
                    age_ms: now_mono
                        .saturating_duration_since(entry.started_at_mono)
                        .as_millis() as u64,
                    backend_id: *entry.backend_id.lock(),
                }
            })
            .collect()
    }

    // ---- internal: used only by InFlightGuard ----

    fn insert(&self, request_id: String, entry: Arc<InFlightEntry>) {
        self.entries.insert(request_id, entry);
    }

    fn remove(&self, request_id: &str) {
        self.entries.remove(request_id);
    }
}

/// Operator-facing snapshot. Serializable so admin tools can dump the
/// in-flight table over HTTP.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)] // field names are self-describing
pub struct InFlightSnapshot {
    pub request_id: String,
    pub backend_name: String,
    pub driver: DriverKind,
    pub started_at_wall: SystemTime,
    pub age_ms: u64,
    pub backend_id: Option<BackendId>,
}

/// RAII registration guard. Insert-on-new, remove-on-drop — panics
/// and early returns both unregister. The guard holds an `Arc` to
/// the registry so the drop path works even if the plugin is dropped
/// mid-flight (impractical in real deployments but correct under
/// test teardown).
#[must_use = "dropping the guard unregisters the entry; bind it to a local to keep the request live"]
pub struct InFlightGuard {
    registry: Arc<InFlightRegistry>,
    request_id: String,
    /// Retained so the Drop impl can re-label the gauge without
    /// looking it up through the registry.
    driver: DriverKind,
}

impl InFlightGuard {
    /// Register a new call and return the guard. Caller must retain
    /// the guard for the duration of the DB work. Refreshes the
    /// `mcpg_sql_requests_in_flight` gauge on both register and drop.
    pub fn register(
        registry: Arc<InFlightRegistry>,
        request_id: String,
        backend_name: String,
        driver: DriverKind,
    ) -> Self {
        let entry = Arc::new(InFlightEntry {
            backend_name,
            driver,
            started_at_wall: SystemTime::now(),
            started_at_mono: Instant::now(),
            backend_id: parking_lot::Mutex::new(None),
        });
        registry.insert(request_id.clone(), entry);
        crate::metrics::record_in_flight(registry.len(), driver);
        Self {
            registry,
            request_id,
            driver,
        }
    }

    /// The request id the guard is registered under. Drivers call
    /// [`InFlightRegistry::set_backend_id`] with this key after they
    /// acquire a connection.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.request_id);
        crate::metrics::record_in_flight(self.registry.len(), self.driver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_registers_on_create_and_unregisters_on_drop() {
        let reg = Arc::new(InFlightRegistry::new());
        assert_eq!(reg.len(), 0);
        {
            let _g = InFlightGuard::register(
                reg.clone(),
                "req-1".into(),
                "orders.lookup".into(),
                DriverKind::Postgres,
            );
            assert_eq!(reg.len(), 1);
            let snap = reg.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].request_id, "req-1");
            assert_eq!(snap[0].backend_name, "orders.lookup");
            assert!(snap[0].backend_id.is_none());
        }
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn guard_unregisters_on_panic_unwind() {
        // The guard is RAII — even if the surrounding task panics
        // and unwinds, drop runs and the entry is removed. Proves
        // no leaks under error paths. `AssertUnwindSafe` here is a
        // test-scope assertion that our internal state machine is
        // panic-safe (the Drop impl is the single mutation path).
        let reg = Arc::new(InFlightRegistry::new());
        let reg_probe = reg.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _g = InFlightGuard::register(
                reg_probe,
                "req-panic".into(),
                "b".into(),
                DriverKind::Sqlite,
            );
            panic!("simulated driver panic");
        }));
        assert!(result.is_err());
        assert_eq!(reg.len(), 0, "registry must be empty after panic unwind");
    }

    #[test]
    fn backend_id_lazy_fill_is_visible_in_snapshot() {
        let reg = Arc::new(InFlightRegistry::new());
        let _g = InFlightGuard::register(
            reg.clone(),
            "req-bid".into(),
            "b".into(),
            DriverKind::Postgres,
        );
        assert!(reg.snapshot()[0].backend_id.is_none());
        reg.set_backend_id("req-bid", BackendId::Postgres { pid: 4242 });
        match reg.snapshot()[0].backend_id {
            Some(BackendId::Postgres { pid }) => assert_eq!(pid, 4242),
            other => panic!("unexpected backend_id variant: {other:?}"),
        }
    }

    #[test]
    fn set_backend_id_for_missing_key_is_noop() {
        // After a guard drops, stray set_backend_id calls must not
        // panic or re-create the entry.
        let reg = Arc::new(InFlightRegistry::new());
        reg.set_backend_id("nope", BackendId::Sqlite { handle: 1 });
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn concurrent_registrations_do_not_interfere() {
        use std::thread;
        let reg = Arc::new(InFlightRegistry::new());
        let mut handles = Vec::new();
        for i in 0..16 {
            let r = reg.clone();
            handles.push(thread::spawn(move || {
                let guard = InFlightGuard::register(
                    r,
                    format!("req-{i}"),
                    "b".into(),
                    DriverKind::Postgres,
                );
                // Hold briefly.
                std::thread::sleep(std::time::Duration::from_millis(5));
                drop(guard);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(reg.len(), 0);
    }
}
