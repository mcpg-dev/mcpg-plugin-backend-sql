//! cdylib sync bridge — adapts the async `BackendPlugin` /
//! `WatchStrategyPlugin` impls of the SQL crate onto the sync FFI traits
//! the cdylib vtable expects ([`SyncBackendPlugin`] /
//! [`SyncWatchStrategyPlugin`]). Each wrapper owns a private multi-thread
//! runtime and `block_on`s the async logic; the backend wrapper derives an
//! `Arc<dyn BackendHost>` from the make-time [`HostHandle`] (via
//! [`HostHandleBackendHost`]) for credential resolution + revocation /
//! rotation subscriptions through the host-FFI slots, and ALSO installs
//! the same handle on the inner plugin (`set_host_handle`) for unified
//! observability.
//!
//! Step 5b of the SQL backend migration. Mirrors the proven nats / kafka
//! pilots (`libs/plugins/backend/{nats,kafka}`). Deviations, all
//! intentional:
//!
//! - Three entities: one `backend` (kind `sql`) + two `watch_strategy`
//!   (kinds `sql_polling` + `postgres_listen_notify`). The backend
//!   overrides `execute_transaction` + `audit_metadata` (v35/v36) on top
//!   of the standard surface.
//! - The backend factory installs the host handle on the inner plugin
//!   (like the openai chat variants) AND wraps it for `register_profile`.
//! - No streaming: SQL doesn't stream, so `execute_streaming` /
//!   `cancel_stream` keep the buffered `SyncBackendPlugin` default.
//! - `from_host_config` ignores `config_json` — per-binding connection
//!   details (url, session_vars, …) arrive through the `register_profile`
//!   spec, not a plugin-level config block.
//!
//! The whole module is gated on the `postgres` feature: the cdylib is
//! always built with default features (postgres on), and the
//! `postgres_listen_notify` watch entity depends on the
//! `watch_pg_listen` module which is itself `#[cfg(feature = "postgres")]`.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest, ResourcePage,
    WatchError, WatchEvent, WatchEventSink, WatchHandle, WatchStrategyPlugin,
};
use mcpg_plugin_sdk::ffi::{SyncBackendPlugin, SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::SqlBackendPlugin;
use crate::watch::SqlPollingWatchPlugin;
use crate::watch_pg_listen::PostgresListenNotifyWatchPlugin;

/// Build the private multi-thread runtime each cdylib wrapper uses to
/// `block_on` its async inner plugin. Two worker threads + `enable_all`
/// — copied from the nats template.
fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("sql cdylib: tokio runtime init failed: {e}"))
}

// ---------------------------------------------------------------------------
// Backend bridge
// ---------------------------------------------------------------------------

/// `SyncBackendPlugin` bridge over [`SqlBackendPlugin`].
pub struct SqlBackendCdylib {
    inner: SqlBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl SqlBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — the SQL
    /// plugin carries no plugin-level config (per-binding url +
    /// session_vars etc. arrive via `register_profile`). The make-time
    /// [`HostHandle`] is installed on the inner plugin for unified
    /// observability AND wrapped into an `Arc<dyn BackendHost>` passed to
    /// `register_profile`.
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = SqlBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-sql"),
        }
    }
}

impl SyncBackendPlugin for SqlBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }
    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }
    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }
    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }
    fn execute_transaction(
        &self,
        backend_name: &str,
        tx_group: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendError> {
        self.rt.block_on(BackendPlugin::execute_transaction(
            &self.inner,
            backend_name,
            tx_group,
        ))
    }
    fn input_schema(&self, profile_name: &str) -> Option<serde_json::Value> {
        BackendPlugin::input_schema(&self.inner, profile_name)
    }
    fn output_schema(&self, profile_name: &str) -> Option<serde_json::Value> {
        BackendPlugin::output_schema(&self.inner, profile_name)
    }
    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }
    fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        self.rt.block_on(BackendPlugin::list_resources(
            &self.inner,
            profile_name,
            cursor,
        ))
    }
    fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        self.rt.block_on(BackendPlugin::complete_template_variable(
            &self.inner,
            profile_name,
            variable_name,
            prefix,
            config,
            context,
        ))
    }
    fn shutdown(&self) {
        self.rt.block_on(BackendPlugin::shutdown(&self.inner));
    }
}

// ---------------------------------------------------------------------------
// Watch bridges — shared sink + cancel-state machinery (defined once,
// reused by both watch wrappers; verbatim from the nats template).
// ---------------------------------------------------------------------------

/// Async `WatchEventSink` forwarding each event to the cdylib FFI
/// push-callback (serialized `WatchEvent` JSON).
struct ClosureWatchSink {
    emit: Box<dyn Fn(&str) + Send + Sync + 'static>,
}

#[async_trait::async_trait]
impl WatchEventSink for ClosureWatchSink {
    async fn emit(&self, event: WatchEvent) {
        match serde_json::to_string(&event) {
            Ok(json) => (self.emit)(&json),
            Err(e) => {
                tracing::warn!(error = %e, "sql watch: failed to serialize WatchEvent; dropping")
            }
        }
    }
}

/// Cancel state boxed behind the opaque [`WatchHandleBox`] pointer.
struct WatchCancelState {
    handle: Box<dyn WatchHandle>,
    rt: tokio::runtime::Handle,
}

/// `SyncWatchStrategyPlugin` bridge over [`SqlPollingWatchPlugin`].
pub struct SqlPollingWatchCdylib {
    inner: SqlPollingWatchPlugin,
    rt: tokio::runtime::Runtime,
}

impl SqlPollingWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the
    /// polling watcher carries no plugin-level config (per-watch
    /// connection + query arrive via the `watch` spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            inner: SqlPollingWatchPlugin::new(),
            rt: build_bridge_runtime("mcpg-watch-sql-polling"),
        }
    }
}

impl SyncWatchStrategyPlugin for SqlPollingWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        WatchStrategyPlugin::manifest(&self.inner)
    }
    fn kind(&self) -> &str {
        WatchStrategyPlugin::kind(&self.inner)
    }
    fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let sink = Arc::new(ClosureWatchSink { emit: emit_event });
        let handle = self.rt.block_on(WatchStrategyPlugin::watch(
            &self.inner,
            resource_uri,
            spec,
            sink,
        ))?;
        let state = Box::new(WatchCancelState {
            handle,
            rt: self.rt.handle().clone(),
        });
        Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
    }
    fn cancel(&self, watch_handle: WatchHandleBox) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: pointer produced by `Box::into_raw` in `watch`, round-
        // tripped by the host exactly once.
        #[allow(unsafe_code)]
        let state = unsafe { Box::from_raw(watch_handle.0 as *mut WatchCancelState) };
        state.rt.block_on(state.handle.cancel());
    }
}

/// `SyncWatchStrategyPlugin` bridge over [`PostgresListenNotifyWatchPlugin`].
pub struct PgListenWatchCdylib {
    inner: PostgresListenNotifyWatchPlugin,
    rt: tokio::runtime::Runtime,
}

impl PgListenWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the
    /// LISTEN/NOTIFY watcher carries no plugin-level config (per-watch
    /// connection + channel arrive via the `watch` spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            inner: PostgresListenNotifyWatchPlugin::new(),
            rt: build_bridge_runtime("mcpg-watch-pg-listen"),
        }
    }
}

impl SyncWatchStrategyPlugin for PgListenWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        WatchStrategyPlugin::manifest(&self.inner)
    }
    fn kind(&self) -> &str {
        WatchStrategyPlugin::kind(&self.inner)
    }
    fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let sink = Arc::new(ClosureWatchSink { emit: emit_event });
        let handle = self.rt.block_on(WatchStrategyPlugin::watch(
            &self.inner,
            resource_uri,
            spec,
            sink,
        ))?;
        let state = Box::new(WatchCancelState {
            handle,
            rt: self.rt.handle().clone(),
        });
        Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
    }
    fn cancel(&self, watch_handle: WatchHandleBox) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: pointer produced by `Box::into_raw` in `watch`, round-
        // tripped by the host exactly once.
        #[allow(unsafe_code)]
        let state = unsafe { Box::from_raw(watch_handle.0 as *mut WatchCancelState) };
        state.rt.block_on(state.handle.cancel());
    }
}

// ---------------------------------------------------------------------------
// cdylib export — three entities under `dev.mcpg.backend.sql`. Each watch
// entity self-describes via its `manifest()` slot (ids
// `dev.mcpg.watch.sql_polling` / `dev.mcpg.watch.postgres_listen_notify`)
// and is distinguished by its `inner_name` slug.
// ---------------------------------------------------------------------------
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.sql",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // SQL bindings self-configure a dynamic resource list (the gateway
    // merges per-binding `list_resources` output on `resources/list`), so
    // the kind declares `dynamic_list`. A SQL backend also dispatches
    // correctly as a pipeline step (through the generic envelope path), so it
    // declares `pipeline_capable`. Health is pool-tracked (Skip); label = kind.
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        dynamic_list: true,
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: SqlBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                SqlBackendCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch_polling {
            inner_name: "watch-polling",
            plugin_type: SqlPollingWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                SqlPollingWatchCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch_pg_listen {
            inner_name: "watch-pg-listen",
            plugin_type: PgListenWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                PgListenWatchCdylib::from_host_config(cfg, host),
        },
    ],
}
