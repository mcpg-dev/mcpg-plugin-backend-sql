//! `sql_changes`: each row of a keyset query is one change event.
//!
//! The operator writes a keyset query: rows after the last key, in key
//! order, at most `:_limit` of them. The plugin binds the last key it
//! emitted to `:_after_<column>` for each key column, emits each row in
//! order, and carries the key as the event's `upstream_cursor`, so the host
//! resumes after the last row it stored. The plugin never builds SQL; it
//! binds values only.
//!
//! What a row is a change of is the query's choice. An insert-only key
//! (`id`) reads new rows; a change marker (`updated_at, id`, a version, an
//! outbox sequence) reads updates too; a soft-delete column or an outbox a
//! trigger fills reads deletes. `op_column` names the column whose value
//! says which: `insert`, `update` or `delete`.
//!
//! Key values are bound with their JSON type: an integer as a 64-bit
//! integer, text as text. A non-integer key on Postgres (a timestamp, a
//! numeric) needs a cast in the SQL, for example
//! `CAST(:_after_created_at AS timestamptz)`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    PluginManifest, WatchError, WatchEvent, WatchEventSink, WatchHandle, WatchStrategyPlugin,
    firstparty_manifest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::{DriverKind, QueryBody, RowMode, SqlBackendConfig};
use crate::driver::{self, PoolHandle, SqlDriver};
use crate::errors::SqlError;
use crate::params::{self, BoundParam, PreparedStmt};
use crate::pool;
use crate::session::SessionVars;

/// The kind this strategy registers under.
pub const KIND: &str = "sql_changes";
/// The event type of every event.
pub const EVENT_TYPE: &str = "sql.row.changed";
/// The placeholder `batch_size` binds to.
const LIMIT_PLACEHOLDER: &str = "_limit";
/// The placeholder `settle_ms` binds to, as Unix seconds.
const SETTLE_PLACEHOLDER: &str = "_settle_before";
/// Prefix of the placeholder each key column binds to.
const AFTER_PREFIX: &str = "_after_";
/// Version of the cursor this plugin writes.
const CURSOR_VERSION: u64 = 1;
const MIN_INTERVAL_MS: u64 = 100;
const DEFAULT_INTERVAL_MS: u64 = 1_000;
const DEFAULT_BATCH_SIZE: u32 = 100;
const MAX_BATCH_SIZE: u32 = 500;
/// Most rows emitted in one tick: the host's event queues hold 1024, and
/// several sources share them.
const MAX_ROWS_PER_TICK: usize = 500;
/// Largest event the host takes.
const MAX_EVENT_BYTES: usize = 256 * 1024;
/// Query timeout when `query.timeout_ms` is unset.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Longest wait between two attempts to reach the database.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How long a cancel waits for the loop to stop.
const CANCEL_JOIN: Duration = Duration::from_secs(10);

/// Where a source with no stored position starts.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangesStart {
    /// After the newest row now: `latest_sql` gives its key.
    #[default]
    Latest,
    /// After `initial`: every row the query returns.
    Beginning,
}

/// What a change did to its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOp {
    /// The row is new.
    Insert,
    /// The row changed.
    Update,
    /// The row is gone.
    Delete,
}

impl ChangeOp {
    /// The op `value` names, in any letter case: `insert`, `update` or
    /// `delete`, as a trigger's `TG_OP` writes them.
    fn of(value: &Value) -> Option<Self> {
        match value.as_str()?.to_ascii_lowercase().as_str() {
            "insert" => Some(Self::Insert),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// Spec of a `sql_changes` watch: the connection and `query` of a SQL
/// binding, and how rows are keyed.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlChangesWatchSpec {
    /// Driver, URL, pool, session variables and the `query` block
    /// (`row_mode: many`; `sql` with the placeholders below;
    /// `timeout_ms`).
    #[serde(flatten)]
    pub connection: SqlBackendConfig,
    /// The columns of the ordering key, in `ORDER BY` order. Together they
    /// are unique and only grow.
    pub key_columns: Vec<String>,
    /// The key before the first row, one value per key column: the query
    /// gets it on a first start from the beginning, and on a table with
    /// no rows yet.
    pub initial: Map<String, Value>,
    /// Where a source with no stored position starts: `latest` (default)
    /// or `beginning`.
    #[serde(default)]
    pub start: ChangesStart,
    /// For `start: latest`: one row whose key columns hold the newest key,
    /// for example `SELECT MAX(id) AS id FROM orders`. No row, or a null,
    /// means `initial`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_sql: Option<String>,
    /// Rows read per query, bound to `:_limit`. 1 to 500; default 100.
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    /// Milliseconds between polls. At least 100; default 1000.
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    /// The column with the time the change happened: RFC 3339 text, a
    /// timestamp, or Unix seconds. Omitted, the time it was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at_column: Option<String>,
    /// The column that says what the change did: `insert`, `update` or
    /// `delete`, in any letter case. Omitted, every row is an insert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_column: Option<String>,
    /// Read only rows older than this many milliseconds, so a row that
    /// commits late with a lower key is not passed over. The query then
    /// binds `:_settle_before`, now minus `settle_ms` in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_ms: Option<u64>,
}

fn default_batch_size() -> u32 {
    DEFAULT_BATCH_SIZE
}

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

/// The position after a row: its key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Cursor {
    v: u64,
    k: Vec<Value>,
}

/// The validated, compiled form of a spec.
#[derive(Debug, Clone)]
struct Plan {
    stmt: PreparedStmt,
    latest: Option<PreparedStmt>,
    key_columns: Vec<String>,
    initial: Vec<Value>,
    start: ChangesStart,
    batch_size: u32,
    interval: Duration,
    timeout: Duration,
    occurred_at_column: Option<String>,
    op_column: Option<String>,
    settle: Option<Duration>,
}

impl SqlChangesWatchSpec {
    fn compile(&self) -> Result<Plan, SqlError> {
        let invalid = |m: String| SqlError::InvalidSpec(format!("sql_changes: {m}"));
        self.connection.validate()?;
        if self.connection.query.row_mode != RowMode::Many {
            return Err(invalid("query.row_mode must be `many`".into()));
        }
        let QueryBody::Sql { sql } = &self.connection.query.body else {
            return Err(invalid(
                "query needs `sql`: a keyset SELECT, not a procedure or file".into(),
            ));
        };
        if self.key_columns.is_empty() {
            return Err(invalid("key_columns must name at least one column".into()));
        }
        for column in &self.key_columns {
            if !is_column_name(column) {
                return Err(invalid(format!(
                    "key_columns: `{column}` is not a column name of [A-Za-z0-9_]"
                )));
            }
        }
        let mut initial = Vec::with_capacity(self.key_columns.len());
        for column in &self.key_columns {
            match self.initial.get(column) {
                Some(value) if !value.is_null() => initial.push(value.clone()),
                _ => {
                    return Err(invalid(format!(
                        "initial must give a value for key column `{column}`"
                    )));
                }
            }
        }
        if let Some(extra) = self.initial.keys().find(|k| !self.key_columns.contains(k)) {
            return Err(invalid(format!("initial: `{extra}` is not a key column")));
        }
        if !(1..=MAX_BATCH_SIZE).contains(&self.batch_size) {
            return Err(invalid(format!(
                "batch_size must be 1 to {MAX_BATCH_SIZE}, not {}",
                self.batch_size
            )));
        }
        if self.interval_ms < MIN_INTERVAL_MS {
            return Err(invalid(format!(
                "interval_ms must be at least {MIN_INTERVAL_MS}"
            )));
        }
        for (field, column) in [
            ("occurred_at_column", &self.occurred_at_column),
            ("op_column", &self.op_column),
        ] {
            if let Some(column) = column
                && !is_column_name(column)
            {
                return Err(invalid(format!(
                    "{field}: `{column}` is not a column name of [A-Za-z0-9_]"
                )));
            }
        }
        if self.settle_ms == Some(0) {
            return Err(invalid("settle_ms must be greater than 0".into()));
        }
        crate::config::reject_multi_statement(sql)?;
        crate::config::reject_privileged_ddl(sql)?;
        let driver = self.connection.driver;
        let (rewritten, order) = params::rewrite_placeholders(sql, driver);
        let mut allowed: Vec<String> = self
            .key_columns
            .iter()
            .map(|c| format!("{AFTER_PREFIX}{c}"))
            .collect();
        allowed.push(LIMIT_PLACEHOLDER.to_owned());
        if self.settle_ms.is_some() {
            allowed.push(SETTLE_PLACEHOLDER.to_owned());
        }
        if let Some(unknown) = order.iter().find(|name| !allowed.contains(name)) {
            return Err(invalid(format!(
                "query.sql binds `:{unknown}`; it may bind only {}",
                allowed
                    .iter()
                    .map(|n| format!(":{n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if let Some(missing) = allowed.iter().find(|name| !order.contains(name)) {
            return Err(invalid(format!(
                "query.sql must bind `:{missing}`: the rows after the last key, at most \
                 :{LIMIT_PLACEHOLDER} of them{}",
                if self.settle_ms.is_some() {
                    ", older than :_settle_before"
                } else {
                    ""
                }
            )));
        }
        let latest = match (&self.start, &self.latest_sql) {
            (ChangesStart::Latest, None) => {
                return Err(invalid(
                    "start: latest needs latest_sql, a query giving the newest key; or set \
                     start: beginning"
                        .into(),
                ));
            }
            (_, Some(latest_sql)) => {
                crate::config::reject_multi_statement(latest_sql)?;
                crate::config::reject_privileged_ddl(latest_sql)?;
                let (rewritten, order) = params::rewrite_placeholders(latest_sql, driver);
                if let Some(name) = order.first() {
                    return Err(invalid(format!(
                        "latest_sql binds `:{name}`; it takes no placeholders"
                    )));
                }
                Some(PreparedStmt {
                    sql: rewritten,
                    param_order: Vec::new(),
                    driver,
                })
            }
            (ChangesStart::Beginning, None) => None,
        };
        Ok(Plan {
            stmt: PreparedStmt {
                sql: rewritten,
                param_order: order,
                driver,
            },
            latest,
            key_columns: self.key_columns.clone(),
            initial,
            start: self.start,
            batch_size: self.batch_size,
            interval: Duration::from_millis(self.interval_ms),
            timeout: Duration::from_millis(
                self.connection
                    .query
                    .timeout_ms
                    .unwrap_or(DEFAULT_TIMEOUT_MS),
            ),
            occurred_at_column: self.occurred_at_column.clone(),
            op_column: self.op_column.clone(),
            settle: self.settle_ms.map(Duration::from_millis),
        })
    }
}

fn is_column_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The arguments of one page after `key`.
fn page_args(plan: &Plan, key: &[Value], now_secs: i64) -> Vec<BoundParam> {
    plan.stmt
        .param_order
        .iter()
        .map(|name| {
            let value = if name == LIMIT_PLACEHOLDER {
                Value::from(plan.batch_size)
            } else if name == SETTLE_PLACEHOLDER {
                let settle = plan.settle.map_or(0, |d| d.as_secs() as i64);
                Value::from(now_secs - settle)
            } else {
                let column = &name[AFTER_PREFIX.len()..];
                let index = plan
                    .key_columns
                    .iter()
                    .position(|c| c == column)
                    .unwrap_or_default();
                key[index].clone()
            };
            BoundParam {
                name: name.clone(),
                value,
            }
        })
        .collect()
}

/// The key of `row`; `None` when a key column is missing or null.
fn row_key(plan: &Plan, row: &Value) -> Option<Vec<Value>> {
    plan.key_columns
        .iter()
        .map(|column| row.get(column).filter(|v| !v.is_null()).cloned())
        .collect()
}

/// The event of `row`, with key `key`, read by the watch on `uri`; `None`
/// when its `op_column` names no change.
fn row_event(plan: &Plan, uri: &str, row: Value, key: &[Value]) -> Option<WatchEvent> {
    let op = match &plan.op_column {
        Some(column) => ChangeOp::of(row.get(column)?)?,
        None => ChangeOp::Insert,
    };
    let key_json = serde_json::to_string(key).unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(uri.as_bytes());
    hasher.update(&[0]);
    hasher.update(key_json.as_bytes());
    let digest = hasher.finalize();
    let occurred_at = plan
        .occurred_at_column
        .as_deref()
        .and_then(|column| row.get(column))
        .and_then(occurred_at);
    Some(WatchEvent {
        event_id: Some(format!("row-{}", &digest.to_hex()[..32])),
        event_type: Some(EVENT_TYPE.to_owned()),
        occurred_at,
        data: Some(serde_json::json!({ "op": op, "row": row })),
        upstream_cursor: serde_json::to_value(Cursor {
            v: CURSOR_VERSION,
            k: key.to_vec(),
        })
        .ok(),
        ..WatchEvent::default()
    })
}

/// RFC 3339 UTC of a column value: RFC 3339 text, a naive timestamp read
/// as UTC, or Unix seconds.
fn occurred_at(value: &Value) -> Option<String> {
    let at = match value {
        Value::String(text) => chrono::DateTime::parse_from_rfc3339(text)
            .map(|t| t.with_timezone(&chrono::Utc))
            .ok()
            .or_else(|| {
                ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"]
                    .iter()
                    .find_map(|format| {
                        chrono::NaiveDateTime::parse_from_str(text, format)
                            .ok()
                            .map(|t| t.and_utc())
                    })
            })?,
        Value::Number(n) => chrono::DateTime::from_timestamp(n.as_i64()?, 0)?,
        _ => return None,
    };
    Some(at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// The key a stored cursor names; an error when it does not fit the spec.
fn resume_key(plan: &Plan, resume: Value) -> Result<Vec<Value>, WatchError> {
    let cursor: Cursor = serde_json::from_value(resume).map_err(|e| WatchError::InvalidSpec {
        message: format!("sql_changes: the stored position is not one this plugin wrote: {e}"),
    })?;
    if cursor.v != CURSOR_VERSION || cursor.k.len() != plan.key_columns.len() {
        return Err(WatchError::InvalidSpec {
            message: format!(
                "sql_changes: the stored position has {} key values for {} key columns; \
                 the key changed, so the source starts over under a new event type",
                cursor.k.len(),
                plan.key_columns.len()
            ),
        });
    }
    Ok(cursor.k)
}

/// `WatchStrategyPlugin` for `kind: "sql_changes"`.
pub struct SqlChangesWatchPlugin {
    manifest: PluginManifest,
    drivers: std::collections::HashMap<DriverKind, Arc<dyn SqlDriver>>,
}

impl std::fmt::Debug for SqlChangesWatchPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlChangesWatchPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

impl Default for SqlChangesWatchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlChangesWatchPlugin {
    /// A watch plugin over the drivers this build carries.
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.watch.sql_changes",
                name: "SQL Changes Watch",
                class: WatchStrategy,
            },
            drivers: driver::build_registry(),
        }
    }

    /// A watch plugin over `drivers`, for tests.
    pub fn with_drivers(
        drivers: std::collections::HashMap<DriverKind, Arc<dyn SqlDriver>>,
    ) -> Self {
        let mut plugin = Self::new();
        plugin.drivers = drivers;
        plugin
    }
}

struct ChangesHandle {
    cancel: CancellationToken,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[async_trait]
impl WatchHandle for ChangesHandle {
    async fn cancel(&self) {
        self.cancel.cancel();
        if let Some(task) = self.task.lock().await.take()
            && tokio::time::timeout(CANCEL_JOIN, task).await.is_err()
        {
            warn!("sql_changes watch: the loop did not stop in time");
        }
    }
}

#[async_trait]
impl WatchStrategyPlugin for SqlChangesWatchPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        KIND
    }

    async fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError> {
        let (spec, resume) = mcpg_plugin_protocol::take_watch_resume(spec);
        let parsed: SqlChangesWatchSpec =
            serde_json::from_value(spec).map_err(|e| WatchError::InvalidSpec {
                message: format!("sql_changes watch spec: {e}"),
            })?;
        let plan = parsed.compile().map_err(|e| WatchError::InvalidSpec {
            message: e.to_string(),
        })?;
        let resume = resume.map(|r| resume_key(&plan, r)).transpose()?;
        let driver = self
            .drivers
            .get(&parsed.connection.driver)
            .cloned()
            .ok_or_else(|| WatchError::InvalidSpec {
                message: format!(
                    "driver '{}' is not compiled into this build",
                    parsed.connection.driver.as_str()
                ),
            })?;
        let cancel = CancellationToken::new();
        info!(
            uri = %resource_uri,
            driver = parsed.connection.driver.as_str(),
            resumed = resume.is_some(),
            "sql_changes watch: started"
        );
        let task = tokio::spawn(run(
            parsed.connection,
            driver,
            plan,
            resume,
            resource_uri.to_owned(),
            sink,
            cancel.clone(),
        ));
        Ok(Box::new(ChangesHandle {
            cancel,
            task: Mutex::new(Some(task)),
        }))
    }
}

/// Connect, find the start, then poll until cancelled. Every failure is
/// retried with backoff: the watch never ends on its own.
async fn run(
    connection: SqlBackendConfig,
    driver: Arc<dyn SqlDriver>,
    plan: Plan,
    resume: Option<Vec<Value>>,
    uri: String,
    sink: Arc<dyn WatchEventSink>,
    cancel: CancellationToken,
) {
    let session = SessionVars::from_map(connection.session_vars.clone());
    let mut backoff = Backoff::default();
    let pool = loop {
        let attempt = async {
            let (pool, _rotator) = pool::build_pool(&connection, &driver).await?;
            driver.health_check(&pool).await?;
            Ok::<_, SqlError>(pool)
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            outcome = attempt => match outcome {
                Ok(pool) => break pool,
                Err(error) => {
                    warn!(uri = %uri, error = %error, "sql_changes watch: cannot reach the database; retrying");
                    if backoff.wait(&cancel).await.is_err() {
                        return;
                    }
                }
            },
        }
    };
    backoff.reset();
    let mut key = match resume {
        Some(key) => key,
        None => loop {
            match start_key(&plan, &driver, &pool, &session, &cancel).await {
                Ok(Some(key)) => break key,
                Ok(None) => return,
                Err(error) => {
                    warn!(uri = %uri, error = %error, "sql_changes watch: the start query failed; retrying");
                    if backoff.wait(&cancel).await.is_err() {
                        return;
                    }
                }
            }
        },
    };
    let mut ticker = tokio::time::interval(plan.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!(uri = %uri, "sql_changes watch: cancelled");
                return;
            }
            _ = ticker.tick() => {}
        }
        match poll(
            &plan, &driver, &pool, &session, &uri, &mut key, &*sink, &cancel,
        )
        .await
        {
            Ok(()) => backoff.reset(),
            Err(error) => {
                warn!(uri = %uri, error = %error, "sql_changes watch: poll failed; retrying at the next tick");
            }
        }
    }
}

/// The key a first start begins after: `initial`, or the newest key for
/// `start: latest`. `Ok(None)` when cancelled.
async fn start_key(
    plan: &Plan,
    driver: &Arc<dyn SqlDriver>,
    pool: &PoolHandle,
    session: &SessionVars,
    cancel: &CancellationToken,
) -> Result<Option<Vec<Value>>, SqlError> {
    let Some(latest) = plan
        .latest
        .as_ref()
        .filter(|_| plan.start == ChangesStart::Latest)
    else {
        return Ok(Some(plan.initial.clone()));
    };
    let batch = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(None),
        batch = timed(plan.timeout, driver.execute(pool, latest, &[], session)) => batch?,
    };
    Ok(Some(
        batch
            .rows
            .first()
            .and_then(|row| row_key(plan, row))
            .unwrap_or_else(|| plan.initial.clone()),
    ))
}

/// Read and emit the rows after `key`, page by page, up to
/// [`MAX_ROWS_PER_TICK`]; `key` moves past each row emitted.
#[allow(clippy::too_many_arguments)]
async fn poll(
    plan: &Plan,
    driver: &Arc<dyn SqlDriver>,
    pool: &PoolHandle,
    session: &SessionVars,
    uri: &str,
    key: &mut Vec<Value>,
    sink: &dyn WatchEventSink,
    cancel: &CancellationToken,
) -> Result<(), SqlError> {
    let mut emitted = 0usize;
    loop {
        let args = page_args(plan, key, chrono::Utc::now().timestamp());
        let batch = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            batch = timed(plan.timeout, driver.execute(pool, &plan.stmt, &args, session)) => batch?,
        };
        let full = batch.rows.len() >= plan.batch_size as usize;
        for row in batch.rows.into_iter().take(plan.batch_size as usize) {
            let Some(next) = row_key(plan, &row) else {
                return Err(SqlError::InvalidSpec(format!(
                    "sql_changes: a row has no value for a key column of {:?}; select every \
                     key column, never null",
                    plan.key_columns
                )));
            };
            match row_event(plan, uri, row, &next) {
                None => {
                    warn!(uri = %uri, "sql_changes watch: a row's op_column is not insert, update or delete; it is skipped");
                }
                Some(event) => {
                    let size = serde_json::to_vec(&event).map_or(usize::MAX, |b| b.len());
                    if size > MAX_EVENT_BYTES {
                        warn!(uri = %uri, bytes = size, "sql_changes watch: a row is larger than an event can be; it is skipped");
                    } else {
                        sink.emit(event).await;
                        emitted += 1;
                    }
                }
            }
            *key = next;
        }
        if !full || emitted >= MAX_ROWS_PER_TICK || cancel.is_cancelled() {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
}

async fn timed<T>(
    limit: Duration,
    work: impl std::future::Future<Output = Result<T, SqlError>>,
) -> Result<T, SqlError> {
    tokio::time::timeout(limit, work)
        .await
        .map_err(|_| SqlError::Timeout(u64::try_from(limit.as_millis()).unwrap_or(u64::MAX)))?
}

/// Exponential backoff from one second to [`MAX_BACKOFF`].
#[derive(Default)]
struct Backoff {
    attempts: u32,
}

impl Backoff {
    /// Wait for the next attempt; `Err` when cancelled first.
    async fn wait(&mut self, cancel: &CancellationToken) -> Result<(), ()> {
        let delay = Duration::from_secs(1u64 << self.attempts.min(6)).min(MAX_BACKOFF);
        self.attempts = self.attempts.saturating_add(1);
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(()),
            () = tokio::time::sleep(delay) => Ok(()),
        }
    }

    fn reset(&mut self) {
        self.attempts = 0;
    }
}

#[cfg(test)]
#[path = "watch_changes_tests.rs"]
mod tests;
