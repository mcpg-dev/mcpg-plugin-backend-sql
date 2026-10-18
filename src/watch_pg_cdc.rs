//! `watch_strategy` entity (`postgres_cdc`): each row change a PostgreSQL
//! publication carries, read from a logical replication slot, as an MCP
//! Event.
//!
//! The watch decodes the built-in `pgoutput` plugin through the SQL slot
//! functions, so it needs no extension and no replication connection and
//! works on managed PostgreSQL: `pg_logical_slot_peek_binary_changes` reads
//! from the slot's confirmed position without consuming, and
//! `pg_replication_slot_advance` moves that position once the gateway has
//! acknowledged every change of a transaction and of every transaction
//! before it. A change the gateway does not take comes again on a later
//! peek, so delivery is at-least-once; the change's LSN is its event id.
//!
//! Inserts, updates and deletes are `sql.row.changed` with the new row (the
//! old key or row for a delete), the old row when the table's replica
//! identity sends one, and the transaction's id and commit time; a
//! TRUNCATE is `sql.table.truncated`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use mcpg_plugin_protocol::backend::{WatchError, WatchEvent};
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::queue::{
    Delivery, QueueOptions, QueueSource, acknowledge_queue_watch, cancel_queue_watch, defaults,
    spawn_queue_watch,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::pgoutput::{self, Message, Relations, commit_time, decode, lsn_text, parse_lsn, row_of};

/// The plugin this entity belongs to.
pub const PLUGIN_ID: &str = "dev.mcpg.backend.sql";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "postgres_cdc";

/// The event type of an insert, update or delete.
pub const ROW_CHANGED_EVENT_TYPE: &str = "sql.row.changed";

/// The event type of a TRUNCATE.
pub const TRUNCATED_EVENT_TYPE: &str = "sql.table.truncated";

const CURSOR_VERSION: u64 = 1;

/// The most rows one peek reads. `upto_nchanges` counts every output row:
/// the BEGIN, COMMIT and RELATION rows, the changes still in flight, and on
/// PostgreSQL 14 and older a BEGIN and COMMIT for each transaction that
/// touched no published table.
const MAX_PEEK_ROWS: usize = 65_536;

fn default_poll_interval_ms() -> u64 {
    1_000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// `postgres://…`, with its password and `sslmode`; resolved before the
    /// watch starts. Its role needs `REPLICATION` (or `rds_replication`,
    /// `cloudsqlsuperuser`, …).
    url: String,
    /// The publication whose tables are read.
    publication: String,
    /// Create the publication `FOR TABLE` these when it is missing.
    #[serde(default)]
    tables: Vec<String>,
    /// The replication slot, created when missing; default one derived from
    /// the source, the same on every restart.
    #[serde(default)]
    slot: Option<String>,
    /// How often the slot is read when it had nothing new.
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u64,
    #[serde(default = "defaults::max_in_flight")]
    max_in_flight: usize,
    #[serde(default = "defaults::ack_timeout_ms")]
    ack_timeout_ms: u64,
}

/// A slot name the same for the same source on every restart.
fn derived_slot(resource_uri: &str) -> String {
    let digest = blake3::hash(resource_uri.as_bytes()).to_hex();
    format!("mcpg_{}", &digest[..16])
}

/// A name PostgreSQL takes for a slot: lower-case letters, digits and `_`.
fn valid_slot(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// An identifier quoted for SQL.
fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// A `schema.table` (or `table`) quoted for SQL.
fn quoted_table(name: &str) -> String {
    name.split('.').map(quoted).collect::<Vec<_>>().join(".")
}

/// The changes of one transaction seen in the last peek.
#[derive(Debug, Default)]
struct Transaction {
    /// Every change of it; complete once its Commit was seen.
    changes: HashSet<u64>,
    complete: bool,
    acked: HashSet<u64>,
}

/// What the watch holds between peeks.
#[derive(Debug, Default)]
struct Progress {
    /// Changes emitted and not released, by LSN.
    delivered: HashSet<u64>,
    /// Transactions not yet consumed, by end LSN, in commit order.
    transactions: BTreeMap<u64, Transaction>,
    /// The transaction each change belongs to.
    owner: HashMap<u64, u64>,
    /// How far the slot is consumed: a peek that read from before an
    /// advance still holds those changes, and they are not new.
    consumed: u64,
}

impl Progress {
    /// The end LSN to advance the slot to: past every leading transaction
    /// fully acknowledged.
    fn advance(&mut self) -> Option<u64> {
        let mut to = None;
        while let Some((&end, tx)) = self.transactions.first_key_value() {
            if !tx.complete || tx.acked.len() < tx.changes.len() {
                break;
            }
            for change in &tx.changes {
                self.owner.remove(change);
                self.delivered.remove(change);
            }
            self.transactions.remove(&end);
            self.consumed = self.consumed.max(end);
            to = Some(end);
        }
        to
    }
}

/// The database side of one `postgres_cdc` watch.
struct PostgresCdc {
    url: String,
    publication: String,
    tables: Vec<String>,
    slot: String,
    rt: tokio::runtime::Runtime,
    pool: Mutex<Option<PgPool>>,
    progress: Mutex<Progress>,
    /// The source read from this slot before: a missing slot is a gap.
    resumed: bool,
    /// A gap to report before the next change.
    gap: Mutex<bool>,
    /// An end LSN the slot is to be advanced to that an advance failed to
    /// reach.
    unadvanced: Mutex<Option<u64>>,
}

impl PostgresCdc {
    fn pool(&self) -> Option<PgPool> {
        self.pool.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn prepare(&self, pool: &PgPool) -> Result<bool, String> {
        let level: String = sqlx::query_scalar("SHOW wal_level")
            .fetch_one(pool)
            .await
            .map_err(|e| format!("PostgreSQL SHOW wal_level failed: {e}"))?;
        if level != "logical" {
            return Err(format!(
                "PostgreSQL wal_level is '{level}'; logical decoding needs wal_level = logical"
            ));
        }
        let published: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = $1)")
                .bind(&self.publication)
                .fetch_one(pool)
                .await
                .map_err(|e| format!("PostgreSQL publication check failed: {e}"))?;
        if !published {
            if self.tables.is_empty() {
                return Err(format!(
                    "PostgreSQL publication '{}' does not exist; create it, or list tables",
                    self.publication
                ));
            }
            let tables: Vec<String> = self.tables.iter().map(|t| quoted_table(t)).collect();
            sqlx::query(&format!(
                "CREATE PUBLICATION {} FOR TABLE {}",
                quoted(&self.publication),
                tables.join(", ")
            ))
            .execute(pool)
            .await
            .map_err(|e| format!("PostgreSQL CREATE PUBLICATION failed: {e}"))?;
        }
        let slotted: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = $1)",
        )
        .bind(&self.slot)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("PostgreSQL slot check failed: {e}"))?;
        if !slotted {
            sqlx::query("SELECT pg_create_logical_replication_slot($1, 'pgoutput')")
                .bind(&self.slot)
                .execute(pool)
                .await
                .map_err(|e| format!("PostgreSQL slot creation failed: {e}"))?;
        }
        Ok(!slotted)
    }

    /// The slot's output from its confirmed position, decoded: about `limit`
    /// rows, since decoding stops only at the first COMMIT past the limit.
    async fn peek_rows(&self, pool: &PgPool, limit: usize) -> Result<Vec<(u64, Message)>, String> {
        let rows = sqlx::query(
            "SELECT lsn::text AS lsn, data FROM pg_logical_slot_peek_binary_changes( \
             $1, NULL, $2, 'proto_version', '1', 'publication_names', $3)",
        )
        .bind(&self.slot)
        .bind(i32::try_from(limit).unwrap_or(i32::MAX))
        .bind(&self.publication)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("PostgreSQL slot peek failed: {e}"))?;
        rows.iter()
            .map(|row| {
                let lsn_text_value: String = row.try_get("lsn").map_err(|e| e.to_string())?;
                let data: Vec<u8> = row.try_get("data").map_err(|e| e.to_string())?;
                let lsn = parse_lsn(&lsn_text_value)
                    .ok_or_else(|| format!("PostgreSQL LSN '{lsn_text_value}' does not parse"))?;
                Ok((lsn, decode(&data)?))
            })
            .collect()
    }

    /// The deliveries of one peek: what is new since the slot's confirmed
    /// position and not in flight, at most `max`.
    async fn peek(&self, pool: &PgPool, max: usize) -> Result<Vec<Delivery>, String> {
        let in_flight = self
            .progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .delivered
            .len();
        // The changes in flight come first again, each with its BEGIN and
        // COMMIT, so a peek of `in_flight + max` rows can end before any new
        // change: read further until it holds `max` of them or the output
        // ends. Only an output shorter than the limit is the end; one that
        // reaches it can stop at a COMMIT exactly there.
        let mut limit = (in_flight + max).clamp(1, MAX_PEEK_ROWS);
        let messages = loop {
            let messages = self.peek_rows(pool, limit).await?;
            if messages.len() < limit
                || limit == MAX_PEEK_ROWS
                || self.new_changes(&messages) >= max
            {
                break messages;
            }
            limit = limit.saturating_mul(4).min(MAX_PEEK_ROWS);
        };

        let mut relations: Relations = HashMap::new();
        let mut deliveries = Vec::new();
        let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        let mut transaction: Vec<u64> = Vec::new();
        let mut begin: Option<(u32, i64)> = None;
        for (lsn, message) in messages {
            let events = match message {
                Message::Begin {
                    commit_time_micros,
                    xid,
                    ..
                } => {
                    begin = Some((xid, commit_time_micros));
                    transaction.clear();
                    continue;
                }
                Message::Commit { end_lsn } => {
                    if end_lsn <= progress.consumed {
                        transaction.clear();
                        continue;
                    }
                    for change in &transaction {
                        progress.owner.insert(*change, end_lsn);
                    }
                    let tx = progress.transactions.entry(end_lsn).or_default();
                    tx.changes = transaction.drain(..).collect();
                    tx.complete = true;
                    continue;
                }
                Message::Relation { oid, relation } => {
                    relations.insert(oid, relation);
                    continue;
                }
                Message::Other => continue,
                change => {
                    transaction.push(lsn);
                    // A transaction's end LSN is where the next one's first
                    // change starts.
                    if lsn < progress.consumed
                        || progress.delivered.contains(&lsn)
                        || deliveries.len() >= max
                    {
                        continue;
                    }
                    change_events(&self.slot, lsn, begin, &relations, change)?
                }
            };
            progress.delivered.insert(lsn);
            let total = events.len();
            for (index, event) in events.into_iter().enumerate() {
                // A TRUNCATE of several tables is one change: its last
                // event settles it.
                let receipt = if index + 1 == total {
                    json!({ "lsn": lsn })
                } else {
                    Value::Null
                };
                deliveries.push(Delivery { event, receipt });
            }
        }
        Ok(deliveries)
    }

    /// The changes in `messages` that a peek delivers: neither consumed nor
    /// in flight.
    fn new_changes(&self, messages: &[(u64, Message)]) -> usize {
        let progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        messages
            .iter()
            .filter(|(lsn, message)| {
                !matches!(
                    message,
                    Message::Begin { .. }
                        | Message::Commit { .. }
                        | Message::Relation { .. }
                        | Message::Other
                ) && *lsn >= progress.consumed
                    && !progress.delivered.contains(lsn)
            })
            .count()
    }

    /// Advance the slot past what is acknowledged. Only the receiving
    /// thread calls it, after a peek: a peek holds the slot, and an advance
    /// from another session then fails.
    fn settle(&self, pool: &PgPool) -> Result<(), String> {
        let mut unadvanced = self.unadvanced.lock().unwrap_or_else(|e| e.into_inner());
        let to = self
            .progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .advance();
        let Some(to) = to.max(*unadvanced) else {
            return Ok(());
        };
        let advanced = self.rt.block_on(
            sqlx::query("SELECT pg_replication_slot_advance($1, $2::text::pg_lsn)")
                .bind(&self.slot)
                .bind(lsn_text(to))
                .execute(pool),
        );
        match advanced {
            Ok(_) => {
                *unadvanced = None;
                Ok(())
            }
            Err(e) => {
                // What is consumed stays consumed: the advance is tried again
                // after the next peek.
                *unadvanced = Some(to);
                Err(format!("PostgreSQL slot advance failed: {e}"))
            }
        }
    }
}

/// The events of one change message.
fn change_events(
    slot: &str,
    lsn: u64,
    begin: Option<(u32, i64)>,
    relations: &Relations,
    change: Message,
) -> Result<Vec<WatchEvent>, String> {
    let relation_of = |oid: u32| {
        relations
            .get(&oid)
            .ok_or_else(|| format!("pgoutput change of relation {oid} before its Relation"))
    };
    let mut base = Map::new();
    base.insert("lsn".into(), json!(lsn_text(lsn)));
    let committed = begin.and_then(|(_, micros)| commit_time(micros));
    if let Some((xid, _)) = begin {
        base.insert("xid".into(), json!(xid));
    }
    if let Some(at) = &committed {
        base.insert("commitTime".into(), json!(at));
    }
    let event = |event_type: &str, id: String, data: Map<String, Value>| WatchEvent {
        event_id: Some(id),
        event_type: Some(event_type.to_owned()),
        occurred_at: committed.clone(),
        data: Some(Value::Object(data)),
        upstream_cursor: Some(json!({ "v": CURSOR_VERSION, "lsn": lsn_text(lsn) })),
        ..WatchEvent::default()
    };
    let row_event = |op: &str,
                     relation: &pgoutput::Relation,
                     row: Map<String, Value>,
                     old: Option<Map<String, Value>>,
                     unchanged: Vec<String>| {
        let mut data = base.clone();
        data.insert("op".into(), json!(op));
        data.insert("schema".into(), json!(relation.schema));
        data.insert("table".into(), json!(relation.name));
        data.insert("row".into(), Value::Object(row));
        if let Some(old) = old {
            data.insert("old".into(), Value::Object(old));
        }
        if !unchanged.is_empty() {
            data.insert("unchanged".into(), json!(unchanged));
        }
        event(
            ROW_CHANGED_EVENT_TYPE,
            format!("{slot}/{}", lsn_text(lsn)),
            data,
        )
    };
    Ok(match change {
        Message::Insert { oid, new } => {
            let relation = relation_of(oid)?;
            let (row, unchanged) = row_of(relation, &new, false);
            vec![row_event("insert", relation, row, None, unchanged)]
        }
        Message::Update { oid, old, new } => {
            let relation = relation_of(oid)?;
            let (row, unchanged) = row_of(relation, &new, false);
            let old = old.map(|(old, full)| row_of(relation, &old, !full).0);
            vec![row_event("update", relation, row, old, unchanged)]
        }
        Message::Delete { oid, old, full } => {
            let relation = relation_of(oid)?;
            let (row, _) = row_of(relation, &old, !full);
            vec![row_event("delete", relation, row, None, Vec::new())]
        }
        Message::Truncate {
            oids,
            cascade,
            restart_identity,
        } => oids
            .iter()
            .map(|oid| {
                let relation = relation_of(*oid)?;
                let mut data = base.clone();
                data.insert("schema".into(), json!(relation.schema));
                data.insert("table".into(), json!(relation.name));
                data.insert("cascade".into(), json!(cascade));
                data.insert("restartIdentity".into(), json!(restart_identity));
                Ok(event(
                    TRUNCATED_EVENT_TYPE,
                    format!("{slot}/{}/{oid}", lsn_text(lsn)),
                    data,
                ))
            })
            .collect::<Result<_, String>>()?,
        _ => Vec::new(),
    })
}

impl QueueSource for PostgresCdc {
    fn connect(&self) -> Result<(), String> {
        let pool = self.rt.block_on(
            PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&self.url),
        );
        // The URL carries the password, so the error is not echoed with it.
        let pool = pool.map_err(|e| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("PostgreSQL connect failed: {e}"))
        })?;
        let created = self.rt.block_on(self.prepare(&pool))?;
        if created && self.resumed {
            *self.gap.lock().unwrap_or_else(|e| e.into_inner()) = true;
        }
        // A new session peeks from the slot's confirmed position again.
        *self.progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress::default();
        *self.pool.lock().unwrap_or_else(|e| e.into_inner()) = Some(pool);
        Ok(())
    }

    fn receive(&self, max: usize, wait: Duration) -> Result<Vec<Delivery>, String> {
        let Some(pool) = self.pool() else {
            return Err("not connected".into());
        };
        let mut deliveries = Vec::new();
        if std::mem::take(&mut *self.gap.lock().unwrap_or_else(|e| e.into_inner())) {
            tracing::warn!(slot = %self.slot, "postgres_cdc: the slot was gone and is created again; changes in between are not known");
            deliveries.push(Delivery {
                event: WatchEvent {
                    gap: true,
                    ..WatchEvent::default()
                },
                receipt: Value::Null,
            });
        }
        deliveries.extend(self.rt.block_on(self.peek(&pool, max))?);
        // What the gateway acknowledged since, and transactions with nothing
        // published, are consumed here.
        if let Err(error) = self.settle(&pool) {
            tracing::warn!(slot = %self.slot, error = %error, "postgres_cdc: the slot stays where it is until the next peek");
        }
        if deliveries.is_empty() {
            std::thread::sleep(wait);
        }
        Ok(deliveries)
    }

    /// Recorded; the slot advances after the next peek.
    fn ack(&self, receipt: &Value) -> Result<(), String> {
        let Some(lsn) = receipt.get("lsn").and_then(Value::as_u64) else {
            return Ok(());
        };
        let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(end) = progress.owner.get(&lsn).copied()
            && let Some(tx) = progress.transactions.get_mut(&end)
        {
            tx.acked.insert(lsn);
        }
        Ok(())
    }

    /// The change comes again on a later peek.
    fn release(&self, receipt: &Value) -> Result<(), String> {
        if let Some(lsn) = receipt.get("lsn").and_then(Value::as_u64) {
            self.progress
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .delivered
                .remove(&lsn);
        }
        Ok(())
    }
}

impl Drop for PostgresCdc {
    fn drop(&mut self) {
        let pool = self
            .pool
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(pool) = pool {
            self.rt.block_on(pool.close());
        }
    }
}

/// `watch_strategy` entity. Stateless beyond its manifest — each watcher's
/// database, publication and slot arrive on the per-watch spec.
pub struct PostgresCdcWatchCdylib {
    manifest: PluginManifest,
}

impl PostgresCdcWatchCdylib {
    /// Infallible cdylib factory; the watch carries no plugin-level config.
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        crate::cdylib::install_crypto_provider();
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.sql",
                name: "PostgreSQL CDC Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

impl SyncWatchStrategyPlugin for PostgresCdcWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let (spec, resume) = mcpg_plugin_protocol::take_watch_resume(spec);
        let parsed: WatchSpec =
            serde_json::from_value(spec).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid postgres_cdc watch spec: {e}"),
            })?;
        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if !parsed.url.starts_with("postgres://") && !parsed.url.starts_with("postgresql://") {
            return Err(invalid(
                "url must start with postgres:// or postgresql://".into(),
            ));
        }
        if parsed.url.contains("cred://") {
            return Err(invalid(
                "url must not contain cred:// — per-caller credentials are unsupported; use \
                 ${env.X} / ${secret.X} / vault:// (resolved before the watch starts)"
                    .into(),
            ));
        }
        if parsed.publication.trim().is_empty() {
            return Err(invalid("publication must not be empty".into()));
        }
        let slot = parsed
            .slot
            .clone()
            .unwrap_or_else(|| derived_slot(resource_uri));
        if !valid_slot(&slot) {
            return Err(invalid(
                "slot must be 1 to 63 lower-case letters, digits or _".into(),
            ));
        }
        if parsed.poll_interval_ms < 100 || parsed.poll_interval_ms > 20_000 {
            return Err(invalid("poll_interval_ms must be 100 to 20000".into()));
        }
        let options = QueueOptions {
            source: format!("postgres slot {slot}"),
            max_in_flight: parsed.max_in_flight,
            ack_timeout: Duration::from_millis(parsed.ack_timeout_ms),
            receive_wait: Duration::from_millis(parsed.poll_interval_ms),
        };
        options.validate().map_err(invalid)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("mcpg-pg-cdc")
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("postgres_cdc: tokio runtime init failed: {e}"),
            })?;
        let source = PostgresCdc {
            url: parsed.url,
            publication: parsed.publication,
            tables: parsed.tables,
            slot,
            rt,
            pool: Mutex::new(None),
            progress: Mutex::new(Progress::default()),
            resumed: resume.is_some(),
            gap: Mutex::new(false),
            unadvanced: Mutex::new(None),
        };
        spawn_queue_watch(resource_uri, options, emit_event, source)
    }

    fn acknowledge(&self, watch_handle: &WatchHandleBox, position: &Value) {
        acknowledge_queue_watch(watch_handle, position);
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_queue_watch(watch_handle);
    }
}

#[cfg(test)]
#[path = "watch_pg_cdc_tests.rs"]
mod tests;
