use super::*;
use crate::driver::{ConnectCfg, RowBatch};
use serde_json::json;
use std::sync::Mutex as StdMutex;

fn spec(extra: Value) -> Value {
    let mut base = json!({
        "driver": "sqlite",
        "url": "sqlite::memory:",
        "query": {
            "row_mode": "many",
            "sql": "SELECT id, at, body FROM t WHERE id > :_after_id ORDER BY id LIMIT :_limit"
        },
        "key_columns": ["id"],
        "initial": { "id": 0 },
        "start": "beginning"
    });
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

fn compile(value: Value) -> Result<Plan, String> {
    serde_json::from_value::<SqlChangesWatchSpec>(value)
        .map_err(|e| e.to_string())?
        .compile()
        .map_err(|e| e.to_string())
}

#[test]
fn a_keyset_spec_compiles_and_binds_only_its_placeholders() {
    let plan = compile(spec(json!({}))).unwrap();
    assert_eq!(plan.stmt.param_order, ["_after_id", "_limit"]);
    assert_eq!(plan.initial, [json!(0)]);
    assert_eq!(plan.batch_size, DEFAULT_BATCH_SIZE);
    let args = page_args(&plan, &[json!(41)], 1_790_000_000);
    assert_eq!(
        args.iter().map(|a| a.value.clone()).collect::<Vec<_>>(),
        [json!(41), json!(100)]
    );

    let composite = compile(spec(json!({
        "query": {
            "row_mode": "many",
            "sql": "SELECT * FROM t WHERE at > :_after_at OR (at = :_after_at AND id > :_after_id) AND at < :_settle_before ORDER BY at, id LIMIT :_limit"
        },
        "key_columns": ["at", "id"],
        "initial": { "at": "1970-01-01T00:00:00Z", "id": 0 },
        "settle_ms": 5000
    })))
    .unwrap();
    let args = page_args(
        &composite,
        &[json!("2026-10-10T12:00:00Z"), json!(7)],
        1_790_000_000,
    );
    assert_eq!(
        args.iter()
            .map(|a| (a.name.as_str(), a.value.clone()))
            .collect::<Vec<_>>(),
        [
            ("_after_at", json!("2026-10-10T12:00:00Z")),
            ("_after_at", json!("2026-10-10T12:00:00Z")),
            ("_after_id", json!(7)),
            ("_settle_before", json!(1_789_999_995)),
            ("_limit", json!(100)),
        ]
    );
}

#[test]
fn a_spec_that_cannot_page_safely_is_refused() {
    let cases = [
        (json!({ "key_columns": [] }), "at least one column"),
        (json!({ "key_columns": ["id; drop"] }), "not a column name"),
        (json!({ "initial": {} }), "initial must give a value"),
        (
            json!({ "initial": { "id": null } }),
            "initial must give a value",
        ),
        (
            json!({ "initial": { "id": 0, "other": 1 } }),
            "`other` is not a key column",
        ),
        (json!({ "batch_size": 0 }), "batch_size must be 1 to 500"),
        (json!({ "batch_size": 501 }), "batch_size must be 1 to 500"),
        (
            json!({ "interval_ms": 50 }),
            "interval_ms must be at least 100",
        ),
        (json!({ "settle_ms": 1000 }), "must bind `:_settle_before`"),
        (
            json!({ "settle_ms": 0 }),
            "settle_ms must be greater than 0",
        ),
        (
            json!({ "start": "latest" }),
            "start: latest needs latest_sql",
        ),
        (
            json!({ "start": "latest", "latest_sql": "SELECT MAX(id) AS id FROM t WHERE x = :x" }),
            "latest_sql binds `:x`",
        ),
        (json!({ "occurred_at_column": "a b" }), "not a column name"),
        (
            json!({ "op_column": "op-x" }),
            "op_column: `op-x` is not a column name",
        ),
        (
            json!({ "query": { "row_mode": "single", "sql": "SELECT 1 WHERE 1 > :_after_id LIMIT :_limit" } }),
            "row_mode must be `many`",
        ),
        (
            json!({ "query": { "row_mode": "many", "sql": "SELECT * FROM t WHERE id > :_after_id ORDER BY id" } }),
            "must bind `:_limit`",
        ),
        (
            json!({ "query": { "row_mode": "many", "sql": "SELECT * FROM t ORDER BY id LIMIT :_limit" } }),
            "must bind `:_after_id`",
        ),
        (
            json!({ "query": { "row_mode": "many", "sql": "SELECT * FROM t WHERE id > :_after_id AND tenant = :tenant LIMIT :_limit" } }),
            "binds `:tenant`",
        ),
        (
            json!({ "query": { "row_mode": "many", "sql": "SELECT * FROM t WHERE id > :_after_id LIMIT :_limit; DELETE FROM t" } }),
            "",
        ),
        (json!({ "typo": 1 }), "unknown field"),
    ];
    for (extra, needle) in cases {
        let error = compile(spec(extra.clone())).expect_err(&extra.to_string());
        assert!(error.contains(needle), "{extra}: {error}");
    }
}

#[test]
fn an_event_carries_the_row_its_key_and_a_stable_id() {
    let plan = compile(spec(json!({ "occurred_at_column": "at" }))).unwrap();
    let row = json!({ "id": 7, "at": "2026-10-10T12:00:00.5+02:00", "body": "x" });
    let event = row_event(&plan, "mcpg-event://orders.new", row.clone(), &[json!(7)]).unwrap();
    assert_eq!(event.event_type.as_deref(), Some(EVENT_TYPE));
    assert_eq!(
        event.data,
        Some(json!({ "op": "insert", "row": row.clone() }))
    );
    assert_eq!(event.upstream_cursor, Some(json!({ "v": 1, "k": [7] })));
    assert_eq!(
        event.occurred_at.as_deref(),
        Some("2026-10-10T10:00:00.500Z")
    );
    let id = event.event_id.clone().unwrap();
    assert!(id.starts_with("row-") && id.len() == 36, "{id}");
    let id_of = |uri: &str, key: i64| {
        row_event(&plan, uri, row.clone(), &[json!(key)])
            .unwrap()
            .event_id
    };
    assert_eq!(
        id_of("mcpg-event://orders.new", 7),
        Some(id.clone()),
        "a re-read row keeps its id"
    );
    assert_ne!(id_of("mcpg-event://orders.new", 8), Some(id.clone()));
    assert_ne!(id_of("mcpg-event://other", 7), Some(id));
}

#[test]
fn the_op_column_says_what_each_change_did() {
    let plan = compile(spec(json!({ "op_column": "op" }))).unwrap();
    for (value, want) in [
        (json!("insert"), Some("insert")),
        (json!("UPDATE"), Some("update")),
        (json!("Delete"), Some("delete")),
        (json!("upsert"), None),
        (json!(1), None),
        (Value::Null, None),
    ] {
        let row = json!({ "id": 1, "op": value.clone() });
        let op = row_event(&plan, "mcpg-event://t", row, &[json!(1)])
            .map(|e| e.data.unwrap()["op"].as_str().unwrap().to_owned());
        assert_eq!(op.as_deref(), want, "{value}");
    }
    let missing = row_event(&plan, "mcpg-event://t", json!({ "id": 1 }), &[json!(1)]);
    assert!(
        missing.is_none(),
        "a row without its op column names no change"
    );
}

#[test]
fn an_update_of_one_row_is_its_own_event() {
    let plan = compile(spec(json!({
        "query": {
            "row_mode": "many",
            "sql": "SELECT * FROM t WHERE (updated_at, id) > (:_after_updated_at, :_after_id) ORDER BY updated_at, id LIMIT :_limit"
        },
        "key_columns": ["updated_at", "id"],
        "initial": { "updated_at": 0, "id": 0 },
        "op_column": "op"
    })))
    .unwrap();
    let first = row_event(
        &plan,
        "mcpg-event://t",
        json!({ "id": 1, "updated_at": 10, "op": "insert" }),
        &[json!(10), json!(1)],
    )
    .unwrap();
    let second = row_event(
        &plan,
        "mcpg-event://t",
        json!({ "id": 1, "updated_at": 11, "op": "update" }),
        &[json!(11), json!(1)],
    )
    .unwrap();
    assert_ne!(first.event_id, second.event_id);
    assert_eq!(second.data.unwrap()["op"], "update");
}

#[test]
fn row_times_read_as_utc() {
    for (value, want) in [
        (
            json!("2026-10-10T12:00:00Z"),
            Some("2026-10-10T12:00:00.000Z"),
        ),
        (
            json!("2026-10-10T12:00:00.123456"),
            Some("2026-10-10T12:00:00.123Z"),
        ),
        (
            json!("2026-10-10 12:00:00"),
            Some("2026-10-10T12:00:00.000Z"),
        ),
        (json!(1_790_000_000), Some("2026-09-21T14:13:20.000Z")),
        (json!("not a time"), None),
        (json!(true), None),
    ] {
        assert_eq!(occurred_at(&value).as_deref(), want, "{value}");
    }
}

#[test]
fn a_stored_position_must_fit_the_key() {
    let plan = compile(spec(json!({}))).unwrap();
    assert_eq!(
        resume_key(&plan, json!({ "v": 1, "k": [12] })).unwrap(),
        [json!(12)]
    );
    for bad in [
        json!({ "v": 1, "k": [1, 2] }),
        json!({ "v": 2, "k": [1] }),
        json!({ "k": [1] }),
        json!("12"),
    ] {
        assert!(resume_key(&plan, bad.clone()).is_err(), "{bad}");
    }
}

/// A driver that answers each query from a script and records its args.
struct ScriptedDriver {
    pages: StdMutex<Vec<Vec<Value>>>,
    calls: StdMutex<Vec<(String, Vec<Value>)>>,
}

impl ScriptedDriver {
    fn new(pages: Vec<Vec<Value>>) -> Arc<Self> {
        Arc::new(Self {
            pages: StdMutex::new(pages),
            calls: StdMutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, Vec<Value>)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl SqlDriver for ScriptedDriver {
    fn kind(&self) -> &'static str {
        "scripted"
    }

    async fn connect(&self, _cfg: &ConnectCfg) -> Result<crate::driver::ConnectOutcome, SqlError> {
        Err(SqlError::InvalidSpec("scripted".into()))
    }

    async fn execute(
        &self,
        _pool: &PoolHandle,
        stmt: &PreparedStmt,
        args: &[BoundParam],
        _session: &SessionVars,
    ) -> Result<RowBatch, SqlError> {
        self.calls.lock().unwrap().push((
            stmt.sql.clone(),
            args.iter().map(|a| a.value.clone()).collect(),
        ));
        let mut pages = self.pages.lock().unwrap();
        let rows = if pages.is_empty() {
            Vec::new()
        } else {
            pages.remove(0)
        };
        Ok(RowBatch {
            rows,
            ..RowBatch::default()
        })
    }

    async fn execute_affected(
        &self,
        _pool: &PoolHandle,
        _stmt: &PreparedStmt,
        _args: &[BoundParam],
        _session: &SessionVars,
    ) -> Result<u64, SqlError> {
        Ok(0)
    }

    async fn health_check(&self, _pool: &PoolHandle) -> Result<(), SqlError> {
        Ok(())
    }
}

#[derive(Default)]
struct Collect(StdMutex<Vec<WatchEvent>>);

#[async_trait]
impl WatchEventSink for Collect {
    async fn emit(&self, event: WatchEvent) {
        self.0.lock().unwrap().push(event);
    }
}

#[cfg(feature = "sqlite")]
async fn pool() -> PoolHandle {
    PoolHandle::Sqlite(
        sqlx::sqlite::SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap(),
    )
}

fn rows(ids: std::ops::RangeInclusive<i64>) -> Vec<Value> {
    ids.map(|id| json!({ "id": id, "body": format!("r{id}") }))
        .collect()
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_full_page_reads_on_and_the_key_moves_past_every_row() {
    let plan = compile(spec(json!({ "batch_size": 2 }))).unwrap();
    let scripted = ScriptedDriver::new(vec![rows(1..=2), rows(3..=4), rows(5..=5)]);
    let driver: Arc<dyn SqlDriver> = scripted.clone();
    let sink = Collect::default();
    let mut key = vec![json!(0)];
    poll(
        &plan,
        &driver,
        &pool().await,
        &SessionVars::default(),
        "mcpg-event://t",
        &mut key,
        &sink,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let events = sink.0.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|e| e.data.as_ref().unwrap()["row"]["id"].clone())
            .collect::<Vec<_>>(),
        [json!(1), json!(2), json!(3), json!(4), json!(5)]
    );
    assert_eq!(key, [json!(5)]);
    assert_eq!(
        scripted
            .calls()
            .iter()
            .map(|(_, args)| args.clone())
            .collect::<Vec<_>>(),
        [
            vec![json!(0), json!(2)],
            vec![json!(2), json!(2)],
            vec![json!(4), json!(2)],
        ],
        "each page starts after the last row"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn one_tick_stops_at_its_row_budget() {
    let plan = compile(spec(json!({ "batch_size": 500 }))).unwrap();
    let scripted = ScriptedDriver::new(vec![rows(1..=500), rows(501..=1000)]);
    let driver: Arc<dyn SqlDriver> = scripted.clone();
    let sink = Collect::default();
    let mut key = vec![json!(0)];
    poll(
        &plan,
        &driver,
        &pool().await,
        &SessionVars::default(),
        "mcpg-event://t",
        &mut key,
        &sink,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), MAX_ROWS_PER_TICK);
    assert_eq!(key, [json!(500)]);
    assert_eq!(scripted.calls().len(), 1, "the next tick reads on");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_row_without_its_key_stops_the_page_without_moving_past_it() {
    let plan = compile(spec(json!({}))).unwrap();
    let scripted = ScriptedDriver::new(vec![vec![
        json!({ "id": 1 }),
        json!({ "id": null }),
        json!({ "id": 3 }),
    ]]);
    let driver: Arc<dyn SqlDriver> = scripted;
    let sink = Collect::default();
    let mut key = vec![json!(0)];
    let error = poll(
        &plan,
        &driver,
        &pool().await,
        &SessionVars::default(),
        "mcpg-event://t",
        &mut key,
        &sink,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("key column"), "{error}");
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    assert_eq!(key, [json!(1)]);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_row_too_large_for_an_event_is_skipped_and_passed() {
    let plan = compile(spec(json!({}))).unwrap();
    let big = "x".repeat(MAX_EVENT_BYTES);
    let scripted = ScriptedDriver::new(vec![vec![
        json!({ "id": 1, "body": big }),
        json!({ "id": 2, "body": "small" }),
    ]]);
    let driver: Arc<dyn SqlDriver> = scripted;
    let sink = Collect::default();
    let mut key = vec![json!(0)];
    poll(
        &plan,
        &driver,
        &pool().await,
        &SessionVars::default(),
        "mcpg-event://t",
        &mut key,
        &sink,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].upstream_cursor, Some(json!({ "v": 1, "k": [2] })));
    assert_eq!(key, [json!(2)]);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn latest_starts_after_the_newest_key_or_initial_on_an_empty_table() {
    let plan = compile(spec(json!({
        "start": "latest",
        "latest_sql": "SELECT MAX(id) AS id FROM t"
    })))
    .unwrap();
    let pool = pool().await;
    let cancel = CancellationToken::new();
    let found: Arc<dyn SqlDriver> = ScriptedDriver::new(vec![vec![json!({ "id": 42 })]]);
    assert_eq!(
        start_key(&plan, &found, &pool, &SessionVars::default(), &cancel)
            .await
            .unwrap(),
        Some(vec![json!(42)])
    );
    let empty: Arc<dyn SqlDriver> = ScriptedDriver::new(vec![vec![json!({ "id": null })]]);
    assert_eq!(
        start_key(&plan, &empty, &pool, &SessionVars::default(), &cancel)
            .await
            .unwrap(),
        Some(vec![json!(0)])
    );
    let beginning = compile(spec(json!({}))).unwrap();
    let unused: Arc<dyn SqlDriver> = ScriptedDriver::new(Vec::new());
    assert_eq!(
        start_key(&beginning, &unused, &pool, &SessionVars::default(), &cancel)
            .await
            .unwrap(),
        Some(vec![json!(0)])
    );
}

#[tokio::test]
async fn watch_refuses_a_bad_spec_or_a_foreign_position_at_once() {
    let plugin = SqlChangesWatchPlugin::new();
    let sink: Arc<dyn WatchEventSink> = Arc::new(Collect::default());
    let bad = plugin
        .watch(
            "mcpg-event://t",
            &spec(json!({ "batch_size": 0 })),
            Arc::clone(&sink),
        )
        .await;
    assert!(matches!(bad, Err(WatchError::InvalidSpec { .. })));
    let mut resumed = spec(json!({}));
    resumed[mcpg_plugin_protocol::WATCH_RESUME_SPEC_KEY] = json!({ "v": 1, "k": [1, 2] });
    let foreign = plugin.watch("mcpg-event://t", &resumed, sink).await;
    assert!(
        matches!(foreign, Err(WatchError::InvalidSpec { message }) if message.contains("key changed"))
    );
}
