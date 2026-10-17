use super::*;
use crate::pgoutput::{Datum, Relation};

fn stub_host() -> HostHandle {
    // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
    // factory ignores the host entirely.
    #[allow(unsafe_code)]
    unsafe {
        HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
    }
}

fn plugin() -> PostgresCdcWatchCdylib {
    PostgresCdcWatchCdylib::from_host_config("", stub_host())
}

#[test]
fn a_tls_configuration_can_be_built_once_the_plugin_is_made() {
    let _ = plugin();
    let _ = rustls::ClientConfig::builder();
}

fn refused(spec: Value) -> String {
    match plugin().watch("mcpg-event://orders", &spec, Box::new(|_| {})) {
        Err(WatchError::InvalidSpec { message }) => message,
        Err(other) => panic!("not a spec error: {other:?}"),
        Ok(handle) => {
            plugin().cancel(handle);
            panic!("accepted {spec}");
        }
    }
}

/// pgoutput's encoding of a string: its bytes and a zero.
fn cstr(s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    b
}

fn relation_message() -> Vec<u8> {
    let mut m = vec![b'R'];
    m.extend(16_384u32.to_be_bytes());
    m.extend(cstr("public"));
    m.extend(cstr("orders"));
    m.push(b'd');
    m.extend(3u16.to_be_bytes());
    for (flags, name, oid) in [(1u8, "id", 23u32), (0, "status", 25), (0, "meta", 3802)] {
        m.push(flags);
        m.extend(cstr(name));
        m.extend(oid.to_be_bytes());
        m.extend((-1i32).to_be_bytes());
    }
    m
}

fn tuple(values: &[Option<&str>]) -> Vec<u8> {
    let mut t = (values.len() as u16).to_be_bytes().to_vec();
    for value in values {
        match value {
            None => t.push(b'n'),
            Some("<toast>") => t.push(b'u'),
            Some(text) => {
                t.push(b't');
                t.extend((text.len() as i32).to_be_bytes());
                t.extend(text.as_bytes());
            }
        }
    }
    t
}

#[test]
fn manifest_and_kind_are_correct() {
    use mcpg_plugin_protocol::PluginClass;
    let p = plugin();
    assert_eq!(SyncWatchStrategyPlugin::manifest(&p).id, PLUGIN_ID);
    assert_eq!(
        SyncWatchStrategyPlugin::manifest(&p).plugin_class,
        PluginClass::WatchStrategy
    );
    assert_eq!(p.kind(), WATCH_KIND);
}

#[test]
fn a_bad_spec_is_refused_before_anything_connects() {
    let with = |extra: Value| {
        let mut spec = json!({ "url": "postgres://u:p@db/app", "publication": "mcpg" });
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        spec
    };
    assert!(refused(with(json!({ "bogus": 1 }))).contains("unknown field"));
    assert!(refused(with(json!({ "url": "mysql://db" }))).contains("postgres://"));
    assert!(refused(with(json!({ "url": "postgres://u:cred://x@db" }))).contains("cred://"));
    assert!(refused(with(json!({ "publication": " " }))).contains("publication"));
    assert!(refused(with(json!({ "slot": "Bad-Slot" }))).contains("slot"));
    assert!(refused(with(json!({ "poll_interval_ms": 10 }))).contains("poll_interval_ms"));
    assert!(refused(with(json!({ "max_in_flight": 0 }))).contains("max_in_flight"));
}

#[test]
fn the_derived_slot_is_a_valid_name_the_same_for_the_same_source() {
    let slot = derived_slot("mcpg-event://orders");
    assert!(valid_slot(&slot));
    assert_eq!(slot, derived_slot("mcpg-event://orders"));
    assert_ne!(slot, derived_slot("mcpg-event://other"));
    assert_eq!(quoted_table("public.my\"t"), "\"public\".\"my\"\"t\"");
}

#[test]
fn lsns_read_and_write_as_postgresql_does() {
    assert_eq!(parse_lsn("16/B374D848"), Some(0x16_B374_D848));
    assert_eq!(lsn_text(0x16_B374_D848), "16/B374D848");
    assert_eq!(parse_lsn("nope"), None);
}

#[test]
fn pgoutput_messages_decode() {
    let Message::Relation { oid, relation } = decode(&relation_message()).unwrap() else {
        panic!("a relation");
    };
    assert_eq!(oid, 16_384);
    assert_eq!(
        (relation.schema.as_str(), relation.name.as_str()),
        ("public", "orders")
    );
    assert!(relation.columns[0].key && !relation.columns[1].key);

    let mut begin = vec![b'B'];
    begin.extend(0x10u64.to_be_bytes());
    begin.extend(0i64.to_be_bytes());
    begin.extend(742u32.to_be_bytes());
    assert_eq!(
        decode(&begin).unwrap(),
        Message::Begin {
            final_lsn: 0x10,
            commit_time_micros: 0,
            xid: 742
        }
    );
    assert_eq!(commit_time(0).as_deref(), Some("2000-01-01T00:00:00.000Z"));

    let mut insert = vec![b'I'];
    insert.extend(16_384u32.to_be_bytes());
    insert.push(b'N');
    insert.extend(tuple(&[Some("7"), Some("open"), Some(r#"{"a":1}"#)]));
    let Message::Insert { new, .. } = decode(&insert).unwrap() else {
        panic!("an insert");
    };
    let (row, unchanged) = row_of(&relation, &new, false);
    assert_eq!(
        Value::Object(row),
        json!({ "id": 7, "status": "open", "meta": { "a": 1 } })
    );
    assert!(unchanged.is_empty());

    let mut update = vec![b'U'];
    update.extend(16_384u32.to_be_bytes());
    update.push(b'O');
    update.extend(tuple(&[Some("7"), Some("open"), None]));
    update.push(b'N');
    update.extend(tuple(&[Some("7"), Some("closed"), Some("<toast>")]));
    let Message::Update { old, new, .. } = decode(&update).unwrap() else {
        panic!("an update");
    };
    assert!(old.is_some());
    assert_eq!(new[2], Datum::Unchanged);
    let (row, unchanged) = row_of(&relation, &new, false);
    assert_eq!(row["status"], json!("closed"));
    assert_eq!(unchanged, ["meta"]);

    let mut delete = vec![b'D'];
    delete.extend(16_384u32.to_be_bytes());
    delete.push(b'K');
    delete.extend(tuple(&[Some("7"), None, None]));
    assert!(matches!(decode(&delete).unwrap(), Message::Delete { .. }));

    let mut truncate = vec![b'T'];
    truncate.extend(1u32.to_be_bytes());
    truncate.push(3);
    truncate.extend(16_384u32.to_be_bytes());
    assert_eq!(
        decode(&truncate).unwrap(),
        Message::Truncate {
            oids: vec![16_384],
            cascade: true,
            restart_identity: true
        }
    );

    let mut commit = vec![b'C', 0];
    commit.extend(0x10u64.to_be_bytes());
    commit.extend(0x20u64.to_be_bytes());
    commit.extend(0i64.to_be_bytes());
    assert_eq!(decode(&commit).unwrap(), Message::Commit { end_lsn: 0x20 });
    assert!(decode(&insert[..5]).is_err(), "a message cut short");
    assert_eq!(decode(b"Y").unwrap(), Message::Other);
}

#[test]
fn values_follow_their_types() {
    use crate::pgoutput::value_of;
    assert_eq!(value_of(16, "t"), json!(true));
    assert_eq!(
        value_of(20, "9007199254740993"),
        json!(9_007_199_254_740_993i64)
    );
    assert_eq!(value_of(701, "1.5"), json!(1.5));
    assert_eq!(value_of(701, "NaN"), json!("NaN"));
    assert_eq!(
        value_of(1700, "1.10"),
        json!("1.10"),
        "numeric keeps its digits"
    );
    assert_eq!(value_of(114, "[1,2]"), json!([1, 2]));
    assert_eq!(
        value_of(1184, "2026-10-10 12:00:00+00"),
        json!("2026-10-10 12:00:00+00")
    );
}

#[test]
fn a_change_event_names_its_table_transaction_and_lsn() {
    let mut relations: Relations = HashMap::new();
    let Message::Relation { oid, relation } = decode(&relation_message()).unwrap() else {
        panic!()
    };
    relations.insert(oid, relation);
    let events = change_events(
        "mcpg_x",
        0x1_0000_0010,
        Some((742, 0)),
        &relations,
        Message::Delete {
            oid,
            old: vec![Datum::Text("7".into()), Datum::Null, Datum::Null],
            full: false,
        },
    )
    .unwrap();
    let event = &events[0];
    assert_eq!(event.event_id.as_deref(), Some("mcpg_x/1/10"));
    assert_eq!(event.event_type.as_deref(), Some(ROW_CHANGED_EVENT_TYPE));
    let data = event.data.as_ref().unwrap();
    assert_eq!(data["op"], json!("delete"));
    assert_eq!(data["table"], json!("orders"));
    assert_eq!(
        data["row"],
        json!({ "id": 7 }),
        "a key-only identity: the key alone"
    );
    assert_eq!(data["xid"], json!(742));
    assert_eq!(data["lsn"], json!("1/10"));
    let truncated = change_events(
        "mcpg_x",
        0x30,
        None,
        &relations,
        Message::Truncate {
            oids: vec![oid],
            cascade: false,
            restart_identity: false,
        },
    )
    .unwrap();
    assert_eq!(
        truncated[0].event_type.as_deref(),
        Some(TRUNCATED_EVENT_TYPE)
    );
    let unknown = change_events(
        "mcpg_x",
        0x40,
        None,
        &relations,
        Message::Insert {
            oid: 1,
            new: Vec::new(),
        },
    );
    assert!(unknown.is_err(), "a change before its relation");
    let _: &Relation = relations.values().next().unwrap();
}

#[test]
fn the_slot_advances_past_leading_transactions_acknowledged_in_full() {
    let mut progress = Progress::default();
    for (end, changes) in [
        (0x20u64, vec![0x11u64, 0x12]),
        (0x40, vec![0x31]),
        (0x50, vec![]),
    ] {
        let tx = progress.transactions.entry(end).or_default();
        tx.changes = changes.iter().copied().collect();
        tx.complete = true;
        for change in changes {
            progress.owner.insert(change, end);
            progress.delivered.insert(change);
        }
    }
    let ack = |progress: &mut Progress, lsn: u64| {
        let end = progress.owner[&lsn];
        progress
            .transactions
            .get_mut(&end)
            .unwrap()
            .acked
            .insert(lsn);
    };
    ack(&mut progress, 0x31);
    assert_eq!(
        progress.advance(),
        None,
        "the first transaction is not done"
    );
    ack(&mut progress, 0x11);
    assert_eq!(progress.advance(), None);
    ack(&mut progress, 0x12);
    assert_eq!(
        progress.advance(),
        Some(0x50),
        "past the first, the second, and the empty third"
    );
    assert!(progress.transactions.is_empty() && progress.delivered.is_empty());
}
