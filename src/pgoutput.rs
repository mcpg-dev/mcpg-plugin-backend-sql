//! A decoder of PostgreSQL's built-in logical replication output plugin,
//! `pgoutput` (protocol version 1): the messages of one decoding session,
//! as `pg_logical_slot_peek_binary_changes` returns them, one per row.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

/// Microseconds between the Unix epoch and PostgreSQL's, 2000-01-01.
const PG_EPOCH_MICROS: i64 = 946_684_800_000_000;

/// A table, as a Relation message describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Relation {
    pub schema: String,
    pub name: String,
    pub columns: Vec<Column>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub name: String,
    pub type_oid: u32,
    pub key: bool,
}

/// One column value of a tuple.
#[derive(Debug, Clone, PartialEq)]
pub enum Datum {
    Null,
    /// A TOASTed value the change left as it was: not sent.
    Unchanged,
    Text(String),
}

/// One decoded message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Begin {
        final_lsn: u64,
        commit_time_micros: i64,
        xid: u32,
    },
    Commit {
        end_lsn: u64,
    },
    Relation {
        oid: u32,
        relation: Relation,
    },
    Insert {
        oid: u32,
        new: Vec<Datum>,
    },
    /// `old` is the old key (`full: false`) or row (`full: true`), when the
    /// replica identity sends one.
    Update {
        oid: u32,
        old: Option<(Vec<Datum>, bool)>,
        new: Vec<Datum>,
    },
    Delete {
        oid: u32,
        old: Vec<Datum>,
        full: bool,
    },
    Truncate {
        oids: Vec<u32>,
        cascade: bool,
        restart_identity: bool,
    },
    /// Origin, Type, logical Message: nothing a row change needs.
    Other,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "pgoutput message ends early".to_owned())?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
    fn string(&mut self) -> Result<String, String> {
        let rest = &self.bytes[self.at..];
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| "pgoutput string is not terminated".to_owned())?;
        let text = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.at += end + 1;
        Ok(text)
    }
    fn tuple(&mut self) -> Result<Vec<Datum>, String> {
        let columns = self.u16()?;
        let mut datums = Vec::with_capacity(usize::from(columns));
        for _ in 0..columns {
            datums.push(match self.u8()? {
                b'n' => Datum::Null,
                b'u' => Datum::Unchanged,
                b't' => {
                    let len = usize::try_from(self.i32()?)
                        .map_err(|_| "pgoutput value has a negative length".to_owned())?;
                    Datum::Text(String::from_utf8_lossy(self.take(len)?).into_owned())
                }
                kind => {
                    return Err(format!(
                        "pgoutput value kind '{}' is not text",
                        kind as char
                    ));
                }
            });
        }
        Ok(datums)
    }
}

/// Decode one pgoutput message.
pub fn decode(bytes: &[u8]) -> Result<Message, String> {
    let mut r = Reader { bytes, at: 0 };
    Ok(match r.u8()? {
        b'B' => Message::Begin {
            final_lsn: r.u64()?,
            commit_time_micros: r.i64()?,
            xid: r.u32()?,
        },
        b'C' => {
            let _flags = r.u8()?;
            let _commit_lsn = r.u64()?;
            let end_lsn = r.u64()?;
            Message::Commit { end_lsn }
        }
        b'R' => {
            let oid = r.u32()?;
            let schema = r.string()?;
            let name = r.string()?;
            let _replica_identity = r.u8()?;
            let count = r.u16()?;
            let mut columns = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                let flags = r.u8()?;
                let name = r.string()?;
                let type_oid = r.u32()?;
                let _modifier = r.i32()?;
                columns.push(Column {
                    name,
                    type_oid,
                    key: flags & 1 == 1,
                });
            }
            Message::Relation {
                oid,
                relation: Relation {
                    schema: if schema.is_empty() {
                        "pg_catalog".into()
                    } else {
                        schema
                    },
                    name,
                    columns,
                },
            }
        }
        b'I' => {
            let oid = r.u32()?;
            match r.u8()? {
                b'N' => Message::Insert {
                    oid,
                    new: r.tuple()?,
                },
                kind => return Err(format!("pgoutput insert has tuple '{}'", kind as char)),
            }
        }
        b'U' => {
            let oid = r.u32()?;
            let mut old = None;
            let mut kind = r.u8()?;
            if kind == b'K' || kind == b'O' {
                old = Some((r.tuple()?, kind == b'O'));
                kind = r.u8()?;
            }
            if kind != b'N' {
                return Err(format!("pgoutput update has tuple '{}'", kind as char));
            }
            Message::Update {
                oid,
                old,
                new: r.tuple()?,
            }
        }
        b'D' => {
            let oid = r.u32()?;
            match r.u8()? {
                kind @ (b'K' | b'O') => Message::Delete {
                    oid,
                    old: r.tuple()?,
                    full: kind == b'O',
                },
                kind => return Err(format!("pgoutput delete has tuple '{}'", kind as char)),
            }
        }
        b'T' => {
            let count = r.u32()?;
            let options = r.u8()?;
            let mut oids = Vec::new();
            for _ in 0..count {
                oids.push(r.u32()?);
            }
            Message::Truncate {
                oids,
                cascade: options & 1 == 1,
                restart_identity: options & 2 == 2,
            }
        }
        _ => Message::Other,
    })
}

/// A column value as JSON, by its type: numbers and booleans as such,
/// `json`/`jsonb` parsed, `numeric` and everything else as PostgreSQL's
/// text.
pub fn value_of(type_oid: u32, text: &str) -> Value {
    match type_oid {
        16 => json!(text == "t"),
        20 | 21 | 23 | 26 => text
            .parse::<i64>()
            .map_or_else(|_| json!(text), |n| json!(n)),
        700 | 701 => text
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .map_or_else(|| json!(text), |f| json!(f)),
        114 | 3802 => serde_json::from_str(text).unwrap_or_else(|_| json!(text)),
        _ => json!(text),
    }
}

/// A tuple as a JSON object, and the columns a change left unchanged
/// (TOAST). With `keys_only`, only the key columns.
pub fn row_of(
    relation: &Relation,
    datums: &[Datum],
    keys_only: bool,
) -> (Map<String, Value>, Vec<String>) {
    let mut row = Map::new();
    let mut unchanged = Vec::new();
    for (column, datum) in relation.columns.iter().zip(datums) {
        if keys_only && !column.key {
            continue;
        }
        match datum {
            Datum::Null => {
                row.insert(column.name.clone(), Value::Null);
            }
            Datum::Unchanged => unchanged.push(column.name.clone()),
            Datum::Text(text) => {
                row.insert(column.name.clone(), value_of(column.type_oid, text));
            }
        }
    }
    (row, unchanged)
}

/// An LSN as PostgreSQL writes it, `X/Y`.
pub fn lsn_text(lsn: u64) -> String {
    format!("{:X}/{:X}", lsn >> 32, lsn & 0xFFFF_FFFF)
}

/// An LSN from PostgreSQL's `X/Y`.
pub fn parse_lsn(text: &str) -> Option<u64> {
    let (high, low) = text.split_once('/')?;
    Some((u64::from_str_radix(high, 16).ok()? << 32) | u64::from_str_radix(low, 16).ok()?)
}

/// A commit time, RFC 3339, from microseconds since 2000-01-01.
pub fn commit_time(micros: i64) -> Option<String> {
    mcpg_plugin_protocol::occurred_at_from_millis((micros + PG_EPOCH_MICROS) / 1_000)
}

/// The relations of one decoding session, by oid.
pub type Relations = HashMap<u32, Relation>;
