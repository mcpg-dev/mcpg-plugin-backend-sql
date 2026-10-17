# SQL Backend — `dev.mcpg.backend.sql`

> class `backend` · `native` · package `mcpg-plugin-backend-sql` · artifact `libmcpg_plugin_backend_sql.so`

SQL database backend plugin for mcpg. Exposes relational databases
(Postgres, MySQL/MariaDB, SQLite) as MCP tools, resources, and pipeline
steps via the standard `BackendPlugin` contract plus SQL-specific
surfaces. Reach for it to query a database directly instead of
wrapping it behind a REST service.

One cdylib ships four entities under `dev.mcpg.backend.sql`:

| `backend.kind` | Entity manifest id | Surface |
|---|---|---|
| `sql` | `dev.mcpg.backend.sql` | tool / resource / pipeline-step dispatch |
| `sql_polling` | `dev.mcpg.watch.sql_polling` | interval-hash resource watch strategy |
| `postgres_listen_notify` | `dev.mcpg.watch.postgres_listen_notify` | Postgres `LISTEN`/`NOTIFY` watch strategy |
| `sql_changes` | `dev.mcpg.watch.sql_changes` | each inserted, updated or deleted row a keyset query reads, as an MCP Events source that resumes |

## Configuration

The `plugins:` entry just loads the cdylib; per-call config lives in
each tool/resource binding's `backend: { kind: sql, ... }` block (the
plugin owns its own `SqlBackendConfig` shape and validates it at boot).

```yaml
plugins:
  - id: dev.mcpg.backend.sql
    class: backend
    source: { path: ./plugins/libmcpg_plugin_backend_sql.so }
```

The binding `backend.kind: sql` block must carry at least `driver`,
`url`, and `query` (see "Minimal config" below for the full shape).

## Status

**Shipped.** Synchronous request/response
calls against PostgreSQL, MySQL/MariaDB, and SQLite. All six row
modes ship: `single | many | scalar | affected_rows |
resource_contents | stream`. Parameters are always bound through
sqlx's prepared-statement interface — no string interpolation, ever.

Additional capabilities shipped beyond the MVP:

- **`list_query`** — keyset-paginated dynamic `resources/list` provider
  for `kind: resource_template` backends.
- **`await:`** — fire-and-wait runtime: optional trigger → poll check →
  CEL predicate → return the matched row or `Timeout`.
- **`sql_tx` pipeline step** — transactional grouping of N statements
  on a pinned pool connection; rollback on any nested-step failure
  Postgres + SQLite; MySQL returns `InvalidSpec` until the
  driver-side `SqlTxHandle` impl lands.
- **Driver-level cancel** — Postgres via `pg_cancel_backend` on a side
  connection; MySQL via `KILL QUERY <connection_id>` (requires
  `PROCESS` / `CONNECTION_ADMIN` privilege on the pool user —
  probed at registration via `SHOW GRANTS FOR CURRENT_USER`; opt out
  with `pool.require_cancel_privilege: false`).
- **Watch strategies** — `sql_polling` (interval hash),
  `postgres_listen_notify` (push via `LISTEN`/`NOTIFY`) and `sql_changes`
  (a keyset query over an id, a change marker or a trigger outbox; one
  `sql.row.changed` event per row with `op` `insert`, `update` or
  `delete`; resumes after the last stored key) as pluggable
  `WatchStrategyPlugin`s; and `postgres_cdc`, every change a
  PostgreSQL publication carries, from a logical replication slot (see
  [PostgreSQL change data capture](#postgresql-change-data-capture-postgres_cdc)).
- **Schema-drift retry** — automatic one-shot retry on Postgres
  SQLSTATEs `26000`/`42P18`/`0A000` and MySQL `1615 ER_NEED_REPREPARE`
  when a cached prepared statement goes stale after concurrent DDL.
- **CEL-computed params** via `param_exprs`, schema derivation
  from prepared-statement metadata, per-backend circuit breaker,
  in-flight progress heartbeats, and structured `mcpg::sql::audit`
  tracing.

Not yet shipped:
`row_mode: stream` cursor continuation (first-chunk shape ships today;
`fetch_more` is the follow-up), poll-mode content-fetcher bridge for
the WatchEngine, and MSSQL driver.

Session vars work on Postgres (via `SET LOCAL` inside a transaction)
and MySQL/MariaDB (bound `SET @var` statements on a pinned
connection); SQLite ignores them.

## Supported engines

| Driver     | Scheme(s)                | Backend         | Session vars       | INSERT/UPDATE `rows_affected` |
|------------|--------------------------|-----------------|--------------------|-------------------------------|
| Postgres   | `postgres`, `postgresql` | `sqlx/postgres` | yes (`SET LOCAL`)  | yes                           |
| MySQL      | `mysql`, `mariadb`       | `sqlx/mysql`    | yes (`SET @var`)   | yes                           |
| SQLite     | `sqlite`                 | `sqlx/sqlite`   | no                 | yes                           |

Each driver is gated behind a Cargo feature of the same name. The
default build enables all three.

## Credentials

The connection URL is the **sole credential surface**. Operators embed
secrets directly in the URL and use the gateway's string interpolator
(`${env.VAR}` at config-load time; future `vault:…` / `aws-sm:…`
schemes via a plugin-provided resolver) so cleartext never lives in
YAML source. The earlier `backends.sql.credentials.{password_env,
password_file, password_ref}` block was removed in favor of a single
gateway-wide secret resolver (see commit `c5e6e97`).

## Minimal config

A tool entry under `mcp.capabilities.tools[]` whose backend selects
the SQL plugin via `backend.kind: sql`:

```yaml
mcp:
  capabilities:
    tools:
      - name: get-order
        description: Fetch an order by ID.
        backend:
          kind: sql
          driver: postgres
          url: "postgres://mcpg:${env.ORDERS_DB_PASSWORD}@db.internal/orders?sslmode=require"
          query:
            sql: "SELECT id, total FROM orders WHERE id = :order_id"
            params: [order_id]
            row_mode: single
```

> Per-entry `kind:` was dropped in Layout #4 Slice B2 — list
> membership (`tools[]` vs `prompts[]` vs `resources[]` vs
> `resource_templates[]`) carries the capability kind; only
> `backend.kind` selects the implementation.

## Stored procedure

```yaml
- name: settle-invoice
  description: Run the settle_invoice stored procedure.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://mcpg:${env.ORDERS_DB_PASSWORD}@db.internal/orders"
    query:
      procedure: "orders.settle_invoice"
      params: [invoice_id, amount_cents]
      row_mode: affected_rows
```

The driver emits `CALL orders.settle_invoice($1, $2)` for Postgres or
`CALL orders.settle_invoice(?, ?)` for MySQL. Procedures that return
a result row can use `row_mode: single`.

## Multi-tenant RLS (Postgres)

```yaml
- name: list-tickets
  description: List tickets; tenant-scoped via Postgres RLS.
  backend:
    kind: sql
    driver: postgres
    url: "postgres://mcpg:${env.SUPPORT_DB_PASSWORD}@db.internal/support"
    query:
      sql: "SELECT id, title, status FROM tickets"
      row_mode: many
      max_rows: 100
    session_vars:
      # Values are parameter-bound via `set_config()`; identifier
      # safety is enforced at config parse (`is_safe_sql_identifier`).
      # A Postgres RLS policy keyed on
      # `current_setting('app.current_tenant')` now sees the
      # authenticated principal's tenant on every call.
      "app.current_tenant": "${identity.tenant}"
```

## Row mode cheat sheet

| `row_mode`          | Returns                                                           | Use case                              |
|---------------------|-------------------------------------------------------------------|---------------------------------------|
| `single`            | one JSON object keyed by column, or `null`                        | `get_order_by_id`                     |
| `many`              | JSON array of objects (capped by `max_rows`)                      | `list_open_tickets`                   |
| `scalar`            | first column of first row as a naked value                        | `SELECT count(*)`                     |
| `affected_rows`     | `{"rows_affected": N}` from the driver                            | INSERT / UPDATE / DELETE              |
| `resource_contents` | `{"contents": [{"uri", "text"|"blob", "mimeType"?}]}` envelope    | resource / resource_template reads    |
| `stream`            | `{"rows": [...], "next_cursor": null, "truncated": bool}`         | iterable SELECTs — keyset continuation |

`max_rows` still applies to every read mode — oversized results are
truncated at the row boundary and `truncated: true` surfaces in the
response payload (for `stream`) or on `_meta` (for the other modes).

For the full config surface, YAML examples, metrics, and design
rationale see
[the backends reference](https://mcpg.dev/docs/reference/backends).
This README stays deliberately short so it doesn't drift with every
doc update.

## Threat model: SQL injection

Parameter **values** always flow through sqlx's prepared-statement
binding — never string-interpolated. That single rule prevents the
classic injection vector regardless of what the caller sends in
`arguments`.

Config-side fields that the plugin *does* inline into the statement
text are defense-in-depth'd at `register_profile`:

| Surface | Inlined where | Validator | Reject pattern |
|---|---|---|---|
| `query.procedure` | `CALL <procedure>(...)` | `is_safe_sql_identifier` | `;`, spaces, quotes, operators |
| `query.sql` / `sql_file` | executed verbatim | `reject_multi_statement` | unquoted `;` between statements |
| `session_vars` keys | `set_config('<key>', $1, true)` | `is_safe_sql_identifier` | same as procedure |
| `session_vars` values | bound as `$1` | n/a | n/a — parameterized |
| `param_exprs` results | bound as parameters | n/a | n/a — parameterized |
| `list_query.cursor_column` | inlined into ORDER BY | `is_safe_sql_identifier` | same as procedure |

Operator-supplied SQL bodies are **trusted by design**: operators
declare their queries intentionally, and the backend can't second-
guess legitimate `DELETE`/`UPDATE` intent. What the plugin *can*
guarantee is that no config-side input reshapes an operator's
statement. Multi-statement bodies are rejected because they
defeat placeholder binding anyway; atomic multi-step work belongs
in a `kind: sql_tx` pipeline step.

**Privileged DDL is rejected at config parse.** Statements
leading with `GRANT`, `REVOKE`, or `CREATE|ALTER|DROP {USER,ROLE,
DATABASE,GROUP}` are refused — the SQL backend is for
application-scoped data access, not role/user/grant administration.
Operators who need those must configure them on a separately-scoped
admin backend gated behind `governance.minimum_trust = "verified"`
+ an allowlist CEL. Regular schema DDL (`CREATE TABLE`,
`ALTER TABLE`, `DROP INDEX`, …) still works. Leading comments
(`--`, `/* */`) are stripped before the check so hiding
`-- innocent\nGRANT …` doesn't bypass it.

## PostgreSQL change data capture (`postgres_cdc`)

The `postgres_cdc` watch strategy reads every change a publication carries
from a logical replication slot. It decodes the built-in `pgoutput` plugin
through the SQL slot functions (`pg_logical_slot_peek_binary_changes`), so it
needs no extension and no replication connection, and works on managed
PostgreSQL (RDS, Aurora, Cloud SQL, Azure, Supabase, Neon).

```yaml
mcp:
  capabilities:
    events:
      - name: orders.changed
        description: A row of the orders table was inserted, updated or deleted.
        source:
          watch:
            strategy:
              type: plugin
              kind: postgres_cdc
              url: "postgres://mcpg_cdc:${env.PG_CDC_PASSWORD}@db.internal/shop?sslmode=require"
              publication: mcpg_orders
              tables: [public.orders]
            event_type: sql.row.changed
```

| Field | Default | Notes |
|---|---|---|
| `url` | — | `postgres://`, with its password and `sslmode`; resolved before the watch starts and never logged. |
| `publication` | — | The publication whose tables are read. |
| `tables` | `[]` | Create the publication `FOR TABLE` these when it is missing; without them a missing publication is an error. |
| `slot` | derived from the source | The replication slot, created when missing. |
| `poll_interval_ms` | `1000` | How often the slot is read when it had nothing new (100 to 20000). |
| `max_in_flight`, `ack_timeout_ms` | `256`, `60000` | Changes out at a time, and how long one waits for the gateway before it is read again. |

Each insert, update or delete is a `sql.row.changed` event: `op`, `schema`,
`table`, `row` (the row after the change; for a delete the old key, or the
old row under `REPLICA IDENTITY FULL`), `old` (an update's old row, when the
replica identity sends it), `unchanged` (TOASTed columns the change did not
send), `lsn`, `xid` and `commitTime`. Integers, floats, booleans and
`json`/`jsonb` are JSON values; `numeric` and other types are PostgreSQL's
text. A `TRUNCATE` is `sql.table.truncated`.

Delivery is at-least-once, in commit order: the slot advances
(`pg_replication_slot_advance`) only once the gateway has stored every change
of a transaction and of every transaction before it, and a change it did not
take is read again under the same `slot/lsn` event id.

Requirements and care:

- `wal_level = logical` on the server, and a role with replication rights
  (`REPLICATION`, `rds_replication`, `cloudsqlsuperuser`, …) that may create
  the slot and, with `tables`, the publication.
- A slot keeps WAL on the server until it advances. Drop the slot of a
  source you remove (`SELECT pg_drop_replication_slot('…')`), and consider
  `max_slot_wal_keep_size` as a guard.
- A slot that is gone when the source restarts (dropped, or lost in a
  failover) is created again, and the event log records a gap: what changed
  in between is not known.

## Environment expectations

Integration tests look for the following (Linux only):

- `POSTGRES_TEST_URL` — e.g. `postgres://mcpg:mcpg@localhost/mcpg_test`
- `MYSQL_TEST_URL` — e.g. `mysql://mcpg:mcpg@127.0.0.1/mcpg_test`

Both are set by the `SQL / postgres` and `SQL / mysql` rows of
`.github/workflows/integration.yml`, which also set `MCPG_REQUIRE_DB=1` and
run postgres with `wal_level = logical`. Without the env vars a test skips
with a note, unless `MCPG_REQUIRE_DB` is set, which makes the skip a failure.
SQLite tests always run (in-memory). The `cdc_postgres` suite also needs
`wal_level = logical`, and skips on a server without it unless
`MCPG_REQUIRE_DB` is set:

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=mcpg postgres:16-alpine \
  postgres -c wal_level=logical
POSTGRES_TEST_URL=postgres://postgres:mcpg@127.0.0.1:5432/postgres \
  cargo test -p mcpg-plugin-backend-sql --test cdc_postgres
```

## Benches

Criterion benches cover the hot paths (`sql_backend_hot_paths`). They live in
the development tree and are not part of the published crate, so measure
against your own workload rather than a shipped baseline: bench numbers taken
on shared CI runners are too noisy to assert thresholds against.

## Build

```bash
cargo build -p mcpg-plugin-backend-sql --features cdylib-export --release   # → target/release/libmcpg_plugin_backend_sql.so
```

The default build enables all three drivers (`postgres`, `mysql`,
`sqlite`); cloud-DB auth schemes (`sql-rds-iam`, `sql-azure-ad`,
`sql-gcp-iam`, `sql-aurora-failover`) are opt-in Cargo features.

## Sign & load (production)

Sign the artifact, pin/verify via the entry's `signature:` block, and
honour revocations — see
[plugin security](https://mcpg.dev/docs/security/plugin-security).

## References

- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
- Operator reference: `apps/gateway/docs/backends.md` (SQL section)
- Operator cookbook: `apps/gateway/docs/sql/cookbook.md` — 26 worked recipes
- Migration guide: `apps/gateway/docs/sql/migration.md` — REST-wrapped DB → direct SQL backend
- Troubleshooting: `apps/gateway/docs/sql/troubleshooting.md` — failure modes + fixes
- Samples: `examples/26-sql-sqlite-todos`,
  `27-sql-dynamic-resource-listings`, `28-sql-pipeline-tx`,
  `29-sql-await-job`
- Trait surface: `libs/plugin-api/src/backend.rs`
- Sibling plugins: `libs/plugins/backends/nats`,
  `libs/plugins/backends/kafka`
