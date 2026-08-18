# MySQL to PostgreSQL migration

Blackwall moved from MariaDB/MySQL to PostgreSQL. This is a hard swap: the
MySQL driver is gone from `go.mod` and there is no configuration switch to go
back. This document records how the migration was performed, what changed
behaviourally, and how to roll back.

## What changed in the code

| Area | MySQL | PostgreSQL |
| --- | --- | --- |
| Driver | `go-sql-driver/mysql` | `jackc/pgx/v5` via a wrapper driver |
| Placeholders | `?` | `$N`, rewritten in the driver (`internal/db/pgcompat.go`) |
| Generated ids | `LastInsertId()` | `RETURNING id` at every insert site |
| Upserts | `ON DUPLICATE KEY UPDATE` | `ON CONFLICT (...) DO UPDATE` |
| `INSERT IGNORE` | — | `ON CONFLICT ... DO NOTHING` |
| Date maths | `DATE_ADD` / `DATE_SUB` | `NOW() ± INTERVAL` |
| Conditional counts | `SUM(predicate)` | `COUNT(*) FILTER (WHERE predicate)` |
| Conditionals | `IF(a, b, c)` | `CASE WHEN a THEN b ELSE c END` |
| Multi-table update | `UPDATE t JOIN u SET ...` | subquery in `WHERE ... IN` |
| Chain lock | `GET_LOCK` / `RELEASE_LOCK` | `pg_advisory_xact_lock` |
| JSON access | `JSON_UNQUOTE(JSON_EXTRACT(...))` | `bw_json_text(...)` helper |

The `?` placeholders are deliberately *not* rewritten in the source. A wrapping
`database/sql` driver translates them per statement, which keeps ~1,045
placeholders — including the dynamically built `?,?,?` IN-clause lists —
correct by construction rather than by hand. It is unit-tested in
`internal/db/pgcompat_test.go`.

## Behavioural notes

- **Case sensitivity is preserved.** The MariaDB schema used
  `utf8mb4_unicode_ci` throughout, so text comparison was case-insensitive.
  Bounded `CHAR`/`VARCHAR` columns are therefore `CITEXT` in PostgreSQL, which
  keeps both equality and `LIKE` case-insensitive and keeps unique constraints
  colliding the way they used to. A case-sensitive ICU collation was rejected
  because PostgreSQL cannot run `LIKE` against a non-deterministic collation.
- **Length limits are preserved.** `CITEXT` has no length parameter, so each
  converted column carries a `CHECK (length(col) <= n)`.
- **`tinyint(1)` became `BOOLEAN`**, matching the Go models, so SQL literals
  are now `TRUE`/`FALSE` rather than `1`/`0`.
- **`DATETIME` became `TIMESTAMPTZ`** with the session pinned to UTC, which is
  how the application always wrote timestamps.
- **`ON UPDATE CURRENT_TIMESTAMP`** has no PostgreSQL equivalent and is
  reproduced by the `bw_touch_updated_at` trigger.
- **MySQL's lenient casts are reproduced, not inherited.** `CAST(x AS UNSIGNED)`
  yielded `0` for non-numeric text and `JSON_EXTRACT` yielded `NULL` for
  non-JSON; PostgreSQL raises in both cases. Guarded equivalents keep the old
  behaviour — this matters because 39 live `audit_log` rows hold a
  non-numeric `target_id`.

## Running the migration

The schema is generated from a live MySQL database:

```bash
python3 tools/pgmigrate/gen_schema.py > internal/db/schema.sql
```

Create the database and load the schema:

```bash
createdb -O blackwall blackwall
psql -d blackwall -c 'CREATE EXTENSION IF NOT EXISTS citext;'
psql -d blackwall -f internal/db/schema.sql
```

Copy the data. The tool is type-aware in both directions, runs in a single
transaction with foreign keys deferred, and resets every sequence afterwards:

```bash
cd tools/pgmigrate
go run . \
  -mysql 'blackwall:PASS@tcp(HOST:3306)/blackwall?parseTime=true&loc=UTC' \
  -pg    'postgres://blackwall:PASS@HOST:5432/blackwall?sslmode=disable' \
  -truncate -verify
```

`-verify` compares row counts per table and exits non-zero on any mismatch.

## Verification

Two checks are worth repeating after any re-run:

1. **Audit chain continuity.** The SHA-256 chain must still link across the
   migration boundary — the first row written under PostgreSQL should carry the
   last MySQL row's `chain_hash` as its `chain_prev_hash`.
2. **Statement validity.** Every SQL literal in the tree can be checked with
   `PREPARE` against a populated database, which catches missing columns and
   unported syntax without executing anything.

## Rollback

The MariaDB database is left untouched by the migration — it is read-only
throughout. To roll back, redeploy the last pre-migration image and point it at
MariaDB again.

The cost of rolling back is any write that landed in PostgreSQL after cutover:
those rows exist only in PostgreSQL and are not replicated back. Sessions,
tokens, and audit entries created after the switch would be lost. Roll back
promptly or not at all.

## Known pre-existing defects (not introduced by this migration)

Statement validation surfaced three queries that reference objects which do not
exist in the MariaDB schema either, so they were already failing at runtime:

- `internal/handler/metrics.go` queries a table `oauth_tokens` that does not
  exist (the real tables are `oauth_access_tokens` / `oauth_refresh_tokens`).
- `internal/handler/admin.go` selects `rows_affected` from
  `maintenance_job_runs`, which has no such column.
- `internal/service/branding.go` reads and writes `primary_color`,
  `login_message`, and `support_email` on `organizations`; migration 3 was
  recorded as applied but those three columns are absent, so per-organisation
  branding is broken.

These were left as-is so the migration reproduces current behaviour exactly.
They should be fixed separately.
