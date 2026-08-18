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

Create the database and load the schema. Load it **as the application role**,
not as a superuser: whoever runs the DDL owns the tables, and only the owner
can `ALTER` them. Loading the schema as `postgres` leaves the application
unable to apply its own future migrations — it fails at boot with
`must be owner of table` and, because the container runs with `--rm`, the
error disappears with it.

```bash
createdb -O blackwall blackwall
psql -d blackwall -c 'CREATE EXTENSION IF NOT EXISTS citext;'   # needs superuser
PGPASSWORD=... psql -h HOST -U blackwall -d blackwall -f internal/db/schema.sql
```

If the schema was already loaded as the wrong role, transfer ownership:

```sql
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname='public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO blackwall', r.tablename);
  END LOOP;
  FOR r IN SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema='public' LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO blackwall', r.sequence_name);
  END LOOP;
  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p
           JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO blackwall', r.sig);
  END LOOP;
END $$;
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

## Pre-existing defects found and fixed

Statement validation surfaced three queries referencing objects that did not
exist in the MariaDB schema either, so they had been failing at runtime long
before this migration. They were fixed in a follow-up commit:

**Metrics reported zero active tokens.** `internal/handler/metrics.go` queried
a table `oauth_tokens` that has never existed; the scan error was discarded, so
`oauth_tokens_active` silently reported 0 forever. It now reads
`oauth_access_tokens`, with `oauth_refresh_tokens_active` added alongside —
summing two different kinds of token into one gauge would not be meaningful.

**The maintenance page read two columns that do not exist.**
`maintenance_job_runs` has `stats_json` and `error_trace`, not `rows_affected`
and `error_message`. The page now reads the real columns. The underlying
problem was one level deeper: `MaintenanceService.runJob` computed each job's
counts and then discarded them, never writing `stats_json` at all, so there was
nothing to display even with a correct query. It now persists them, and the
"rows affected" figure is the sum of the job's counters.

**Organisation branding was broken by a swallowed migration error.** Migration 3
added `logo_url`, `primary_color`, `login_message` and `support_email` in a
single multi-column `ALTER`. `logo_url` already existed in the base schema, so
MySQL rejected the whole statement as a duplicate column — and the handler
treated "duplicate column" as "already applied" and carried on, recording the
migration as complete while three columns were never added. Migration 8 restores
them.

That failure mode cannot recur here: PostgreSQL applies
`ADD COLUMN IF NOT EXISTS` per column, so a partially-applicable `ALTER` no
longer depends on error-swallowing to be idempotent.
