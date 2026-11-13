# PostgreSQL to MySQL migration

Blackwall ran on PostgreSQL from 2026-08-18 to 2026-11-13 and is back on
MySQL 8. The code change reverts the PostgreSQL port (`e7b8916`): the MySQL
driver, `?` placeholders, `LastInsertId()`, `ON DUPLICATE KEY UPDATE` and
`GET_LOCK` are back exactly as they were. Fixes made while on PostgreSQL were
kept and ported where they touched SQL:

- approval SLA latency uses `TIMESTAMPDIFF` again;
- migration 8 (the organisation branding columns migration 3 failed to add)
  adds one column per `ALTER`, so a duplicate column can only skip the column
  it names;
- the metrics, maintenance-page and maintenance-stats query fixes carry over
  unchanged, as they are plain SQL.

## Schema

The original MariaDB database no longer exists, so `internal/db/schema.sql`
was rebuilt by inverting the PostgreSQL baseline's type mapping:

| PostgreSQL | MySQL |
| --- | --- |
| `BIGSERIAL` / `BIGINT` | `BIGINT UNSIGNED` (`AUTO_INCREMENT` for serials) |
| `CITEXT` + `CHECK (length <= n)` | `VARCHAR(n)`, `utf8mb4_unicode_ci` |
| `TEXT` + `CHECK (x IN (...))` | `ENUM(...)` |
| `TEXT` | `LONGTEXT` (the original size is not recoverable; this is the superset) |
| `BOOLEAN` | `TINYINT(1)` |
| `TIMESTAMPTZ` | `DATETIME` |
| `bw_touch_updated_at` trigger | `ON UPDATE CURRENT_TIMESTAMP` |
| `bw_is_json` check | `json_valid` check |

One key could not be carried over as-is: `saml_service_providers`'s unique
`(project_id, entity_id)` exceeds MySQL's 3072-byte index limit (MariaDB hashed
it). It covers the first 760 characters of `entity_id`. Migration 4 has the
same key and would fail on MySQL 8, but it is recorded as applied by
`schema.sql` and never runs.

The resulting 330 columns across 34 tables match the live PostgreSQL catalog
name for name.

## Data

`tools/mysqlmigrate` copies every table in one MySQL transaction with foreign
key checks off, then `-verify` compares a hash of every table's normalised,
sorted rows on both sides. Timestamps are truncated to whole seconds (MySQL
`DATETIME` would otherwise round); `created_at` is not part of the audit hash
chain, so the chain is unaffected.

```bash
cd tools/mysqlmigrate
go run . \
  -pg    'postgres://blackwall:PASS@172.17.0.1:5432/blackwall?sslmode=disable' \
  -mysql 'blackwall:PASS@tcp(172.17.0.1:3306)/blackwall?parseTime=true&loc=UTC' \
  -truncate -verify
```

Run it from a container on the default bridge: the MySQL account is
`blackwall@172.16.0.0/255.240.0.0`, and a connection from the host itself
reverse-resolves to the host name and is refused.

## Rollback

The PostgreSQL `blackwall` database is left untouched. To roll back, redeploy
the PostgreSQL image (`feat/admin-subdomain-proxy`) and restore
`/opt/blackwall/config.yaml.pre-mysql.*`. Any write made in MySQL after the
cutover is lost.

## Pre-existing defects fixed while on PostgreSQL

Statement validation during the PostgreSQL port found three queries that had
been failing under MariaDB too; the fixes carry over:

- **Metrics reported zero active tokens** — `metrics.go` queried a nonexistent
  `oauth_tokens` table. It now reads `oauth_access_tokens` and reports
  `oauth_refresh_tokens_active` alongside.
- **The maintenance page read nonexistent columns** — it now reads
  `stats_json` and `error_trace`, and `MaintenanceService.runJob` persists the
  per-job counts it previously discarded.
- **Organisation branding was broken** — migration 3's multi-column `ALTER`
  failed on the already-present `logo_url` and the error was swallowed;
  migration 8 adds the three missing columns.
