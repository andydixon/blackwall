#!/usr/bin/env python3
"""Generate PostgreSQL DDL for BlackWall from the live MariaDB information_schema.

Mapping rules (kept deliberately mechanical so the output is reviewable):

  bigint unsigned + auto_increment -> BIGSERIAL          (identity preserved via setval)
  bigint unsigned                  -> BIGINT             (PostgreSQL has no UNSIGNED)
  int unsigned                     -> BIGINT             (int4 cannot hold 4294967295)
  int                              -> INTEGER
  tinyint(1)                       -> BOOLEAN            (Go models these as bool)
  tinyint unsigned                 -> SMALLINT
  datetime                         -> TIMESTAMPTZ        (session TZ pinned to UTC)
  char/varchar with _ci collation  -> CITEXT + length CHECK   (preserves case-insensitive
                                                          comparison AND the length bound)
  char/varchar with _bin collation -> VARCHAR(n)
  text/longtext/mediumtext         -> TEXT
  enum(...)                        -> TEXT + CHECK IN (...)

MySQL's ON UPDATE CURRENT_TIMESTAMP has no PostgreSQL equivalent and is
reproduced with a shared trigger.
"""
import subprocess, collections, re, sys

DB = "blackwall"
MYSQL = ["mysql", "-h", "172.17.0.1", "-u", "blackwall", DB, "-N", "-B", "-e"]


def q(sql):
    out = subprocess.run(MYSQL + [sql], capture_output=True, text=True,
                         env={"MYSQL_PWD": "***REMOVED***", "PATH": "/usr/bin:/bin"})
    if out.returncode:
        sys.exit("mysql failed: " + out.stderr)
    return [line.split("\t") for line in out.stdout.strip("\n").split("\n") if line]


# ── columns ────────────────────────────────────────────────────────────────
cols = collections.OrderedDict()
for (t, c, dt, ct, nullable, default, extra, collation, maxlen) in q("""
    SELECT table_name, column_name, data_type, column_type, is_nullable,
           COALESCE(column_default,'__BW_NODEFAULT__'), extra, COALESCE(collation_name,''),
           COALESCE(character_maximum_length,0)
    FROM information_schema.columns WHERE table_schema='%s'
    ORDER BY table_name, ordinal_position""" % DB):
    cols.setdefault(t, []).append(dict(
        name=c, dt=dt, ct=ct, nullable=(nullable == "YES"),
        default=(None if default == '__BW_NODEFAULT__' else default),
        extra=extra, collation=collation, maxlen=int(maxlen)))

# ── keys ───────────────────────────────────────────────────────────────────
idx = collections.OrderedDict()
for (t, name, nonuniq, cols_csv, sub_csv) in q("""
    SELECT table_name, index_name, non_unique,
           GROUP_CONCAT(column_name ORDER BY seq_in_index),
           GROUP_CONCAT(COALESCE(sub_part,0) ORDER BY seq_in_index)
    FROM information_schema.statistics WHERE table_schema='%s'
    GROUP BY table_name, index_name, non_unique""" % DB):
    idx.setdefault(t, []).append(dict(
        name=name, unique=(nonuniq == "0"),
        cols=cols_csv.split(","), subs=[int(x) for x in sub_csv.split(",")]))

# ── foreign keys ───────────────────────────────────────────────────────────
fks = collections.OrderedDict()
for (t, name, cols_csv, rt, rcols_csv, upd, dele) in q("""
    SELECT k.table_name, k.constraint_name,
           GROUP_CONCAT(k.column_name ORDER BY k.ordinal_position),
           k.referenced_table_name,
           GROUP_CONCAT(k.referenced_column_name ORDER BY k.ordinal_position),
           r.update_rule, r.delete_rule
    FROM information_schema.key_column_usage k
    JOIN information_schema.referential_constraints r
      ON r.constraint_schema=k.table_schema AND r.constraint_name=k.constraint_name
    WHERE k.table_schema='%s' AND k.referenced_table_name IS NOT NULL
    GROUP BY k.table_name, k.constraint_name, k.referenced_table_name,
             r.update_rule, r.delete_rule""" % DB):
    fks.setdefault(t, []).append(dict(name=name, cols=cols_csv.split(","),
                                      rt=rt, rcols=rcols_csv.split(","),
                                      upd=upd, dele=dele))


def pg_type(col):
    dt, ct = col["dt"], col["ct"]
    unsigned = "unsigned" in ct
    if dt == "bigint":
        return "BIGSERIAL" if "auto_increment" in col["extra"] else "BIGINT"
    if dt == "int":
        if "auto_increment" in col["extra"]:
            return "BIGSERIAL"
        return "BIGINT" if unsigned else "INTEGER"
    if dt == "tinyint":
        return "BOOLEAN" if ct.startswith("tinyint(1)") and not unsigned else "SMALLINT"
    if dt == "smallint":
        return "INTEGER" if unsigned else "SMALLINT"
    if dt == "datetime" or dt == "timestamp":
        return "TIMESTAMPTZ"
    if dt == "date":
        return "DATE"
    if dt in ("text", "longtext", "mediumtext", "tinytext"):
        return "TEXT"
    if dt == "enum":
        return "TEXT"
    if dt in ("char", "varchar"):
        # utf8mb4_bin is a case-sensitive (binary) collation; everything else in
        # this schema is utf8mb4_unicode_ci, i.e. case-insensitive.
        return "VARCHAR(%d)" % col["maxlen"] if col["collation"].endswith("_bin") else "CITEXT"
    if dt in ("decimal", "numeric"):
        return ct.replace("decimal", "NUMERIC").upper()
    if dt in ("double", "float"):
        return "DOUBLE PRECISION"
    if dt in ("blob", "longblob", "mediumblob", "varbinary", "binary"):
        return "BYTEA"
    sys.exit("unmapped type: %s %s" % (dt, ct))


def pg_default(col, t):
    d = col["default"]
    if d is None:
        return ""
    dl = d.lower().strip()
    if "auto_increment" in col["extra"]:
        return ""
    if dl in ("current_timestamp()", "current_timestamp"):
        return " DEFAULT NOW()"
    if dl == "null":
        return ""
    if col["dt"] == "tinyint" and col["ct"].startswith("tinyint(1)"):
        return " DEFAULT " + ("TRUE" if d.strip("'") == "1" else "FALSE")
    if d.startswith("'") and d.endswith("'"):
        return " DEFAULT " + d
    if re.fullmatch(r"-?\d+(\.\d+)?", d):
        return " DEFAULT " + d
    return " DEFAULT '%s'" % d.strip("'")


out = []
w = out.append
w("-- BlackWall PostgreSQL schema — generated from the live MariaDB schema.")
w("-- Regenerate with tools/pgmigrate/gen_schema.py; do not hand-edit.")
w("")
w("CREATE EXTENSION IF NOT EXISTS citext;")
w("")
w("-- MySQL's JSON_EXTRACT returns NULL for text that is not valid JSON;")
w("-- a bare ::jsonb cast raises instead. This helper restores the lenient")
w("-- behaviour the application relies on.")
w("CREATE OR REPLACE FUNCTION bw_json_text(doc text, field text) RETURNS text AS $fn$")
w("BEGIN")
w("    RETURN (doc::jsonb) ->> field;")
w("EXCEPTION WHEN others THEN")
w("    RETURN NULL;")
w("END;")
w("$fn$ LANGUAGE plpgsql IMMUTABLE;")
w("")
w("-- Mirrors MySQL's json_valid() for the CHECK constraints below.")
w("CREATE OR REPLACE FUNCTION bw_is_json(doc text) RETURNS boolean AS $fn$")
w("BEGIN")
w("    PERFORM doc::jsonb;")
w("    RETURN TRUE;")
w("EXCEPTION WHEN others THEN")
w("    RETURN FALSE;")
w("END;")
w("$fn$ LANGUAGE plpgsql IMMUTABLE;")
w("")
w("-- Replaces MySQL's ON UPDATE CURRENT_TIMESTAMP column attribute.")
w("CREATE OR REPLACE FUNCTION bw_touch_updated_at() RETURNS trigger AS $fn$")
w("BEGIN")
w("    NEW.updated_at = NOW();")
w("    RETURN NEW;")
w("END;")
w("$fn$ LANGUAGE plpgsql;")
w("")

# Tables must be created before the FKs that reference them; emit all tables
# first, then constraints, so declaration order does not matter.
for t, cs in cols.items():
    w("CREATE TABLE %s (" % t)
    lines = []
    for c in cs:
        typ = pg_type(c)
        line = "    %s %s" % (c["name"], typ)
        if not c["nullable"]:
            line += " NOT NULL"
        line += pg_default(c, t)
        lines.append(line)
        # Preserve the length bound MySQL enforced, which CITEXT drops.
        if typ == "CITEXT" and c["maxlen"]:
            lines.append("    CHECK (length(%s) <= %d)" % (c["name"], c["maxlen"]))
        # Preserve enum membership.
        if c["dt"] == "enum":
            vals = re.findall(r"'((?:[^']|'')*)'", c["ct"])
            lines.append("    CHECK (%s IN (%s))" % (
                c["name"], ", ".join("'%s'" % v for v in vals)))
    w(",\n".join(lines))
    w(");")
    w("")

# ── primary keys, unique constraints, indexes ──────────────────────────────
for t, ixs in idx.items():
    for i in ixs:
        if i["name"] == "PRIMARY":
            w("ALTER TABLE %s ADD PRIMARY KEY (%s);" % (t, ", ".join(i["cols"])))
for t, ixs in idx.items():
    for i in ixs:
        if i["name"] != "PRIMARY" and i["unique"]:
            w("ALTER TABLE %s ADD CONSTRAINT uq_%s_%s UNIQUE (%s);" % (
                t, t, i["name"], ", ".join(i["cols"])))
w("")
for t, ixs in idx.items():
    for i in ixs:
        if i["name"] == "PRIMARY" or i["unique"]:
            continue
        parts = []
        for cname, sub in zip(i["cols"], i["subs"]):
            # MySQL prefix index -> expression index on the same prefix.
            parts.append("left(%s, %d)" % (cname, sub) if sub else cname)
        w("CREATE INDEX ix_%s_%s ON %s (%s);" % (t, i["name"], t, ", ".join(parts)))
w("")

# ── json_valid CHECKs (named separately so they read clearly) ──────────────
json_checks = [
    ("approval_requests", "payload_json", False),
    ("audit_log", "metadata_json", True),
    ("maintenance_job_runs", "stats_json", True),
    ("webauthn_credentials", "transports", True),
]
for t, c, nullable in json_checks:
    if t in cols and any(x["name"] == c for x in cols[t]):
        guard = "%s IS NULL OR " % c if nullable else ""
        w("ALTER TABLE %s ADD CONSTRAINT ck_%s_%s_json CHECK (%sbw_is_json(%s));" % (
            t, t, c, guard, c))
w("")

# ── foreign keys ───────────────────────────────────────────────────────────
for t, fl in fks.items():
    for f in fl:
        clause = "ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s)" % (
            t, f["name"], ", ".join(f["cols"]), f["rt"], ", ".join(f["rcols"]))
        if f["dele"] != "RESTRICT":
            clause += " ON DELETE " + f["dele"]
        if f["upd"] != "RESTRICT":
            clause += " ON UPDATE " + f["upd"]
        # Deferrable so the data migration can load tables in any order
        # (users <-> organizations is a genuine cycle) without superuser.
        clause += " DEFERRABLE INITIALLY IMMEDIATE"
        w(clause + ";")
w("")

# ── ON UPDATE CURRENT_TIMESTAMP triggers ───────────────────────────────────
for t, cs in cols.items():
    for c in cs:
        if "on update current_timestamp" in c["extra"].lower():
            w("CREATE TRIGGER tg_%s_updated_at BEFORE UPDATE ON %s" % (t, t))
            w("    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();")
w("")

print("\n".join(out))
