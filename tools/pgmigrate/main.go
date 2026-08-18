// Command pgmigrate copies BlackWall's data from the legacy MariaDB/MySQL
// database into the PostgreSQL database, table by table.
//
// It is type-aware in both directions: it reads the destination column types
// from PostgreSQL's catalog and coerces each MySQL value to match, which is
// what makes tinyint(1) -> BOOLEAN and datetime -> TIMESTAMPTZ safe. A CSV
// round-trip would not survive the JSON and free-text columns.
//
// The copy runs inside one transaction with all foreign keys deferred to
// COMMIT, so insert ordering does not matter and the whole migration either
// lands intact or rolls back.
//
// Usage:
//
//	go run ./tools/pgmigrate \
//	  -mysql 'blackwall:pass@tcp(172.17.0.1:3306)/blackwall?parseTime=true&loc=UTC' \
//	  -pg    'postgres://blackwall:pass@172.17.0.1:5432/blackwall?sslmode=disable' \
//	  [-truncate] [-verify]
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	myDSN := flag.String("mysql", "", "MySQL DSN (parseTime=true&loc=UTC required)")
	pgDSN := flag.String("pg", "", "PostgreSQL connection URI")
	truncate := flag.Bool("truncate", false, "empty destination tables before copying")
	verify := flag.Bool("verify", false, "compare row counts after copying and exit non-zero on mismatch")
	flag.Parse()

	if *myDSN == "" || *pgDSN == "" {
		flag.Usage()
		os.Exit(2)
	}
	if !strings.Contains(*myDSN, "parseTime=true") {
		log.Fatal("mysql DSN must set parseTime=true so DATETIME arrives as time.Time")
	}

	my, err := sql.Open("mysql", *myDSN)
	must(err, "open mysql")
	defer my.Close()
	must(my.Ping(), "ping mysql")

	pg, err := sql.Open("pgx", *pgDSN)
	must(err, "open postgres")
	defer pg.Close()
	must(pg.Ping(), "ping postgres")

	tables, err := listTables(my)
	must(err, "list tables")
	log.Printf("found %d source tables", len(tables))

	tx, err := pg.Begin()
	must(err, "begin")
	defer tx.Rollback()

	// Defer foreign keys for the load so table order is irrelevant —
	// users <-> organizations is a genuine cycle. The constraints are still
	// checked, just at COMMIT, so a bad copy aborts the whole migration.
	if _, err := tx.Exec("SET CONSTRAINTS ALL DEFERRED"); err != nil {
		log.Fatalf("defer constraints: %v", err)
	}

	if *truncate {
		for _, t := range tables {
			if _, err := tx.Exec(fmtTruncate(t)); err != nil {
				log.Fatalf("truncate %s: %v", t, err)
			}
		}
	}

	total := 0
	for _, t := range tables {
		n, err := copyTable(my, tx, t)
		if err != nil {
			log.Fatalf("copy %s: %v", t, err)
		}
		total += n
		log.Printf("  %-34s %6d rows", t, n)
	}

	must(resetSequences(tx, tables), "reset sequences")
	must(tx.Commit(), "commit")
	log.Printf("copied %d rows across %d tables", total, len(tables))

	if *verify {
		bad := 0
		for _, t := range tables {
			var a, b int
			if err := my.QueryRow("SELECT COUNT(*) FROM `" + t + "`").Scan(&a); err != nil {
				log.Fatalf("count mysql %s: %v", t, err)
			}
			if err := pg.QueryRow(`SELECT COUNT(*) FROM "` + t + `"`).Scan(&b); err != nil {
				log.Fatalf("count postgres %s: %v", t, err)
			}
			if a != b {
				log.Printf("MISMATCH %-30s mysql=%d postgres=%d", t, a, b)
				bad++
			}
		}
		if bad > 0 {
			log.Fatalf("%d table(s) differ", bad)
		}
		log.Print("verify: all row counts match")
	}
}

func fmtTruncate(t string) string { return `TRUNCATE TABLE "` + t + `" CASCADE` }

func listTables(my *sql.DB) ([]string, error) {
	rows, err := my.Query(`SELECT table_name FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_type='BASE TABLE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	sort.Strings(out)
	return out, rows.Err()
}

// pgColumnTypes maps column name to PostgreSQL data type for one table.
func pgColumnTypes(tx *sql.Tx, table string) (map[string]string, error) {
	rows, err := tx.Query(`SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema='public' AND table_name=$1`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var c, d string
		if err := rows.Scan(&c, &d); err != nil {
			return nil, err
		}
		out[c] = d
	}
	return out, rows.Err()
}

func copyTable(my *sql.DB, tx *sql.Tx, table string) (int, error) {
	types, err := pgColumnTypes(tx, table)
	if err != nil {
		return 0, err
	}
	if len(types) == 0 {
		return 0, fmt.Errorf("destination table %q does not exist", table)
	}

	rows, err := my.Query("SELECT * FROM `" + table + "`")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	// Only copy columns the destination actually has, so a source column that
	// was dropped in the PostgreSQL schema is a visible skip rather than a
	// silent failure.
	var keep []int
	var names []string
	for i, c := range cols {
		if _, ok := types[c]; ok {
			keep = append(keep, i)
			names = append(names, c)
		} else {
			log.Printf("  note: %s.%s has no destination column, skipping", table, c)
		}
	}

	ph := make([]string, len(names))
	quoted := make([]string, len(names))
	for i, n := range names {
		ph[i] = fmt.Sprintf("$%d", i+1)
		quoted[i] = `"` + n + `"`
	}
	insert := fmt.Sprintf(`INSERT INTO %q (%s) VALUES (%s)`,
		table, strings.Join(quoted, ", "), strings.Join(ph, ", "))

	stmt, err := tx.Prepare(insert)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for rows.Next() {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		args := make([]any, len(keep))
		for j, srcIdx := range keep {
			args[j] = coerce(raw[srcIdx], types[names[j]])
		}
		if _, err := stmt.Exec(args...); err != nil {
			return n, fmt.Errorf("row %d: %w", n+1, err)
		}
		n++
	}
	return n, rows.Err()
}

// coerce converts a value as delivered by the MySQL driver into something the
// PostgreSQL driver will accept for the destination column type. The MySQL
// driver hands back []byte for every string-ish column and int64 for tinyint,
// neither of which PostgreSQL accepts for TEXT/BOOLEAN respectively.
func coerce(v any, pgType string) any {
	if v == nil {
		return nil
	}
	switch strings.ToLower(pgType) {
	case "boolean":
		switch t := v.(type) {
		case int64:
			return t != 0
		case []byte:
			return len(t) > 0 && t[0] != '0'
		case bool:
			return t
		}
	case "timestamp with time zone", "timestamp without time zone", "date":
		if t, ok := v.(time.Time); ok {
			// MySQL DATETIME is wall-clock with no zone; the source DSN reads
			// it as UTC, which is how the application always wrote it.
			return t.UTC()
		}
	}
	// Everything else: render byte slices as text, leave the rest alone.
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

// resetSequences advances each BIGSERIAL sequence past the highest id copied,
// so the first insert after the migration does not collide with existing rows.
func resetSequences(tx *sql.Tx, tables []string) error {
	rows, err := tx.Query(`
		SELECT c.relname, a.attname, pg_get_serial_sequence(c.relname, a.attname)
		FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname='public' AND c.relkind='r'
		  AND pg_get_serial_sequence(c.relname, a.attname) IS NOT NULL`)
	if err != nil {
		return err
	}
	type seq struct{ table, col, name string }
	var seqs []seq
	for rows.Next() {
		var s seq
		if err := rows.Scan(&s.table, &s.col, &s.name); err != nil {
			rows.Close()
			return err
		}
		seqs = append(seqs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range seqs {
		// is_called=false with COALESCE(max,0)+1 leaves an empty table's
		// sequence handing out 1 rather than 2.
		q := fmt.Sprintf(
			`SELECT setval('%s', COALESCE((SELECT MAX(%q) FROM %q), 0) + 1, false)`,
			s.name, s.col, s.table)
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("setval %s: %w", s.name, err)
		}
	}
	log.Printf("reset %d sequences", len(seqs))
	return nil
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
