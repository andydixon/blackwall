// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

// Command mysqlmigrate copies BlackWall's data from PostgreSQL back into
// MySQL, table by table. It is the reverse of the removed tools/pgmigrate.
//
// The destination schema must already exist (internal/db/schema.sql). Column
// lists come from MySQL's catalog, so every MySQL column must exist in
// PostgreSQL under the same name.
//
// The copy runs in one MySQL transaction with foreign key checks off for the
// session (users <-> organizations is a genuine cycle), so the whole copy
// lands or rolls back. Timestamps are truncated to whole seconds to match
// DATETIME, which rounds rather than truncates.
//
// Usage:
//
//	go run ./tools/mysqlmigrate \
//	  -pg    'postgres://blackwall:pass@172.17.0.1:5432/blackwall?sslmode=disable' \
//	  -mysql 'blackwall:pass@tcp(172.17.0.1:3306)/blackwall?parseTime=true&loc=UTC' \
//	  [-truncate] [-verify]
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

const batchSize = 200

func main() {
	pgDSN := flag.String("pg", "", "PostgreSQL connection URI")
	myDSN := flag.String("mysql", "", "MySQL DSN (parseTime=true&loc=UTC required)")
	truncate := flag.Bool("truncate", false, "empty destination tables before copying")
	verify := flag.Bool("verify", false, "compare per-table content hashes after copying and exit non-zero on mismatch")
	flag.Parse()

	if *myDSN == "" || *pgDSN == "" {
		flag.Usage()
		os.Exit(2)
	}
	if !strings.Contains(*myDSN, "parseTime=true") || !strings.Contains(*myDSN, "loc=UTC") {
		log.Fatal("mysql DSN must set parseTime=true&loc=UTC")
	}

	pg, err := sql.Open("pgx", *pgDSN)
	must(err, "open postgres")
	defer pg.Close()
	must(pg.Ping(), "ping postgres")
	_, err = pg.Exec("SET TIME ZONE 'UTC'")
	must(err, "set pg time zone")
	pg.SetMaxOpenConns(1) // keep the SET on the one connection

	my, err := sql.Open("mysql", *myDSN)
	must(err, "open mysql")
	defer my.Close()
	must(my.Ping(), "ping mysql")

	tables, err := listTables(my)
	must(err, "list tables")
	log.Printf("found %d destination tables", len(tables))

	tx, err := my.Begin()
	must(err, "begin")
	defer tx.Rollback()
	_, err = tx.Exec("SET FOREIGN_KEY_CHECKS=0")
	must(err, "disable foreign key checks")

	for _, t := range tables {
		cols, err := listColumns(my, t)
		must(err, "columns "+t)
		if *truncate {
			_, err := tx.Exec("DELETE FROM `" + t + "`")
			must(err, "truncate "+t)
		}
		n, err := copyTable(pg, tx, t, cols)
		if err != nil {
			log.Fatalf("copy %s: %v", t, err)
		}
		log.Printf("  %-34s %6d rows", t, n)
	}

	_, err = tx.Exec("SET FOREIGN_KEY_CHECKS=1")
	must(err, "enable foreign key checks")
	must(tx.Commit(), "commit")
	log.Print("committed")

	if *verify {
		bad := 0
		for _, t := range tables {
			cols, err := listColumns(my, t)
			must(err, "columns "+t)
			pn, ph, err := tableHash(pg, t, cols, `"`)
			must(err, "hash pg "+t)
			mn, mh, err := tableHash(my, t, cols, "`")
			must(err, "hash mysql "+t)
			status := "ok"
			if pn != mn || ph != mh {
				status = "MISMATCH"
				bad++
			}
			log.Printf("  verify %-34s pg=%d mysql=%d %s", t, pn, mn, status)
		}
		if bad > 0 {
			log.Fatalf("%d tables differ", bad)
		}
		log.Print("verify: every table matches row-for-row")
	}
}

func listTables(my *sql.DB) ([]string, error) {
	rows, err := my.Query(`SELECT table_name FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name`)
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
	return out, rows.Err()
}

func listColumns(my *sql.DB, table string) ([]string, error) {
	rows, err := my.Query(`SELECT column_name FROM information_schema.columns
		WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func copyTable(pg *sql.DB, tx *sql.Tx, table string, cols []string) (int, error) {
	rows, err := pg.Query(fmt.Sprintf(`SELECT %s FROM "%s"`, quoteAll(cols, `"`), table))
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	insert := fmt.Sprintf("INSERT INTO `%s` (%s) VALUES ", table, quoteAll(cols, "`"))
	tuple := "(" + strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",") + ")"

	var batch []interface{}
	n, pending := 0, 0
	flush := func() error {
		if pending == 0 {
			return nil
		}
		q := insert + strings.TrimSuffix(strings.Repeat(tuple+",", pending), ",")
		_, err := tx.Exec(q, batch...)
		batch, pending = batch[:0], 0
		return err
	}

	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		for i, v := range vals {
			if t, ok := v.(time.Time); ok {
				vals[i] = t.UTC().Truncate(time.Second)
			}
		}
		batch = append(batch, vals...)
		pending++
		n++
		if pending == batchSize {
			if err := flush(); err != nil {
				return n, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	return n, flush()
}

// tableHash renders every row as normalised text and hashes the sorted
// rows, so both databases compare equal regardless of how each driver types
// values or how each collation orders strings.
func tableHash(db *sql.DB, table string, cols []string, q string) (int, string, error) {
	rows, err := db.Query(fmt.Sprintf("SELECT %s FROM %s%s%s", quoteAll(cols, q), q, table, q))
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return 0, "", err
		}
		var b strings.Builder
		for _, v := range vals {
			b.WriteString(normalise(v))
			b.WriteByte('\x1f')
		}
		lines = append(lines, b.String())
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l + "\x1e"))
	}
	return len(lines), hex.EncodeToString(h.Sum(nil)), nil
}

func normalise(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "\x00NULL"
	case bool:
		if x {
			return "1"
		}
		return "0"
	case time.Time:
		return x.UTC().Truncate(time.Second).Format("2006-01-02 15:04:05")
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(x)
	}
}

func quoteAll(cols []string, q string) string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = q + c + q
	}
	return strings.Join(out, ", ")
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
