package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5/stdlib"
)

// BlackWall's SQL is written throughout with MySQL-style `?` placeholders,
// including the dynamically built `?,?,?` lists used for IN clauses. Rather
// than rewrite ~1,045 placeholders across 38 files by hand — every one of them
// an opportunity to mis-number a parameter — we translate at the driver layer,
// where the transformation is uniform and testable.
//
// The driver registered here wraps pgx's stdlib driver and rewrites each
// statement's placeholders into PostgreSQL's positional `$N` form immediately
// before it is prepared or executed.
const driverName = "pgx-qmark"

var registerOnce sync.Once

func registerDriver() {
	registerOnce.Do(func() {
		sql.Register(driverName, qmarkDriver{base: stdlib.GetDefaultDriver()})
	})
}

// rewritePlaceholders converts MySQL `?` placeholders into PostgreSQL `$N`
// placeholders, numbered left to right from 1.
//
// A `?` is only a placeholder when it appears in ordinary statement text, so
// the scanner tracks the lexical contexts in which one must be left alone:
// single-quoted literals (where a doubled quote is an embedded quote), double-quoted
// identifiers, dollar-quoted strings, line comments, and block comments —
// which nest in PostgreSQL, unlike C.
//
// The function is deliberately total: text it does not understand is copied
// through untouched rather than guessed at.
func rewritePlaceholders(query string) string {
	// Fast path: the overwhelming majority of statements contain a `?`, but
	// skipping the scan for those that don't keeps DDL and literal SQL exact.
	if !containsQuestion(query) {
		return query
	}

	var out []byte
	// Pre-size to the original plus room for the $N expansion.
	out = make([]byte, 0, len(query)+16)

	n := 0 // placeholder counter
	for i := 0; i < len(query); {
		c := query[i]
		switch {
		case c == '\'':
			// Single-quoted string literal. '' inside is a literal quote and
			// does not end the string.
			out = append(out, c)
			i++
			for i < len(query) {
				if query[i] == '\'' {
					if i+1 < len(query) && query[i+1] == '\'' {
						out = append(out, '\'', '\'')
						i += 2
						continue
					}
					out = append(out, '\'')
					i++
					break
				}
				out = append(out, query[i])
				i++
			}

		case c == '"':
			// Double-quoted identifier. "" inside is a literal quote.
			out = append(out, c)
			i++
			for i < len(query) {
				if query[i] == '"' {
					if i+1 < len(query) && query[i+1] == '"' {
						out = append(out, '"', '"')
						i += 2
						continue
					}
					out = append(out, '"')
					i++
					break
				}
				out = append(out, query[i])
				i++
			}

		case c == '-' && i+1 < len(query) && query[i+1] == '-':
			// Line comment, runs to end of line.
			for i < len(query) && query[i] != '\n' {
				out = append(out, query[i])
				i++
			}

		case c == '/' && i+1 < len(query) && query[i+1] == '*':
			// Block comment. PostgreSQL nests these, so track depth.
			depth := 0
			for i < len(query) {
				if query[i] == '/' && i+1 < len(query) && query[i+1] == '*' {
					depth++
					out = append(out, '/', '*')
					i += 2
					continue
				}
				if query[i] == '*' && i+1 < len(query) && query[i+1] == '/' {
					depth--
					out = append(out, '*', '/')
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				out = append(out, query[i])
				i++
			}

		case c == '$':
			// Dollar-quoted string: $tag$ ... $tag$. If this isn't a well
			// formed opening tag, fall through and copy the byte as-is.
			if tag, ok := dollarTag(query[i:]); ok {
				out = append(out, tag...)
				i += len(tag)
				if end := indexFrom(query, tag, i); end >= 0 {
					out = append(out, query[i:end+len(tag)]...)
					i = end + len(tag)
				} else {
					// Unterminated; copy the remainder verbatim.
					out = append(out, query[i:]...)
					i = len(query)
				}
			} else {
				out = append(out, c)
				i++
			}

		case c == '?':
			n++
			out = append(out, '$')
			out = strconv.AppendInt(out, int64(n), 10)
			i++

		default:
			out = append(out, c)
			i++
		}
	}
	return string(out)
}

func containsQuestion(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '?' {
			return true
		}
	}
	return false
}

// dollarTag returns the opening dollar-quote tag at the start of s (for
// example "$$" or "$body$") when one is present.
func dollarTag(s string) (string, bool) {
	if len(s) == 0 || s[0] != '$' {
		return "", false
	}
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if ch == '$' {
			return s[:i+1], true
		}
		isTagByte := ch == '_' ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(i > 1 && ch >= '0' && ch <= '9')
		if !isTagByte {
			return "", false
		}
	}
	return "", false
}

func indexFrom(s, sub string, from int) int {
	for i := from; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ── driver plumbing ─────────────────────────────────────────────────────────
//
// Everything below delegates to pgx and exists only to route statement text
// through rewritePlaceholders on its way to the server.

type qmarkDriver struct{ base driver.Driver }

func (d qmarkDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return qmarkConn{base: c}, nil
}

// OpenConnector lets database/sql reuse one connector rather than reparsing
// the DSN per connection, and is what pgx's own driver implements.
func (d qmarkDriver) OpenConnector(dsn string) (driver.Connector, error) {
	dc, ok := d.base.(driver.DriverContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	c, err := dc.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return qmarkConnector{base: c, drv: d}, nil
}

type qmarkConnector struct {
	base driver.Connector
	drv  qmarkDriver
}

func (c qmarkConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return qmarkConn{base: conn}, nil
}

func (c qmarkConnector) Driver() driver.Driver { return c.drv }

type qmarkConn struct{ base driver.Conn }

func (c qmarkConn) Prepare(query string) (driver.Stmt, error) {
	return c.base.Prepare(rewritePlaceholders(query))
}

func (c qmarkConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if p, ok := c.base.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, rewritePlaceholders(query))
	}
	return c.Prepare(query)
}

func (c qmarkConn) Close() error { return c.base.Close() }

func (c qmarkConn) Begin() (driver.Tx, error) { //nolint:staticcheck // required by driver.Conn
	return c.base.Begin() //nolint:staticcheck // delegating to pgx
}

func (c qmarkConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.base.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Begin() //nolint:staticcheck // fallback path
}

func (c qmarkConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := c.base.(driver.ExecerContext); ok {
		return e.ExecContext(ctx, rewritePlaceholders(query), args)
	}
	return nil, driver.ErrSkip
}

func (c qmarkConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if q, ok := c.base.(driver.QueryerContext); ok {
		return q.QueryContext(ctx, rewritePlaceholders(query), args)
	}
	return nil, driver.ErrSkip
}

func (c qmarkConn) Ping(ctx context.Context) error {
	if p, ok := c.base.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c qmarkConn) ResetSession(ctx context.Context) error {
	if r, ok := c.base.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c qmarkConn) IsValid() bool {
	if v, ok := c.base.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func (c qmarkConn) CheckNamedValue(v *driver.NamedValue) error {
	if ck, ok := c.base.(driver.NamedValueChecker); ok {
		return ck.CheckNamedValue(v)
	}
	return driver.ErrSkip
}
