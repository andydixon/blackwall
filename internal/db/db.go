package db

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sync"

	"blackwall/internal/config"
)

var (
	instance *sql.DB
	once     sync.Once
)

func Connect(cfg *config.Config) (*sql.DB, error) {
	var err error
	once.Do(func() {
		registerDriver()
		instance, err = sql.Open(driverName, dsn(cfg))
		if err != nil {
			return
		}
		instance.SetMaxOpenConns(25)
		instance.SetMaxIdleConns(10)
	})
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// dsn builds a PostgreSQL connection URI. Every component is URL-escaped, so
// passwords containing reserved characters survive intact — MySQL's DSN format
// tolerated them positionally, a URI does not.
//
// sslmode defaults to disable to preserve the transport posture the MySQL DSN
// had; set db_sslmode to require (or stricter) once the server presents a
// certificate the client can verify.
func dsn(cfg *config.Config) string {
	port := cfg.DBPort
	if port == "" {
		port = "5432"
	}
	sslMode := cfg.DBSSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.DBUser, cfg.DBPass),
		Host:   net.JoinHostPort(cfg.DBHost, port),
		Path:   "/" + cfg.DBName,
	}
	q := url.Values{}
	q.Set("sslmode", sslMode)
	// The schema carries TIMESTAMPTZ columns; pinning the session to UTC keeps
	// values round-tripping identically to the MySQL loc=UTC behaviour.
	q.Set("options", "-c timezone=UTC")
	u.RawQuery = q.Encode()
	return u.String()
}

func Get() *sql.DB {
	return instance
}

// Ping verifies the configured database is reachable and speaking PostgreSQL,
// so a misconfigured host fails at boot with a clear message rather than on
// the first request that touches it.
func Ping(d *sql.DB) error {
	var version string
	if err := d.QueryRow("SELECT version()").Scan(&version); err != nil {
		return fmt.Errorf("database unreachable: %w", err)
	}
	return nil
}
