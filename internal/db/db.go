package db

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/go-sql-driver/mysql"

	"blackwall/internal/config"
)

var (
	instance *sql.DB
	once     sync.Once
)

func Connect(cfg *config.Config) (*sql.DB, error) {
	var err error
	once.Do(func() {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC",
			cfg.DBUser, cfg.DBPass, cfg.DBHost, cfg.DBPort, cfg.DBName)
		instance, err = sql.Open("mysql", dsn)
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

func Get() *sql.DB {
	return instance
}
