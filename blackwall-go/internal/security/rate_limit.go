package security

import (
	"database/sql"
	"math/rand"
	"time"

	"blackwall/internal/config"
)

type RateLimiter struct {
	db *sql.DB
}

func NewRateLimiter(db *sql.DB) *RateLimiter {
	return &RateLimiter{db: db}
}

// Check returns true if the request is allowed, false if rate limited.
func (rl *RateLimiter) Check(identifier, action string, maxAttempts, windowSeconds int) bool {
	if !config.Get().RateLimitEnabled {
		return true
	}

	now := time.Now().UTC()
	windowStart := now.Add(-time.Duration(windowSeconds) * time.Second)

	// Probabilistic cleanup (5%)
	if rand.Intn(100) < 5 {
		go rl.cleanup()
	}

	row := rl.db.QueryRow(
		`SELECT id, attempts, window_start, blocked_until FROM rate_limits WHERE identifier=? AND action=?`,
		identifier, action)

	var id int
	var attempts int
	var ws time.Time
	var blockedUntil sql.NullTime

	err := row.Scan(&id, &attempts, &ws, &blockedUntil)
	if err == sql.ErrNoRows {
		// First attempt — create record
		_, _ = rl.db.Exec(
			`INSERT INTO rate_limits (identifier, action, attempts, window_start) VALUES (?, ?, 1, ?)
			 ON DUPLICATE KEY UPDATE attempts=attempts+1`,
			identifier, action, now)
		return true
	}
	if err != nil {
		return true // allow on error
	}

	// Check if currently blocked
	if blockedUntil.Valid && now.Before(blockedUntil.Time) {
		return false
	}

	// If window expired, reset
	if ws.Before(windowStart) {
		_, _ = rl.db.Exec(
			`UPDATE rate_limits SET attempts=1, window_start=?, blocked_until=NULL WHERE id=?`,
			now, id)
		return true
	}

	// Increment and check
	attempts++
	if attempts > maxAttempts {
		blockUntil := now.Add(time.Duration(windowSeconds) * time.Second)
		_, _ = rl.db.Exec(
			`UPDATE rate_limits SET attempts=?, blocked_until=? WHERE id=?`,
			attempts, blockUntil, id)
		return false
	}

	_, _ = rl.db.Exec(`UPDATE rate_limits SET attempts=? WHERE id=?`, attempts, id)
	return true
}

func (rl *RateLimiter) cleanup() {
	_, _ = rl.db.Exec(`DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 24 HOUR) AND (blocked_until IS NULL OR blocked_until < NOW())`)
}
