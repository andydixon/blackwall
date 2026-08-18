package security

import (
	"database/sql"
	"math/rand"
	"sync/atomic"
	"time"

	"blackwall/internal/config"
)

type RateLimiter struct {
	db             *sql.DB
	cleanupRunning atomic.Bool
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
	if rand.Intn(100) < 5 && rl.cleanupRunning.CompareAndSwap(false, true) {
		go func() {
			defer rl.cleanupRunning.Store(false)
			rl.cleanup()
		}()
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
		_, err = rl.db.Exec(
			`INSERT INTO rate_limits (identifier, action, attempts, window_start) VALUES (?, ?, 1, ?)
			 ON CONFLICT (identifier, action) DO UPDATE SET attempts=rate_limits.attempts+1`,
			identifier, action, now)
		return err == nil
	}
	if err != nil {
		return false
	}

	// Check if currently blocked
	if blockedUntil.Valid && now.Before(blockedUntil.Time) {
		return false
	}

	// If window expired, reset
	if ws.Before(windowStart) {
		_, err = rl.db.Exec(
			`UPDATE rate_limits SET attempts=1, window_start=?, blocked_until=NULL WHERE id=?`,
			now, id)
		return err == nil
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

	_, err = rl.db.Exec(`UPDATE rate_limits SET attempts=? WHERE id=?`, attempts, id)
	return err == nil
}

func (rl *RateLimiter) cleanup() {
	_, _ = rl.db.Exec(`DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL '24 hour' AND (blocked_until IS NULL OR blocked_until < NOW())`)
}
