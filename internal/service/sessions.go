package service

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

// SessionStore manages the server-side row that accompanies each cookie-based
// session. The actual session payload still lives in the gorilla cookie store
// (encrypted, opaque to the server unless re-decoded) — this layer adds:
//
//   - a stable session_id placed in the cookie so the server can identify the
//     row this request belongs to,
//   - server-controlled revocation (admin or user-driven "log this out"),
//   - "max N concurrent sessions per user" enforcement at login time, and
//   - an active-session list any user can review from their portal.
//
// Sessions whose row has been revoked or expired are rejected even if the
// cookie still decrypts successfully. This is what closes the gap that an
// encrypted cookie alone leaves: with no DB row, a stolen cookie remained
// valid until the cookie's MaxAge elapsed.
type SessionStore struct {
	db *sql.DB
}

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// SessionRecord mirrors one user_sessions row.
type SessionRecord struct {
	ID            int
	SessionID     string
	UserID        int
	Scope         string
	IPAddress     sql.NullString
	UserAgent     sql.NullString
	CreatedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     time.Time
	RevokedAt     sql.NullTime
	RevokedReason sql.NullString
}

// IsActive reports whether the record represents a live session that should
// be honoured by the auth middleware.
func (r *SessionRecord) IsActive() bool {
	if r.RevokedAt.Valid {
		return false
	}
	return r.ExpiresAt.After(time.Now())
}

// Create records a new session for the user. Returns the random session_id
// the caller should embed in the cookie. The scope ("admin" or "portal")
// segments the session list view per surface.
//
// If maxConcurrent > 0 and the user already has that many active sessions in
// this scope, the OLDEST sessions are revoked first to bring the count back
// under the cap. This matches Okta/Auth0 behaviour ("kick the oldest device
// out when a new login exceeds the cap").
func (s *SessionStore) Create(userID int, scope, ip, ua string, lifetime time.Duration, maxConcurrent int) (*SessionRecord, error) {
	if userID <= 0 {
		return nil, errors.New("user_id required")
	}
	if scope != "admin" && scope != "portal" {
		return nil, errors.New("scope must be admin or portal")
	}
	if lifetime <= 0 {
		lifetime = 12 * time.Hour
	}

	if maxConcurrent > 0 {
		if err := s.enforceCap(userID, scope, maxConcurrent-1); err != nil {
			return nil, err
		}
	}

	sid, err := newSessionID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expires := now.Add(lifetime)
	var id int64
	err = s.db.QueryRow(`INSERT INTO user_sessions
		(session_id, user_id, scope, ip_address, user_agent, created_at, last_seen_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		sid, userID, scope, nullable(ip), nullable(ua), now, now, expires).Scan(&id)
	if err != nil {
		return nil, err
	}
	return &SessionRecord{
		ID: int(id), SessionID: sid, UserID: userID, Scope: scope,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: expires,
	}, nil
}

// enforceCap revokes the oldest non-revoked sessions for user/scope until
// no more than `maxActive` remain. Called from Create before the new row is
// inserted so the post-insert count lands at exactly maxConcurrent.
func (s *SessionStore) enforceCap(userID int, scope string, maxActive int) error {
	if maxActive < 0 {
		maxActive = 0
	}
	// Two-statement pattern to avoid MySQL's "can't reference target table
	// in subquery" restriction on UPDATE … WHERE id IN (SELECT … FROM same).
	rows, err := s.db.Query(`SELECT id FROM user_sessions
		WHERE user_id=? AND scope=? AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at ASC`, userID, scope)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	excess := len(ids) - maxActive
	for i := 0; i < excess; i++ {
		_, _ = s.db.Exec(`UPDATE user_sessions
			SET revoked_at=NOW(), revoked_reason='concurrent_cap'
			WHERE id=?`, ids[i])
	}
	return nil
}

// Lookup returns the session row matching session_id, regardless of revoked
// state — callers check IsActive() to decide whether to honour it.
func (s *SessionStore) Lookup(sessionID string) (*SessionRecord, error) {
	if sessionID == "" {
		return nil, sql.ErrNoRows
	}
	var r SessionRecord
	err := s.db.QueryRow(`SELECT id, session_id, user_id, scope, ip_address, user_agent,
		created_at, last_seen_at, expires_at, revoked_at, revoked_reason
		FROM user_sessions WHERE session_id=?`, sessionID).Scan(
		&r.ID, &r.SessionID, &r.UserID, &r.Scope, &r.IPAddress, &r.UserAgent,
		&r.CreatedAt, &r.LastSeenAt, &r.ExpiresAt, &r.RevokedAt, &r.RevokedReason)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Touch bumps last_seen_at to NOW. Cheap, used on every authenticated request
// so the user-facing "last activity" column is fresh.
func (s *SessionStore) Touch(sessionID string) {
	_, _ = s.db.Exec(`UPDATE user_sessions SET last_seen_at=NOW() WHERE session_id=? AND revoked_at IS NULL`, sessionID)
}

// Revoke marks a single session as invalid. Reason is recorded for the audit
// trail and surfaced in the user-portal "your active sessions" UI.
func (s *SessionStore) Revoke(sessionID, reason string) error {
	if sessionID == "" {
		return errors.New("session_id required")
	}
	_, err := s.db.Exec(`UPDATE user_sessions
		SET revoked_at=NOW(), revoked_reason=? WHERE session_id=? AND revoked_at IS NULL`,
		safeReason(reason), sessionID)
	return err
}

// RevokeAllForUser invalidates every session for a user. Used when an admin
// disables a user, when the user themselves clicks "sign out everywhere," or
// when a high-impact change (e.g. credential delete) forces a re-auth.
func (s *SessionStore) RevokeAllForUser(userID int, reason string) error {
	_, err := s.db.Exec(`UPDATE user_sessions
		SET revoked_at=NOW(), revoked_reason=?
		WHERE user_id=? AND revoked_at IS NULL`, safeReason(reason), userID)
	return err
}

// ListActiveForUser returns every non-revoked, non-expired session for the user.
func (s *SessionStore) ListActiveForUser(userID int) ([]SessionRecord, error) {
	rows, err := s.db.Query(`SELECT id, session_id, user_id, scope, ip_address, user_agent,
		created_at, last_seen_at, expires_at, revoked_at, revoked_reason
		FROM user_sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRecord
	for rows.Next() {
		var r SessionRecord
		if err := rows.Scan(&r.ID, &r.SessionID, &r.UserID, &r.Scope, &r.IPAddress, &r.UserAgent,
			&r.CreatedAt, &r.LastSeenAt, &r.ExpiresAt, &r.RevokedAt, &r.RevokedReason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// CleanupExpired removes session rows older than the retention window. Called
// from the maintenance job loop so the table doesn't grow unbounded.
func (s *SessionStore) CleanupExpired() (int64, error) {
	r, err := s.db.Exec(`DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '7 day' OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '7 day')`)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, nil
}

func newSessionID() (string, error) {
	// 32 random bytes → 43-char base64url. Fits the CHAR(43) column exactly.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func safeReason(reason string) string {
	if len(reason) > 100 {
		return reason[:100]
	}
	if reason == "" {
		return "manual"
	}
	return reason
}
