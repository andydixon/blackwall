package service

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AdminTokenService manages bearer tokens for the JSON admin API and SCIM 2.0
// endpoints. Tokens are bound to a specific user and inherit that user's
// admin capabilities at request time — there is no token-scoped capability
// escalation, which keeps the threat model symmetrical with the cookie path.
//
// Plaintext is shown EXACTLY ONCE at creation. After that, we store only
// the SHA-256 hash plus a 12-char prefix that the UI uses for identification
// ("bw_admin_a3f9…"). Lost a token? Issue a new one.
type AdminTokenService struct {
	db *sql.DB
}

func NewAdminTokenService(db *sql.DB) *AdminTokenService {
	return &AdminTokenService{db: db}
}

// AdminToken is the metadata row (no plaintext).
type AdminToken struct {
	ID         int
	PublicID   string
	Prefix     string
	UserID     int
	Name       string
	Scopes     []string
	CreatedAt  time.Time
	LastUsedAt sql.NullTime
	ExpiresAt  sql.NullTime
	RevokedAt  sql.NullTime
}

func (t *AdminToken) IsActive() bool {
	if t.RevokedAt.Valid {
		return false
	}
	if t.ExpiresAt.Valid && t.ExpiresAt.Time.Before(time.Now()) {
		return false
	}
	return true
}

// Create mints a fresh token. The PLAINTEXT is in `token` of the returned
// pair — surface it once to the admin, then forget it. Scopes default to
// ["admin:full"] which gives the holder every capability the user has;
// callers can supply a narrower list (e.g. ["scim:read"]) to constrain.
func (s *AdminTokenService) Create(userID int, name string, scopes []string, expires *time.Time) (*AdminToken, string, error) {
	if userID <= 0 {
		return nil, "", errors.New("user_id required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", errors.New("name required")
	}
	if len(scopes) == 0 {
		scopes = []string{"admin:full"}
	}

	// Token format: bw_admin_<32 random base64url chars>. The prefix lets
	// the UI list tokens identifiably; the random suffix is what carries
	// the entropy.
	raw, err := newTokenRaw()
	if err != nil {
		return nil, "", err
	}
	full := "bw_admin_" + raw
	prefix := full[:12]
	sum := sha256.Sum256([]byte(full))
	hash := hex.EncodeToString(sum[:])
	pubID := uuid.NewString()
	scopesJSON, _ := json.Marshal(scopes)

	var expiresVal interface{}
	if expires != nil {
		expiresVal = expires.UTC()
	}

	res, err := s.db.Exec(`INSERT INTO admin_api_tokens
		(public_id, prefix, token_hash, user_id, name, scopes_json, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		pubID, prefix, hash, userID, name, string(scopesJSON), expiresVal)
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	tok := &AdminToken{
		ID: int(id), PublicID: pubID, Prefix: prefix, UserID: userID, Name: name, Scopes: scopes,
		CreatedAt: time.Now(),
	}
	if expires != nil {
		tok.ExpiresAt = sql.NullTime{Time: *expires, Valid: true}
	}
	return tok, full, nil
}

// Lookup validates the supplied bearer token plaintext and returns the
// metadata row if active. Returns (nil, sql.ErrNoRows) for "no such token";
// returns (nil, errors.New("revoked")) / ("expired") for inactive tokens so
// the caller can audit-log the right reason.
func (s *AdminTokenService) Lookup(plaintext string) (*AdminToken, error) {
	plaintext = strings.TrimSpace(plaintext)
	if !strings.HasPrefix(plaintext, "bw_admin_") {
		return nil, sql.ErrNoRows
	}
	sum := sha256.Sum256([]byte(plaintext))
	hash := hex.EncodeToString(sum[:])

	var t AdminToken
	var scopesJSON string
	err := s.db.QueryRow(`SELECT id, public_id, prefix, user_id, name, scopes_json,
		created_at, last_used_at, expires_at, revoked_at
		FROM admin_api_tokens WHERE token_hash=?`, hash).Scan(
		&t.ID, &t.PublicID, &t.Prefix, &t.UserID, &t.Name, &scopesJSON,
		&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(scopesJSON), &t.Scopes)
	if t.RevokedAt.Valid {
		return &t, errors.New("revoked")
	}
	if t.ExpiresAt.Valid && t.ExpiresAt.Time.Before(time.Now()) {
		return &t, errors.New("expired")
	}
	// Best-effort touch of last_used_at — async so the auth path stays fast.
	go func(id int) {
		_, _ = s.db.Exec(`UPDATE admin_api_tokens SET last_used_at=NOW() WHERE id=?`, id)
	}(t.ID)
	return &t, nil
}

// Revoke marks a token as no longer usable.
func (s *AdminTokenService) Revoke(publicID string) error {
	_, err := s.db.Exec(`UPDATE admin_api_tokens SET revoked_at=NOW() WHERE public_id=? AND revoked_at IS NULL`, publicID)
	return err
}

// ListForUser returns all tokens owned by the user (active + historical),
// newest first.
func (s *AdminTokenService) ListForUser(userID int) ([]AdminToken, error) {
	rows, err := s.db.Query(`SELECT id, public_id, prefix, user_id, name, scopes_json,
		created_at, last_used_at, expires_at, revoked_at
		FROM admin_api_tokens WHERE user_id=? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminToken
	for rows.Next() {
		var t AdminToken
		var scopesJSON string
		if err := rows.Scan(&t.ID, &t.PublicID, &t.Prefix, &t.UserID, &t.Name, &scopesJSON,
			&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(scopesJSON), &t.Scopes)
		out = append(out, t)
	}
	return out, nil
}

func newTokenRaw() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
