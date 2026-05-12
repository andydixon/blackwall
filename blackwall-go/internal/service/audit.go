package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"blackwall/internal/config"
)

type AuditLogger struct {
	db            *sql.DB
	correlationID string
	ipAddress     string
	userAgent     string
}

func NewAuditLogger(db *sql.DB) *AuditLogger {
	return &AuditLogger{db: db}
}

func (a *AuditLogger) WithContext(correlationID, ipAddress, userAgent string) *AuditLogger {
	return &AuditLogger{
		db:            a.db,
		correlationID: correlationID,
		ipAddress:     ipAddress,
		userAgent:     userAgent,
	}
}

type AuditMeta map[string]interface{}

func (a *AuditLogger) LogSuccess(eventType string, meta AuditMeta) {
	a.log(eventType, "success", meta)
}

func (a *AuditLogger) LogFail(eventType string, meta AuditMeta) {
	a.log(eventType, "fail", meta)
}

func (a *AuditLogger) LogInfo(eventType string, meta ...AuditMeta) {
	var m AuditMeta
	if len(meta) > 0 {
		m = meta[0]
	}
	a.log(eventType, "info", m)
}

func (a *AuditLogger) log(eventType, outcome string, meta AuditMeta) {
	if meta == nil {
		meta = AuditMeta{}
	}

	// Extract known fields from meta
	extract := func(key string) interface{} {
		v := meta[key]
		delete(meta, key)
		return v
	}

	message, _ := extract("message").(string)
	actorUserID := sqlNullInt64(extract("actor_user_id"))
	actorUserUUID := sqlNullString(extract("actor_user_uuid"))
	projectID := sqlNullInt64(extract("project_id"))
	projectUUID := sqlNullString(extract("project_uuid"))
	orgID := sqlNullInt64(extract("organization_id"))
	orgUUID := sqlNullString(extract("organization_uuid"))
	clientID := sqlNullInt64(extract("oauth_client_id"))
	clientPublicID := sqlNullString(extract("oauth_client_public_id"))
	credID := sqlNullInt64(extract("webauthn_credential_id"))
	credPublicID := sqlNullString(extract("webauthn_credential_public_id"))
	targetType := sqlNullString(extract("target_type"))
	targetID := sqlNullInt64(extract("target_id"))

	// Auto-lookup actor_user_uuid if we have actor_user_id but no uuid
	if actorUserID.Valid && !actorUserUUID.Valid {
		var uuid string
		if err := a.db.QueryRow(`SELECT uuid FROM users WHERE id=?`, actorUserID.Int64).Scan(&uuid); err == nil {
			actorUserUUID = sql.NullString{String: uuid, Valid: true}
		}
	}

	// Auto-lookup org from project if not provided
	if projectID.Valid && !orgID.Valid {
		var oid int64
		var ouuid string
		if err := a.db.QueryRow(`SELECT organization_id, (SELECT uuid FROM organizations WHERE id=organization_id) FROM projects WHERE id=?`, projectID.Int64).Scan(&oid, &ouuid); err == nil {
			orgID = sql.NullInt64{Int64: oid, Valid: true}
			orgUUID = sql.NullString{String: ouuid, Valid: true}
		}
	}

	// Remaining meta as JSON — encoded with HTML escaping disabled to match
	// PHP's json_encode(JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) so the
	// chain payload hashes to the same bytes across implementations.
	var metaJSON sql.NullString
	if len(meta) > 0 {
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(meta); err == nil {
			s := strings.TrimRight(buf.String(), "\n")
			metaJSON = sql.NullString{String: s, Valid: true}
		}
	}

	correlationID := sqlNullStringVal(a.correlationID)
	ipAddress := a.ipAddress
	if ipAddress == "" {
		ipAddress = "0.0.0.0"
	}
	userAgent := sqlNullStringVal(a.userAgent)

	// Audit chain writes must be atomic: read prev_hash + compute + insert
	// under a serialised transaction. Without the lock, two concurrent log
	// calls can both see the same prev_hash and corrupt the chain.
	tx, err := a.db.Begin()
	if err != nil {
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var lockAcquired int
	if err := tx.QueryRow(`SELECT COALESCE(GET_LOCK(?, 2), 0)`, "blackwall:audit_chain").Scan(&lockAcquired); err != nil || lockAcquired != 1 {
		return
	}
	defer func() { _, _ = a.db.Exec(`SELECT RELEASE_LOCK(?)`, "blackwall:audit_chain") }()

	var prevHash sql.NullString
	_ = tx.QueryRow(`SELECT chain_hash FROM audit_log WHERE chain_hash IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&prevHash)

	// Build the canonical chain payload. Field order and JSON encoding must
	// match the PHP implementation byte-for-byte or chain validation fails.
	payload := chainPayload{
		EventType:                  eventType,
		Outcome:                    outcome,
		Message:                    nullableString(message),
		CorrelationID:              nullableString(a.correlationID),
		IPAddress:                  ipAddress,
		UserAgent:                  nullableStringFromNS(userAgent),
		ActorUserID:                nullableInt64(actorUserID),
		ActorUserUUID:              nullableStringFromNS(actorUserUUID),
		ProjectID:                  nullableInt64(projectID),
		ProjectUUID:                nullableStringFromNS(projectUUID),
		OrganizationID:             nullableInt64(orgID),
		OrganizationUUID:           nullableStringFromNS(orgUUID),
		OAuthClientID:              nullableInt64(clientID),
		OAuthClientPublicID:        nullableStringFromNS(clientPublicID),
		WebAuthnCredentialID:       nullableInt64(credID),
		WebAuthnCredentialPublicID: nullableStringFromNS(credPublicID),
		TargetType:                 nullableStringFromNS(targetType),
		TargetID:                   nullableInt64(targetID),
		MetadataJSON:               nullableStringFromNS(metaJSON),
	}

	payloadBuf := &bytes.Buffer{}
	enc := json.NewEncoder(payloadBuf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return
	}
	payloadJSON := strings.TrimRight(payloadBuf.String(), "\n")

	prevHashStr := ""
	if prevHash.Valid {
		prevHashStr = prevHash.String
	}
	chainSum := sha256.Sum256([]byte(prevHashStr + "|" + payloadJSON))
	chainHash := hex.EncodeToString(chainSum[:])

	chainPrev := sql.NullString{}
	if prevHash.Valid {
		chainPrev = prevHash
	}

	if _, err := tx.Exec(`INSERT INTO audit_log
		(created_at, event_type, outcome, message, correlation_id, ip_address, user_agent,
		actor_user_id, actor_user_uuid, project_id, project_uuid, organization_id, organization_uuid,
		oauth_client_id, oauth_client_public_id, webauthn_credential_id, webauthn_credential_public_id,
		target_type, target_id, metadata_json, chain_prev_hash, chain_hash)
		VALUES (NOW(),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		eventType, outcome, sqlNullStringVal(message), correlationID, ipAddress, userAgent,
		actorUserID, actorUserUUID, projectID, projectUUID, orgID, orgUUID,
		clientID, clientPublicID, credID, credPublicID,
		targetType, targetID, metaJSON, chainPrev, chainHash,
	); err != nil {
		return
	}

	if err := tx.Commit(); err != nil {
		return
	}
	committed = true

	// Optional metric push happens after the chain write commits.
	cfg := config.Get()
	if cfg.EventMetricsPushEnabled && cfg.EventMetricsPushURL != "" {
		go pushMetric(cfg, eventType, outcome)
	}
}

// chainPayload mirrors the PHP `$chainPayload` array layout used to feed the
// SHA-256 chain hash. Field order MUST match the PHP source array order so
// the produced JSON byte sequences are identical.
type chainPayload struct {
	EventType                  string  `json:"event_type"`
	Outcome                    string  `json:"outcome"`
	Message                    *string `json:"message"`
	CorrelationID              *string `json:"correlation_id"`
	IPAddress                  string  `json:"ip_address"`
	UserAgent                  *string `json:"user_agent"`
	ActorUserID                *int64  `json:"actor_user_id"`
	ActorUserUUID              *string `json:"actor_user_uuid"`
	ProjectID                  *int64  `json:"project_id"`
	ProjectUUID                *string `json:"project_uuid"`
	OrganizationID             *int64  `json:"organization_id"`
	OrganizationUUID           *string `json:"organization_uuid"`
	OAuthClientID              *int64  `json:"oauth_client_id"`
	OAuthClientPublicID        *string `json:"oauth_client_public_id"`
	WebAuthnCredentialID       *int64  `json:"webauthn_credential_id"`
	WebAuthnCredentialPublicID *string `json:"webauthn_credential_public_id"`
	TargetType                 *string `json:"target_type"`
	TargetID                   *int64  `json:"target_id"`
	MetadataJSON               *string `json:"metadata_json"`
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func nullableStringFromNS(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}

func nullableInt64(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	v := ni.Int64
	return &v
}

func pushMetric(cfg *config.Config, eventType, outcome string) {
	labels := fmt.Sprintf(`event_type="%s"`, eventType)
	if cfg.EventMetricsPushIncludeOutcome {
		labels += fmt.Sprintf(`,outcome="%s"`, outcome)
	}
	if cfg.EventMetricsPushStaticLabels != "" {
		labels += "," + cfg.EventMetricsPushStaticLabels
	}
	line := fmt.Sprintf("%s{%s} 1\n", cfg.EventMetricsPushMetricName, labels)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.EventMetricsPushTimeoutMs)*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EventMetricsPushURL, bytes.NewBufferString(line))
	req.Header.Set("Content-Type", "text/plain")
	http.DefaultClient.Do(req) //nolint:errcheck
}

func sqlNullInt64(v interface{}) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	switch n := v.(type) {
	case int:
		return sql.NullInt64{Int64: int64(n), Valid: true}
	case int64:
		return sql.NullInt64{Int64: n, Valid: true}
	case float64:
		return sql.NullInt64{Int64: int64(n), Valid: true}
	}
	return sql.NullInt64{}
}

func sqlNullString(v interface{}) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	if s, ok := v.(string); ok && s != "" {
		return sql.NullString{String: s, Valid: true}
	}
	return sql.NullString{}
}

func sqlNullStringVal(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ResolvePrivilegeLabel returns a human-readable privilege label.
func ResolvePrivilegeLabel(level int, name string) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("Level %d", level)
}

// FormatAuditQuery builds a searchable audit query result set.
func QueryAuditLog(db *sql.DB, filters map[string]string, page, perPage int) ([]map[string]interface{}, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}

	if v := filters["event_type"]; v != "" {
		where += " AND event_type LIKE ?"
		args = append(args, "%"+v+"%")
	}
	if v := filters["outcome"]; v != "" {
		where += " AND outcome=?"
		args = append(args, v)
	}
	if v := filters["ip"]; v != "" {
		where += " AND ip_address LIKE ?"
		args = append(args, "%"+v+"%")
	}
	if v := filters["actor"]; v != "" {
		where += " AND (actor_user_uuid LIKE ? OR actor_user_id=?)"
		args = append(args, "%"+v+"%", v)
	}
	if v := filters["project_uuid"]; v != "" {
		where += " AND project_uuid=?"
		args = append(args, v)
	}
	if v := filters["correlation_id"]; v != "" {
		where += " AND correlation_id=?"
		args = append(args, v)
	}

	var total int
	countQ := "SELECT COUNT(*) FROM audit_log " + where
	if err := db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if page < 1 {
		page = 1
	}
	offset := (page - 1) * perPage
	query := "SELECT id, event_type, outcome, message, correlation_id, ip_address, actor_user_uuid, project_uuid, metadata_json, created_at FROM audit_log " +
		where + " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, perPage, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var eventType, outcome string
		var message, correlationID, ipAddress, actorUUID, projectUUID, metaJSON sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&id, &eventType, &outcome, &message, &correlationID, &ipAddress, &actorUUID, &projectUUID, &metaJSON, &createdAt); err != nil {
			return nil, 0, err
		}
		row := map[string]interface{}{
			"id":             id,
			"event_type":     eventType,
			"outcome":        outcome,
			"message":        message.String,
			"correlation_id": correlationID.String,
			"ip_address":     ipAddress.String,
			"actor_uuid":     actorUUID.String,
			"project_uuid":   projectUUID.String,
			"metadata":       metaJSON.String,
			"created_at":     createdAt.Format(time.RFC3339),
		}
		results = append(results, row)
	}
	return results, total, nil
}

// ExportAuditCSV exports audit log to CSV format.
func ExportAuditCSV(db *sql.DB, filters map[string]string) (string, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	for _, f := range []string{"event_type", "outcome"} {
		if v := filters[f]; v != "" {
			where += " AND " + f + "=?"
			args = append(args, v)
		}
	}

	rows, err := db.Query("SELECT id, event_type, outcome, message, correlation_id, ip_address, actor_user_uuid, project_uuid, metadata_json, created_at FROM audit_log "+where+" ORDER BY id DESC LIMIT 10000", args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	sb.WriteString("id,event_type,outcome,message,correlation_id,ip_address,actor_uuid,project_uuid,metadata,created_at\n")
	for rows.Next() {
		var id int64
		var eventType, outcome string
		var message, corrID, ip, actorUUID, projectUUID, meta sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&id, &eventType, &outcome, &message, &corrID, &ip, &actorUUID, &projectUUID, &meta, &createdAt); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			id, csvEscape(eventType), csvEscape(outcome), csvEscape(message.String),
			csvEscape(corrID.String), csvEscape(ip.String), csvEscape(actorUUID.String),
			csvEscape(projectUUID.String), csvEscape(meta.String), createdAt.Format(time.RFC3339)))
	}
	return sb.String(), nil
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
