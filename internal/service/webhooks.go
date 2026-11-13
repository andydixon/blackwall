package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// WebhookService manages per-project outbound webhook endpoints and the
// delivery pipeline that pushes audit / lifecycle events to them.
//
// Design notes:
//   - HMAC-SHA256 signatures with the endpoint's secret are sent as
//     `X-BlackWall-Signature: t=<ts>,v1=<hex>` (a stripe-style format). The
//     receiver recomputes HMAC(secret, ts + "." + body) to verify.
//   - Deliveries are persisted as `pending` and picked up by a background
//     dispatcher loop that retries on failure with exponential backoff. We
//     never block the originating request on the HTTP call.
//   - Endpoints with too many consecutive failures are auto-disabled to
//     stop hammering broken sinks.
type WebhookService struct {
	db *sql.DB
}

func NewWebhookService(db *sql.DB) *WebhookService {
	return &WebhookService{db: db}
}

// WebhookEndpoint is the admin-facing view of a registered receiver.
type WebhookEndpoint struct {
	ID                  int
	PublicID            string
	ProjectID           int
	TargetURL           string
	Secret              string
	Events              []string
	Status              string
	Description         string
	LastSuccessAt       sql.NullTime
	LastFailureAt       sql.NullTime
	ConsecutiveFailures int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// CreateEndpoint registers a new webhook receiver for the project. The secret
// is generated server-side and returned alongside the endpoint so the admin
// can copy it once at creation time — we do not surface the raw secret again
// (it lives in DB but the admin UI shows only a masked preview).
func (s *WebhookService) CreateEndpoint(projectID int, targetURL, description string, events []string) (*WebhookEndpoint, error) {
	if projectID <= 0 {
		return nil, errors.New("project_id required")
	}
	if err := validateWebhookTargetURL(targetURL); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		events = []string{"*"}
	}
	eventsJSON, _ := json.Marshal(events)
	publicID := uuid.NewString()
	secret := generateWebhookSecret()

	res, err := s.db.Exec(`INSERT INTO webhook_endpoints
		(project_id, public_id, target_url, secret, events_json, status, description)
		VALUES (?, ?, ?, ?, ?, 'active', ?)`,
		projectID, publicID, targetURL, secret, string(eventsJSON), description)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &WebhookEndpoint{
		ID:        int(id),
		PublicID:  publicID,
		ProjectID: projectID,
		TargetURL: targetURL,
		Secret:    secret,
		Events:    events,
		Status:    "active",
	}, nil
}

// UpdateEndpoint changes mutable fields of an endpoint. Rotates the secret
// when rotateSecret is true (returns the new secret in the result).
func (s *WebhookService) UpdateEndpoint(publicID, targetURL, description string, events []string, status string, rotateSecret bool) (*WebhookEndpoint, error) {
	if err := validateWebhookTargetURL(targetURL); err != nil {
		return nil, err
	}
	if status != "active" && status != "disabled" {
		return nil, errors.New("status must be active or disabled")
	}
	if len(events) == 0 {
		events = []string{"*"}
	}
	eventsJSON, _ := json.Marshal(events)
	newSecret := ""
	if rotateSecret {
		newSecret = generateWebhookSecret()
		if _, err := s.db.Exec(`UPDATE webhook_endpoints SET secret=? WHERE public_id=?`, newSecret, publicID); err != nil {
			return nil, err
		}
	}
	if _, err := s.db.Exec(`UPDATE webhook_endpoints SET target_url=?, description=?, events_json=?, status=?, consecutive_failures=IF(?='active',consecutive_failures,consecutive_failures) WHERE public_id=?`,
		targetURL, description, string(eventsJSON), status, status, publicID); err != nil {
		return nil, err
	}
	return s.GetEndpoint(publicID)
}

// DeleteEndpoint removes an endpoint and (via ON DELETE CASCADE) every
// queued / historic delivery row tied to it.
func (s *WebhookService) DeleteEndpoint(publicID string) error {
	_, err := s.db.Exec(`DELETE FROM webhook_endpoints WHERE public_id=?`, publicID)
	return err
}

// GetEndpoint returns a single endpoint by its public ID.
func (s *WebhookService) GetEndpoint(publicID string) (*WebhookEndpoint, error) {
	var e WebhookEndpoint
	var eventsJSON string
	err := s.db.QueryRow(`SELECT id, public_id, project_id, target_url, secret, events_json,
		status, COALESCE(description,''), last_success_at, last_failure_at,
		consecutive_failures, created_at, updated_at
		FROM webhook_endpoints WHERE public_id=?`, publicID).Scan(
		&e.ID, &e.PublicID, &e.ProjectID, &e.TargetURL, &e.Secret, &eventsJSON,
		&e.Status, &e.Description, &e.LastSuccessAt, &e.LastFailureAt,
		&e.ConsecutiveFailures, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(eventsJSON), &e.Events)
	return &e, nil
}

// ListForProject returns every webhook endpoint registered against the project,
// most-recently-modified first.
func (s *WebhookService) ListForProject(projectID int) ([]WebhookEndpoint, error) {
	rows, err := s.db.Query(`SELECT id, public_id, project_id, target_url, secret, events_json,
		status, COALESCE(description,''), last_success_at, last_failure_at,
		consecutive_failures, created_at, updated_at
		FROM webhook_endpoints WHERE project_id=? ORDER BY updated_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebhookEndpoint
	for rows.Next() {
		var e WebhookEndpoint
		var eventsJSON string
		if err := rows.Scan(&e.ID, &e.PublicID, &e.ProjectID, &e.TargetURL, &e.Secret, &eventsJSON,
			&e.Status, &e.Description, &e.LastSuccessAt, &e.LastFailureAt,
			&e.ConsecutiveFailures, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(eventsJSON), &e.Events)
		out = append(out, e)
	}
	return out, nil
}

// Enqueue creates one pending delivery row per matching endpoint for the
// given project + event. The dispatcher loop picks them up out-of-band.
//
// Best-effort: errors are logged but never bubbled to the originating request,
// because audit hooks must never block the user-visible flow on the network
// availability of an external sink.
func (s *WebhookService) Enqueue(projectID int, eventType string, payload map[string]interface{}) {
	if projectID <= 0 || eventType == "" {
		return
	}
	endpoints, err := s.matchingEndpoints(projectID, eventType)
	if err != nil || len(endpoints) == 0 {
		return
	}
	eventID := uuid.NewString()
	if payload == nil {
		payload = map[string]interface{}{}
	}
	envelope := map[string]interface{}{
		"id":          eventID,
		"type":        eventType,
		"project_id":  projectID,
		"occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
		"data":        payload,
		"api_version": "2024-11",
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		log.Printf("webhook enqueue marshal failed event=%s err=%v", eventType, err)
		return
	}
	for _, ep := range endpoints {
		if _, err := s.db.Exec(`INSERT INTO webhook_deliveries
			(endpoint_id, event_type, event_id, payload_json, status, next_attempt_at)
			VALUES (?, ?, ?, ?, 'pending', NOW())`,
			ep.ID, eventType, eventID, string(body)); err != nil {
			log.Printf("webhook enqueue insert failed endpoint=%d err=%v", ep.ID, err)
		}
	}
}

// matchingEndpoints returns active endpoints for the project whose events
// list either matches the event_type exactly or contains the wildcard "*".
func (s *WebhookService) matchingEndpoints(projectID int, eventType string) ([]WebhookEndpoint, error) {
	all, err := s.ListForProject(projectID)
	if err != nil {
		return nil, err
	}
	var out []WebhookEndpoint
	for _, e := range all {
		if e.Status != "active" {
			continue
		}
		for _, ev := range e.Events {
			if ev == "*" || ev == eventType {
				out = append(out, e)
				break
			}
		}
	}
	return out, nil
}

// DeliverPending pulls up to `batchSize` due deliveries from the queue,
// attempts each, and updates the row with success / next-retry state.
// Returns the number of rows it processed.
//
// Backoff schedule (seconds): 0, 30, 300, 1800, 21600 — fast initial retry,
// then slows down through hours. After attemptCap retries the row is marked
// `exhausted` and the endpoint is flagged for the admin to inspect.
func (s *WebhookService) DeliverPending(ctx context.Context, batchSize int) int {
	if batchSize <= 0 {
		batchSize = 32
	}
	rows, err := s.db.Query(`SELECT d.id, d.endpoint_id, d.event_type, d.event_id, d.payload_json,
		d.attempts, e.target_url, e.secret, e.status
		FROM webhook_deliveries d
		JOIN webhook_endpoints e ON e.id = d.endpoint_id
		WHERE d.status='pending' AND d.next_attempt_at <= NOW()
		ORDER BY d.next_attempt_at ASC
		LIMIT ?`, batchSize)
	if err != nil {
		log.Printf("webhook dispatcher query failed: %v", err)
		return 0
	}
	type job struct {
		id, endpointID, attempts                 int
		eventType, eventID, payload, url, secret string
		endpointStatus                           string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.endpointID, &j.eventType, &j.eventID, &j.payload,
			&j.attempts, &j.url, &j.secret, &j.endpointStatus); err == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	const attemptCap = 5
	backoff := []int{30, 300, 1800, 21600, 86400}

	processed := 0
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			return processed
		default:
		}
		// Skip if the endpoint was disabled between enqueue and dispatch —
		// mark the row as exhausted so it leaves the pending queue.
		if j.endpointStatus != "active" {
			s.db.Exec(`UPDATE webhook_deliveries SET status='exhausted', updated_at=NOW() WHERE id=?`, j.id)
			processed++
			continue
		}

		status, excerpt := s.send(ctx, j.url, j.secret, j.payload, j.eventType, j.eventID)
		j.attempts++

		if status >= 200 && status < 300 {
			s.db.Exec(`UPDATE webhook_deliveries SET status='succeeded', attempts=?, last_status_code=?, last_response_excerpt=?, updated_at=NOW() WHERE id=?`,
				j.attempts, status, excerpt, j.id)
			s.db.Exec(`UPDATE webhook_endpoints SET last_success_at=NOW(), consecutive_failures=0 WHERE id=?`, j.endpointID)
			processed++
			continue
		}

		// Failure path: schedule the next attempt or exhaust.
		if j.attempts >= attemptCap {
			s.db.Exec(`UPDATE webhook_deliveries SET status='exhausted', attempts=?, last_status_code=?, last_response_excerpt=?, updated_at=NOW() WHERE id=?`,
				j.attempts, status, excerpt, j.id)
		} else {
			delay := backoff[j.attempts-1]
			s.db.Exec(`UPDATE webhook_deliveries SET attempts=?, last_status_code=?, last_response_excerpt=?, next_attempt_at=DATE_ADD(NOW(), INTERVAL ? SECOND), updated_at=NOW() WHERE id=?`,
				j.attempts, status, excerpt, delay, j.id)
		}
		s.db.Exec(`UPDATE webhook_endpoints SET last_failure_at=NOW(), consecutive_failures=consecutive_failures+1 WHERE id=?`, j.endpointID)
		// Auto-disable after 20 consecutive failures so we stop hammering
		// dead sinks. The admin sees the endpoint as "disabled" with the
		// failure counter and can re-enable after fixing the receiver.
		s.db.Exec(`UPDATE webhook_endpoints SET status='disabled' WHERE id=? AND consecutive_failures>=20`, j.endpointID)
		processed++
	}
	return processed
}

// send performs one HTTP POST with HMAC signing. Returns the response status
// code (0 on transport error) and a short body excerpt for diagnostics.
func (s *WebhookService) send(ctx context.Context, targetURL, secret, body, eventType, eventID string) (int, string) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sigInput := ts + "." + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sigInput))
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBufferString(body))
	if err != nil {
		return 0, "build_request: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BlackWall-Webhook/1.0")
	req.Header.Set("X-BlackWall-Event", eventType)
	req.Header.Set("X-BlackWall-Event-Id", eventID)
	req.Header.Set("X-BlackWall-Signature", "t="+ts+",v1="+sig)

	client := newWebhookHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "transport_error: " + err.Error()
	}
	defer resp.Body.Close()
	const cap = 512
	buf := make([]byte, cap)
	n, _ := io.ReadFull(resp.Body, buf)
	excerpt := string(buf[:n])
	if n == cap {
		excerpt += "…"
	}
	return resp.StatusCode, excerpt
}

// VerifySignature is a helper a downstream receiver can use to verify the
// X-BlackWall-Signature header. Exposed so we can use it in tests; we don't
// ship a separate client library yet.
func VerifySignature(secret, body, header string, tolerance time.Duration) bool {
	if !strings.HasPrefix(header, "t=") {
		return false
	}
	parts := strings.Split(header, ",")
	var ts, sig string
	for _, p := range parts {
		if strings.HasPrefix(p, "t=") {
			ts = strings.TrimPrefix(p, "t=")
		} else if strings.HasPrefix(p, "v1=") {
			sig = strings.TrimPrefix(p, "v1=")
		}
	}
	if ts == "" || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + body))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return false
	}
	if tolerance > 0 {
		var sec int64
		fmt.Sscanf(ts, "%d", &sec)
		if abs(time.Now().Unix()-sec) > int64(tolerance.Seconds()) {
			return false
		}
	}
	return true
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func validateWebhookTargetURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("target_url must be an absolute http(s) URL")
	}
	if u.User != nil {
		return errors.New("target_url must not contain userinfo")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("target_url must not reference a local address")
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicWebhookIP(ip) {
		return errors.New("target_url must reference a public address")
	}
	return nil
}

func isHTTPURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.Hostname() != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func newWebhookHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid webhook address: %w", err)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve webhook host: %w", err)
			}
			if len(ips) == 0 {
				return nil, errors.New("webhook host resolved to no addresses")
			}
			for _, resolved := range ips {
				if !isPublicWebhookIP(resolved.IP) {
					return nil, fmt.Errorf("webhook host resolved to non-public address %s", resolved.IP)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func isPublicWebhookIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	blocked := []string{
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
	}
	for _, cidr := range blocked {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func generateWebhookSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + hex.EncodeToString(b)
}

// StartDispatcher runs the delivery loop on the supplied interval until the
// context is cancelled. Call from main once at boot.
func (s *WebhookService) StartDispatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.DeliverPending(ctx, 64)
			}
		}
	}()
}

// ListDeliveries returns recent delivery attempts for an endpoint, newest first.
func (s *WebhookService) ListDeliveries(endpointID int, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, event_type, event_id, status, attempts,
		COALESCE(last_status_code, 0), COALESCE(last_response_excerpt,''),
		next_attempt_at, created_at, updated_at
		FROM webhook_deliveries WHERE endpoint_id=? ORDER BY created_at DESC LIMIT ?`,
		endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, attempts, code int
		var eventType, eventID, status, excerpt string
		var nextAt, createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &eventType, &eventID, &status, &attempts, &code,
			&excerpt, &nextAt, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"id":               id,
			"event_type":       eventType,
			"event_id":         eventID,
			"status":           status,
			"attempts":         attempts,
			"last_status_code": code,
			"excerpt":          excerpt,
			"next_attempt_at":  nextAt.Format(time.RFC3339),
			"created_at":       createdAt.Format(time.RFC3339),
			"updated_at":       updatedAt.Format(time.RFC3339),
		})
	}
	return out, nil
}

// Requeue resets a delivery row so the dispatcher will retry immediately.
// Useful when an admin manually fixes a downstream receiver and wants to
// drain the pending queue.
func (s *WebhookService) Requeue(deliveryID int) error {
	_, err := s.db.Exec(`UPDATE webhook_deliveries
		SET status='pending', next_attempt_at=NOW(), updated_at=NOW()
		WHERE id=? AND status IN ('failed','exhausted')`, deliveryID)
	return err
}
