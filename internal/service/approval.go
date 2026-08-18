package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ApprovalRequest is the database row for an admin mutation pending review.
type ApprovalRequest struct {
	ID                      int64
	ActionType              string
	Status                  string
	PayloadJSON             string
	RequestedByUserID       int
	RequestedByUUID         string
	RequestedByDisplayLabel string
	ApprovedByUserID        sql.NullInt64
	ApprovedByUUID          sql.NullString
	ApprovedByDisplayLabel  sql.NullString
	ProjectID               sql.NullInt64
	ProjectUUID             sql.NullString
	ProjectName             sql.NullString
	DecisionNote            sql.NullString
	DecidedAt               sql.NullTime
	CreatedAt               time.Time
	LatestDenialReason      sql.NullString
}

// Payload returns the parsed payload_json as a map.
func (r ApprovalRequest) Payload() map[string]interface{} {
	if r.PayloadJSON == "" {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(r.PayloadJSON), &out); err != nil {
		return nil
	}
	return out
}

// ApprovalSummary holds today/week/month counts per status used by the dashboard.
type ApprovalSummary struct {
	Pending   PeriodCounts
	Approved  PeriodCounts
	Rejected  PeriodCounts
	Cancelled PeriodCounts
}

// ApprovalSLA captures pending-age and decision-latency metrics for the dashboard.
type ApprovalSLA struct {
	DecisionCount              int
	MedianSeconds              int
	P95Seconds                 int
	PendingOlderThanThreshold  int
	PendingWarningDays         int
	OldestPendingCreatedAt     sql.NullTime
}

// PeriodCounts is the standard today/week/month rollup shape.
type PeriodCounts struct {
	Today int
	Week  int
	Month int
}

// ApprovalFilters narrows search results.
type ApprovalFilters struct {
	Status           string
	ActionType       string
	RequestedByUUID  string
	ProjectUUID      string
	FailureReason    string
	DateFrom         string
	DateTo           string
}

type ApprovalService struct {
	db *sql.DB
}

func NewApprovalService(db *sql.DB) *ApprovalService {
	return &ApprovalService{db: db}
}

// Create enqueues a new pending approval request and returns its primary key.
func (s *ApprovalService) Create(actionType string, payload map[string]interface{}, requestedByUserID int, projectID *int) (int64, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var pid sql.NullInt64
	if projectID != nil {
		pid = sql.NullInt64{Int64: int64(*projectID), Valid: true}
	}
	var id int64
	err = s.db.QueryRow(
		`INSERT INTO approval_requests (action_type, status, payload_json, requested_by_user_id, project_id)
		 VALUES (?, 'pending', ?, ?, ?) RETURNING id`,
		actionType, string(payloadJSON), requestedByUserID, pid,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// GetByID returns a single approval request or nil if it doesn't exist.
func (s *ApprovalService) GetByID(id int64) (*ApprovalRequest, error) {
	rows, err := s.queryWithJoins(`WHERE ar.id=?`, []interface{}{id}, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// SearchVisibleToUser returns approvals scoped to what the user can see.
//   - includeAll: if true (super-admin / decide_approvals capability) shows everything matching the filters.
//   - visibleProjectIDs: if includeAll is false, limits to requests this user filed OR
//     requests targeting a project the user can scope.
func (s *ApprovalService) SearchVisibleToUser(userID int, includeAll bool, filters ApprovalFilters, limit, offset int, visibleProjectIDs []int) ([]ApprovalRequest, error) {
	conds, args := s.buildVisibilityConditions("ar", userID, includeAll, visibleProjectIDs)
	conds, args = applyApprovalFilters(conds, args, filters, includeAll, "ar")
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	return s.queryWithJoins(where, args, limit, offset)
}

// CountVisibleToUser returns the total matching count for paging.
func (s *ApprovalService) CountVisibleToUser(userID int, includeAll bool, filters ApprovalFilters, visibleProjectIDs []int) (int, error) {
	conds, args := s.buildVisibilityConditions("ar", userID, includeAll, visibleProjectIDs)
	conds, args = applyApprovalFilters(conds, args, filters, includeAll, "ar")
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	q := `SELECT COUNT(*)
	      FROM approval_requests ar
	      JOIN users req ON req.id = ar.requested_by_user_id
	      LEFT JOIN projects p ON p.id = ar.project_id
	      ` + where
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListPendingByRequester returns the user's own outstanding requests.
func (s *ApprovalService) ListPendingByRequester(requestedByUserID int, limit int) ([]ApprovalRequest, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.queryWithJoins(`WHERE ar.requested_by_user_id=? AND ar.status='pending'`,
		[]interface{}{requestedByUserID}, limit, 0)
}

// SummariseVisibleToUser returns per-status today/week/month counts.
func (s *ApprovalService) SummariseVisibleToUser(userID int, includeAll bool, visibleProjectIDs []int) (ApprovalSummary, error) {
	conds, args := s.buildVisibilityConditions("", userID, includeAll, visibleProjectIDs)
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	q := `SELECT status,
	             COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)                            AS today_count,
	             COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 day')      AS week_count,
	             COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 day')     AS month_count
	      FROM approval_requests ` + where + `
	      GROUP BY status`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return ApprovalSummary{}, err
	}
	defer rows.Close()

	summary := ApprovalSummary{}
	for rows.Next() {
		var status string
		var today, week, month sql.NullInt64
		if err := rows.Scan(&status, &today, &week, &month); err != nil {
			return summary, err
		}
		counts := PeriodCounts{Today: int(today.Int64), Week: int(week.Int64), Month: int(month.Int64)}
		switch status {
		case "pending":
			summary.Pending = counts
		case "approved":
			summary.Approved = counts
		case "rejected":
			summary.Rejected = counts
		case "cancelled":
			summary.Cancelled = counts
		}
	}
	return summary, nil
}

// SummariseSlaVisibleToUser returns latency percentiles + pending-age stats.
func (s *ApprovalService) SummariseSlaVisibleToUser(userID int, includeAll bool, visibleProjectIDs []int, pendingWarningDays int) (ApprovalSLA, error) {
	if pendingWarningDays < 1 {
		pendingWarningDays = 3
	}

	baseConds, baseArgs := s.buildVisibilityConditions("", userID, includeAll, visibleProjectIDs)

	pendingConds := append([]string{}, baseConds...)
	pendingConds = append(pendingConds, "status='pending'")
	pendingWhere := "WHERE " + strings.Join(pendingConds, " AND ")
	pendingQ := `SELECT
	               COUNT(*) FILTER (WHERE created_at < NOW() - (? * INTERVAL '1 day')) AS old_count,
	               MIN(created_at) AS oldest_pending
	             FROM approval_requests ` + pendingWhere
	pendingArgs := append([]interface{}{pendingWarningDays}, baseArgs...)

	var oldCount sql.NullInt64
	var oldest sql.NullTime
	if err := s.db.QueryRow(pendingQ, pendingArgs...).Scan(&oldCount, &oldest); err != nil {
		return ApprovalSLA{}, err
	}

	latencyConds := append([]string{}, baseConds...)
	latencyConds = append(latencyConds, "status IN ('approved','rejected')")
	latencyWhere := "WHERE " + strings.Join(latencyConds, " AND ")
	latencyQ := `SELECT TIMESTAMPDIFF(SECOND, created_at, decided_at) AS decision_seconds
	             FROM approval_requests ` + latencyWhere + `
	             ORDER BY decision_seconds ASC`

	rows, err := s.db.Query(latencyQ, baseArgs...)
	if err != nil {
		return ApprovalSLA{}, err
	}
	defer rows.Close()
	var latencies []int
	for rows.Next() {
		var v sql.NullInt64
		if err := rows.Scan(&v); err != nil {
			return ApprovalSLA{}, err
		}
		if v.Valid && v.Int64 >= 0 {
			latencies = append(latencies, int(v.Int64))
		}
	}
	sort.Ints(latencies)

	return ApprovalSLA{
		DecisionCount:             len(latencies),
		MedianSeconds:             percentileSeconds(latencies, 50),
		P95Seconds:                percentileSeconds(latencies, 95),
		PendingOlderThanThreshold: int(oldCount.Int64),
		PendingWarningDays:        pendingWarningDays,
		OldestPendingCreatedAt:    oldest,
	}, nil
}

// Decide marks a pending request approved or rejected. Returns true if a row was updated.
func (s *ApprovalService) Decide(id int64, status string, approvedByUserID int, note string) (bool, error) {
	if status != "approved" && status != "rejected" {
		return false, fmt.Errorf("invalid decision status %q", status)
	}
	var noteVal sql.NullString
	if note != "" {
		noteVal = sql.NullString{String: note, Valid: true}
	}
	res, err := s.db.Exec(
		`UPDATE approval_requests
		 SET status=?, approved_by_user_id=?, decision_note=?, decided_at=NOW()
		 WHERE id=? AND status='pending'`,
		status, approvedByUserID, noteVal, id,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CancelByRequester lets the requester withdraw their own pending request.
func (s *ApprovalService) CancelByRequester(id int64, requestedByUserID int, note string) (bool, error) {
	var noteVal sql.NullString
	if note != "" {
		noteVal = sql.NullString{String: note, Valid: true}
	}
	res, err := s.db.Exec(
		`UPDATE approval_requests
		 SET status='cancelled', decision_note=?, decided_at=NOW()
		 WHERE id=? AND status='pending' AND requested_by_user_id=?`,
		noteVal, id, requestedByUserID,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// queryWithJoins runs the standard approvals SELECT with all the joined display
// fields, applying the supplied WHERE clause + bound args + LIMIT/OFFSET.
func (s *ApprovalService) queryWithJoins(whereClause string, args []interface{}, limit, offset int) ([]ApprovalRequest, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT ar.id, ar.action_type, ar.status, ar.payload_json,
	             ar.requested_by_user_id,
	             COALESCE(req.uuid, ''), COALESCE(req.display_label, ''),
	             ar.approved_by_user_id, appr.uuid, appr.display_label,
	             ar.project_id, p.uuid, p.name,
	             ar.decision_note, ar.decided_at, ar.created_at,
	             (SELECT bw_json_text(al.metadata_json, 'failure_reason')
	              FROM audit_log al
	              WHERE al.event_type='admin.approval.decision.denied'
	                AND al.target_type='approval_request'
	                AND (CASE WHEN al.target_id ~ '^[0-9]+$'
	                          THEN al.target_id::bigint END) = ar.id
	              ORDER BY al.id DESC LIMIT 1) AS latest_denial_reason
	      FROM approval_requests ar
	      JOIN users req ON req.id = ar.requested_by_user_id
	      LEFT JOIN users appr ON appr.id = ar.approved_by_user_id
	      LEFT JOIN projects p ON p.id = ar.project_id
	      ` + whereClause + `
	      ORDER BY CASE ar.status WHEN 'pending' THEN 0 ELSE 1 END, ar.created_at DESC
	      LIMIT ? OFFSET ?`

	args = append(append([]interface{}{}, args...), limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ApprovalRequest
	for rows.Next() {
		var r ApprovalRequest
		if err := rows.Scan(
			&r.ID, &r.ActionType, &r.Status, &r.PayloadJSON,
			&r.RequestedByUserID, &r.RequestedByUUID, &r.RequestedByDisplayLabel,
			&r.ApprovedByUserID, &r.ApprovedByUUID, &r.ApprovedByDisplayLabel,
			&r.ProjectID, &r.ProjectUUID, &r.ProjectName,
			&r.DecisionNote, &r.DecidedAt, &r.CreatedAt,
			&r.LatestDenialReason,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *ApprovalService) buildVisibilityConditions(alias string, userID int, includeAll bool, visibleProjectIDs []int) ([]string, []interface{}) {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	var conds []string
	var args []interface{}
	if !includeAll {
		if len(visibleProjectIDs) == 0 {
			conds = append(conds, prefix+"requested_by_user_id = ?")
			args = append(args, userID)
		} else {
			placeholders, ids := inClauseInts(visibleProjectIDs)
			conds = append(conds, "("+prefix+"requested_by_user_id = ? OR "+prefix+"project_id IN ("+placeholders+"))")
			args = append(args, userID)
			args = append(args, ids...)
		}
	}
	return conds, args
}

func applyApprovalFilters(conds []string, args []interface{}, f ApprovalFilters, includeAll bool, alias string) ([]string, []interface{}) {
	if f.Status != "" {
		conds = append(conds, alias+".status = ?")
		args = append(args, f.Status)
	}
	if f.ActionType != "" {
		conds = append(conds, alias+".action_type LIKE ?")
		args = append(args, "%"+f.ActionType+"%")
	}
	if includeAll && f.RequestedByUUID != "" {
		conds = append(conds, "req.uuid = ?")
		args = append(args, f.RequestedByUUID)
	}
	if f.ProjectUUID != "" {
		conds = append(conds, "p.uuid = ?")
		args = append(args, f.ProjectUUID)
	}
	if f.FailureReason != "" {
		conds = append(conds, `EXISTS (SELECT 1 FROM audit_log al
		                       WHERE al.event_type='admin.approval.decision.denied'
		                         AND al.target_type='approval_request'
		                         AND (CASE WHEN al.target_id ~ '^[0-9]+$'
		                                   THEN al.target_id::bigint END) = `+alias+`.id
		                         AND bw_json_text(al.metadata_json, 'failure_reason') = ?)`)
		args = append(args, f.FailureReason)
	}
	if f.DateFrom != "" {
		conds = append(conds, alias+".created_at >= ?")
		args = append(args, f.DateFrom)
	}
	if f.DateTo != "" {
		conds = append(conds, alias+".created_at <= ?")
		args = append(args, f.DateTo)
	}
	return conds, args
}

// percentileSeconds picks the value at the requested percentile (1-99) from
// a sorted slice of latencies. Returns 0 for an empty slice.
func percentileSeconds(values []int, percentile int) int {
	if len(values) == 0 {
		return 0
	}
	rank := (percentile * len(values)) / 100
	if rank < 1 {
		rank = 1
	}
	idx := rank - 1
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}
