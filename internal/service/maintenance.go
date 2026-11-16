// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"database/sql"
	"encoding/json"
	"time"

	"blackwall/internal/config"
)

type MaintenanceService struct {
	db *sql.DB
}

func NewMaintenanceService(db *sql.DB) *MaintenanceService {
	return &MaintenanceService{db: db}
}

func (s *MaintenanceService) RunAll(triggeredBy string) map[string]interface{} {
	results := map[string]interface{}{}
	results["tokens"] = s.runJob("cleanup_tokens", triggeredBy, s.cleanupTokens)
	results["audit"] = s.runJob("cleanup_audit", triggeredBy, s.cleanupAudit)
	results["approvals"] = s.runJob("reject_expired_approvals", triggeredBy, s.rejectExpiredApprovals)
	results["rate_limits"] = s.runJob("cleanup_rate_limits", triggeredBy, s.cleanupRateLimits)
	return results
}

func (s *MaintenanceService) runJob(name, triggeredBy string, fn func() (map[string]interface{}, error)) map[string]interface{} {
	start := time.Now()
	var jobID int64
	s.db.QueryRow(`INSERT INTO maintenance_job_runs (job_name, status, started_at, triggered_by) VALUES (?,?,?,?)`,
		name, "running", start, triggeredBy).Scan(&jobID)

	stats, err := fn()
	dur := time.Since(start).Milliseconds()

	status := "success"
	errMsg := sql.NullString{}
	if err != nil {
		status = "fail"
		errMsg = sql.NullString{String: err.Error(), Valid: true}
	}

	// Persist the per-job counts. These were previously computed and then
	// discarded, which is why the admin maintenance page had nothing to show.
	statsJSON := sql.NullString{}
	if len(stats) > 0 {
		if encoded, mErr := json.Marshal(stats); mErr == nil {
			statsJSON = sql.NullString{String: string(encoded), Valid: true}
		}
	}

	s.db.Exec(`UPDATE maintenance_job_runs SET status=?, finished_at=?, duration_ms=?, stats_json=?, error_trace=? WHERE id=?`,
		status, time.Now(), dur, statsJSON, errMsg, jobID)

	result := map[string]interface{}{
		"status":   status,
		"duration": dur,
		"stats":    stats,
	}
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

func (s *MaintenanceService) cleanupTokens() (map[string]interface{}, error) {
	r1, err := s.db.Exec(`DELETE FROM oauth_auth_codes WHERE expires_at < NOW()`)
	if err != nil {
		return nil, err
	}
	r2, err := s.db.Exec(`DELETE FROM oauth_access_tokens WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY)`)
	if err != nil {
		return nil, err
	}
	r3, err := s.db.Exec(`DELETE FROM oauth_refresh_tokens WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY)`)
	if err != nil {
		return nil, err
	}
	a1, _ := r1.RowsAffected()
	a2, _ := r2.RowsAffected()
	a3, _ := r3.RowsAffected()
	return map[string]interface{}{"auth_codes": a1, "access_tokens": a2, "refresh_tokens": a3}, nil
}

func (s *MaintenanceService) cleanupAudit() (map[string]interface{}, error) {
	days := config.Get().AuditRetentionDays
	r, err := s.db.Exec(`DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)`, days)
	if err != nil {
		return nil, err
	}
	a, _ := r.RowsAffected()
	return map[string]interface{}{"deleted": a}, nil
}

func (s *MaintenanceService) rejectExpiredApprovals() (map[string]interface{}, error) {
	maxAge := config.Get().ApprovalPendingMaxAgeDays
	r, err := s.db.Exec(`UPDATE approval_requests SET status='rejected', decision_note='Auto-rejected: exceeded maximum pending age', decided_at=NOW() WHERE status='pending' AND created_at < DATE_SUB(NOW(), INTERVAL ? DAY)`, maxAge)
	if err != nil {
		return nil, err
	}
	a, _ := r.RowsAffected()
	return map[string]interface{}{"rejected": a}, nil
}

func (s *MaintenanceService) cleanupRateLimits() (map[string]interface{}, error) {
	r, err := s.db.Exec(`DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 24 HOUR) AND (blocked_until IS NULL OR blocked_until < NOW())`)
	if err != nil {
		return nil, err
	}
	a, _ := r.RowsAffected()
	return map[string]interface{}{"deleted": a}, nil
}

func (s *MaintenanceService) GetLastRuns() ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`SELECT job_name, status, started_at, finished_at, duration_ms, message, triggered_by FROM maintenance_job_runs ORDER BY started_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var name, status, triggeredBy string
		var started time.Time
		var finished sql.NullTime
		var dur sql.NullInt64
		var message sql.NullString
		if err := rows.Scan(&name, &status, &started, &finished, &dur, &message, &triggeredBy); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"job_name":     name,
			"status":       status,
			"started_at":   started.Format(time.RFC3339),
			"finished_at":  nullTimeStr(finished),
			"duration_ms":  dur.Int64,
			"message":      message.String,
			"triggered_by": triggeredBy,
		})
	}
	return result, nil
}

func nullTimeStr(t sql.NullTime) string {
	if !t.Valid {
		return ""
	}
	return t.Time.Format(time.RFC3339)
}
