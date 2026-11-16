// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"blackwall/internal/config"
)

type MetricsHandler struct {
	DB *sql.DB
}

func (h *MetricsHandler) Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	cfg := config.Get()
	expectedToken := strings.TrimSpace(cfg.MetricsToken)
	allowUnauth := cfg.MetricsAllowUnauthenticated

	if !allowUnauth {
		if expectedToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Metrics authentication is not configured"})
			return
		}

		authHeader := r.Header.Get("Authorization")
		providedToken := ""
		if strings.HasPrefix(authHeader, "Bearer ") {
			providedToken = strings.TrimPrefix(authHeader, "Bearer ")
		}

		if !secureEqual(expectedToken, providedToken) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}
	}

	payload := h.collect()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(payload)
}

func (h *MetricsHandler) collect() map[string]interface{} {
	payload := map[string]interface{}{}

	row := h.DB.QueryRow("SELECT COUNT(*) FROM users")
	var users int64
	row.Scan(&users)
	payload["users_total"] = users

	row = h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE status='active'")
	var activeUsers int64
	row.Scan(&activeUsers)
	payload["users_active"] = activeUsers

	row = h.DB.QueryRow("SELECT COUNT(*) FROM projects")
	var projects int64
	row.Scan(&projects)
	payload["projects_total"] = projects

	row = h.DB.QueryRow("SELECT COUNT(*) FROM oauth_clients")
	var clients int64
	row.Scan(&clients)
	payload["oauth_clients_total"] = clients

	row = h.DB.QueryRow("SELECT COUNT(*) FROM webauthn_credentials")
	var creds int64
	row.Scan(&creds)
	payload["webauthn_credentials_total"] = creds

	row = h.DB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE created_at >= CURDATE()")
	var auditToday int64
	row.Scan(&auditToday)
	payload["audit_events_today"] = auditToday

	// oauth_tokens has never existed; access and refresh tokens live in
	// separate tables. Counting them separately keeps the figures meaningful —
	// summing two different kinds of token into one gauge would not be.
	row = h.DB.QueryRow("SELECT COUNT(*) FROM oauth_access_tokens WHERE expires_at > NOW() AND revoked_at IS NULL")
	var activeTokens int64
	row.Scan(&activeTokens)
	payload["oauth_tokens_active"] = activeTokens

	row = h.DB.QueryRow("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE expires_at > NOW() AND revoked_at IS NULL")
	var activeRefreshTokens int64
	row.Scan(&activeRefreshTokens)
	payload["oauth_refresh_tokens_active"] = activeRefreshTokens

	row = h.DB.QueryRow("SELECT COUNT(*) FROM approval_requests WHERE status='pending'")
	var pendingApprovals int64
	row.Scan(&pendingApprovals)
	payload["approvals_pending"] = pendingApprovals

	return payload
}

// secureEqual is a constant-time string comparison.
func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
