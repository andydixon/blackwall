// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package model

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

type Organization struct {
	ID          int
	UUID        string
	Name        string
	Slug        string
	LogoURL     sql.NullString
	Status      string
	AdminUserID sql.NullInt64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (o *Organization) IsActive() bool { return o.Status == "active" }

type User struct {
	ID             int
	OrganizationID int
	UUID           string
	DisplayLabel   string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (u *User) IsActive() bool { return u.Status == "active" }

type Project struct {
	ID             int
	OrganizationID int
	UUID           string
	Name           string
	OwnerUserID    sql.NullInt64
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (p *Project) IsActive() bool { return p.Status == "active" }

type OAuthClient struct {
	ID                   int
	ClientID             string
	ClientSecretHash     sql.NullString
	ProjectID            int
	Name                 string
	RedirectURIs         []string
	Grants               []string
	Scopes               []string
	PKCERequired         bool
	AccessTokenType      string
	AccessTokenLifetime  int
	RefreshTokenLifetime int
	OIDCEnabled          bool
	Status               string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (c *OAuthClient) IsActive() bool { return c.Status == "active" }
func (c *OAuthClient) IsConfidential() bool {
	return c.ClientSecretHash.Valid && c.ClientSecretHash.String != ""
}
func (c *OAuthClient) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
func (c *OAuthClient) SupportsGrant(grant string) bool {
	for _, g := range c.Grants {
		if g == grant {
			return true
		}
	}
	return false
}
func (c *OAuthClient) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type PrivilegeLevel struct {
	ID          int
	ProjectID   int
	Level       int
	Name        string
	Description sql.NullString
}

type UserProjectRole struct {
	ID             int
	UserID         int
	ProjectID      int
	PrivilegeLevel int
	CreatedAt      time.Time
}

type AdminRole struct {
	UserID    int
	Role      string
	IsActive  bool
	CreatedAt time.Time
}

type ApprovalRequest struct {
	ID                int
	ActionType        string
	Status            string
	PayloadJSON       string
	RequestedByUserID int
	ApprovedByUserID  sql.NullInt64
	DecisionNote      sql.NullString
	ProjectID         sql.NullInt64
	CreatedAt         time.Time
	DecidedAt         sql.NullTime
}

type AuditEntry struct {
	ID                         int64
	EventType                  string
	Outcome                    string
	Message                    sql.NullString
	CorrelationID              sql.NullString
	IPAddress                  sql.NullString
	UserAgent                  sql.NullString
	ActorUserID                sql.NullInt64
	ActorUserUUID              sql.NullString
	ProjectID                  sql.NullInt64
	ProjectUUID                sql.NullString
	OrganizationID             sql.NullInt64
	OrganizationUUID           sql.NullString
	OAuthClientID              sql.NullInt64
	OAuthClientPublicID        sql.NullString
	WebAuthnCredentialID       sql.NullInt64
	WebAuthnCredentialPublicID sql.NullString
	TargetType                 sql.NullString
	TargetID                   sql.NullInt64
	MetadataJSON               sql.NullString
	ChainPrevHash              sql.NullString
	ChainHash                  sql.NullString
	CreatedAt                  time.Time
}

type MaintenanceJobRun struct {
	ID          int
	JobName     string
	Status      string
	StartedAt   time.Time
	FinishedAt  sql.NullTime
	DurationMs  sql.NullInt64
	Message     sql.NullString
	StatsJSON   sql.NullString
	ErrorTrace  sql.NullString
	TriggeredBy string
}

type RateLimitRecord struct {
	ID           int
	Identifier   string
	Action       string
	Attempts     int
	WindowStart  time.Time
	BlockedUntil sql.NullTime
}

func ParseJSONStringSlice(raw string) []string {
	var result []string
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		if raw != "" {
			return strings.Split(raw, ",")
		}
		return nil
	}
	return result
}
