// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

// Package client is a tiny HTTP client against BlackWall's /api/v1 surface.
// Intentionally minimal — the provider reaches into it for one verb at a
// time, so we don't paginate, don't cache, don't share connections beyond
// the standard http.Client default.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBodyBytes = 8 * 1024 * 1024

// Client is the BlackWall admin API HTTP client.
type Client struct {
	Host       string
	Token      string
	HTTPClient *http.Client
}

// New constructs a Client from the provider-block configuration.
func New(host, token string) *Client {
	host = strings.TrimRight(host, "/")
	return &Client{
		Host:  host,
		Token: token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// do is the single roundtrip helper. Marshals body (if any), sets the
// Authorization header, decodes a JSON response into out (if any), and
// turns non-2xx into a structured Error so the Terraform diagnostics layer
// can render a useful message.
func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Host+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(respBytes) > maxResponseBodyBytes {
		return fmt.Errorf("response body exceeds %d bytes", maxResponseBodyBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Body: string(respBytes)}
	}
	if out != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// APIError carries the HTTP status + raw body for diagnostics.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("blackwall api %d: %s", e.Status, e.Body)
}

// IsNotFound returns true if the error is a 404 — useful for the Terraform
// resource Read step where a missing remote object means "drop from state".
func IsNotFound(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status == http.StatusNotFound
	}
	return false
}

// ─── DTOs that mirror the JSON the BlackWall API emits ────────────────────

type Organization struct {
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

type Project struct {
	UUID             string                 `json:"uuid"`
	Name             string                 `json:"name"`
	Status           string                 `json:"status"`
	OrganizationUUID string                 `json:"organization_uuid"`
	OrganizationName string                 `json:"organization_name"`
	Features         map[string]interface{} `json:"features,omitempty"`
}

type ClaimDefault struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type WebhookEndpoint struct {
	PublicID    string   `json:"public_id"`
	TargetURL   string   `json:"target_url"`
	Events      []string `json:"events"`
	Status      string   `json:"status"`
	Description string   `json:"description,omitempty"`
	// Secret is returned only on creation. Subsequent reads omit it; the
	// provider preserves what it captured at create time in state.
	Secret string `json:"secret,omitempty"`
}

// ─── Calls ────────────────────────────────────────────────────────────────

func (c *Client) ListOrganizations(ctx context.Context) ([]Organization, error) {
	var resp struct {
		Organizations []Organization `json:"organizations"`
	}
	if err := c.do(ctx, "GET", "/api/v1/organizations", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Organizations, nil
}

func (c *Client) GetProject(ctx context.Context, uuid string) (*Project, error) {
	var p Project
	if err := c.do(ctx, "GET", "/api/v1/projects/"+uuid, nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) UpsertClaimDefault(ctx context.Context, projectUUID, key, value string) error {
	body := ClaimDefault{Key: key, Value: value}
	return c.do(ctx, "PUT", "/api/v1/projects/"+projectUUID+"/claim_defaults", body, nil)
}

// DeleteClaimDefault removes a project-default claim. The key is sent in
// the query string so a missing body doesn't trip stricter HTTP middleware.
func (c *Client) DeleteClaimDefault(ctx context.Context, projectUUID, key string) error {
	return c.do(ctx, "DELETE", "/api/v1/projects/"+projectUUID+"/claim_defaults?key="+url.QueryEscape(key), nil, nil)
}

func (c *Client) ListClaimDefaults(ctx context.Context, projectUUID string) ([]ClaimDefault, error) {
	var resp struct {
		Claims []ClaimDefault `json:"claim_defaults"`
	}
	if err := c.do(ctx, "GET", "/api/v1/projects/"+projectUUID+"/claim_defaults", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Claims, nil
}

func (c *Client) CreateWebhook(ctx context.Context, projectUUID, targetURL, description string, events []string) (*WebhookEndpoint, error) {
	body := WebhookEndpoint{TargetURL: targetURL, Description: description, Events: events}
	var resp WebhookEndpoint
	if err := c.do(ctx, "POST", "/api/v1/projects/"+projectUUID+"/webhooks", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListWebhooks(ctx context.Context, projectUUID string) ([]WebhookEndpoint, error) {
	var resp struct {
		Webhooks []WebhookEndpoint `json:"webhooks"`
	}
	if err := c.do(ctx, "GET", "/api/v1/projects/"+projectUUID+"/webhooks", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Webhooks, nil
}

// PatchWebhookInput is the body for an in-place webhook update. Pointer
// fields let the caller send "leave this field alone" by passing nil; the
// JSON omitempty + pointer pattern keeps the wire shape minimal.
type PatchWebhookInput struct {
	TargetURL    *string  `json:"target_url,omitempty"`
	Events       []string `json:"events,omitempty"`
	Description  *string  `json:"description,omitempty"`
	Status       *string  `json:"status,omitempty"`
	RotateSecret bool     `json:"rotate_secret,omitempty"`
}

func (c *Client) PatchWebhook(ctx context.Context, projectUUID, publicID string, in PatchWebhookInput) (*WebhookEndpoint, error) {
	var ep WebhookEndpoint
	if err := c.do(ctx, "PATCH", "/api/v1/projects/"+projectUUID+"/webhooks/"+publicID, in, &ep); err != nil {
		return nil, err
	}
	return &ep, nil
}

func (c *Client) DeleteWebhook(ctx context.Context, projectUUID, publicID string) error {
	return c.do(ctx, "DELETE", "/api/v1/projects/"+projectUUID+"/webhooks/"+publicID, nil, nil)
}

// ─── Projects ──────────────────────────────────────────────────────────────

type CreateProjectInput struct {
	Name             string `json:"name"`
	OrganizationUUID string `json:"organization_uuid"`
}

type PatchProjectInput struct {
	Name   *string `json:"name,omitempty"`
	Status *string `json:"status,omitempty"`
}

func (c *Client) CreateProject(ctx context.Context, in CreateProjectInput) (*Project, error) {
	var p Project
	if err := c.do(ctx, "POST", "/api/v1/projects", in, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) PatchProject(ctx context.Context, projectUUID string, in PatchProjectInput) error {
	return c.do(ctx, "PATCH", "/api/v1/projects/"+projectUUID, in, nil)
}

func (c *Client) DeleteProject(ctx context.Context, projectUUID string) error {
	return c.do(ctx, "DELETE", "/api/v1/projects/"+projectUUID, nil, nil)
}

// ─── OAuth clients ─────────────────────────────────────────────────────────

type OAuthClient struct {
	ClientID             string   `json:"client_id"`
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	ClientSecret         string   `json:"client_secret,omitempty"` // only at create
	OIDCEnabled          bool     `json:"oidc_enabled"`
	AccessTokenType      string   `json:"access_token_type"`
	AccessTokenLifetime  int      `json:"access_token_lifetime"`
	RefreshTokenLifetime int      `json:"refresh_token_lifetime"`
	RedirectURIs         []string `json:"redirect_uris"`
	Grants               []string `json:"grants"`
	Scopes               []string `json:"scopes"`
}

type CreateOAuthClientInput struct {
	Name                 string   `json:"name"`
	ClientType           string   `json:"client_type,omitempty"`
	RedirectURIs         []string `json:"redirect_uris,omitempty"`
	Grants               []string `json:"grants,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	AccessTokenType      string   `json:"access_token_type,omitempty"`
	AccessTokenLifetime  int      `json:"access_token_lifetime,omitempty"`
	RefreshTokenLifetime int      `json:"refresh_token_lifetime,omitempty"`
	OIDCEnabled          bool     `json:"oidc_enabled,omitempty"`
}

type PatchOAuthClientInput struct {
	Name                 *string  `json:"name,omitempty"`
	Status               *string  `json:"status,omitempty"`
	RedirectURIs         []string `json:"redirect_uris,omitempty"`
	Grants               []string `json:"grants,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	AccessTokenType      *string  `json:"access_token_type,omitempty"`
	AccessTokenLifetime  *int     `json:"access_token_lifetime,omitempty"`
	RefreshTokenLifetime *int     `json:"refresh_token_lifetime,omitempty"`
	OIDCEnabled          *bool    `json:"oidc_enabled,omitempty"`
}

func (c *Client) CreateOAuthClient(ctx context.Context, projectUUID string, in CreateOAuthClientInput) (*OAuthClient, error) {
	var out OAuthClient
	if err := c.do(ctx, "POST", "/api/v1/projects/"+projectUUID+"/oauth_clients", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetOAuthClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	var out OAuthClient
	if err := c.do(ctx, "GET", "/api/v1/oauth_clients/"+clientID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PatchOAuthClient(ctx context.Context, clientID string, in PatchOAuthClientInput) error {
	return c.do(ctx, "PATCH", "/api/v1/oauth_clients/"+clientID, in, nil)
}

func (c *Client) DeleteOAuthClient(ctx context.Context, clientID string) error {
	return c.do(ctx, "DELETE", "/api/v1/oauth_clients/"+clientID, nil, nil)
}

// ─── SAML SPs ──────────────────────────────────────────────────────────────

type SAMLSP struct {
	PublicID       string            `json:"public_id"`
	EntityID       string            `json:"entity_id"`
	ACSURL         string            `json:"acs_url"`
	SLOURL         string            `json:"slo_url,omitempty"`
	NameIDFormat   string            `json:"name_id_format"`
	Audience       string            `json:"audience,omitempty"`
	SignAssertions bool              `json:"sign_assertions"`
	SignResponse   bool              `json:"sign_response"`
	SPCertPEM      string            `json:"sp_cert_pem,omitempty"`
	AttributeMap   map[string]string `json:"attribute_map"`
	Status         string            `json:"status"`
}

type CreateSAMLSPInput struct {
	EntityID     string            `json:"entity_id"`
	ACSURL       string            `json:"acs_url"`
	SLOURL       string            `json:"slo_url,omitempty"`
	NameIDFormat string            `json:"name_id_format,omitempty"`
	Audience     string            `json:"audience,omitempty"`
	AttributeMap map[string]string `json:"attribute_map,omitempty"`
	SPCertPEM    string            `json:"sp_cert_pem,omitempty"`
}

func (c *Client) CreateSAMLSP(ctx context.Context, projectUUID string, in CreateSAMLSPInput) (*SAMLSP, error) {
	var out SAMLSP
	if err := c.do(ctx, "POST", "/api/v1/projects/"+projectUUID+"/saml_service_providers", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetSAMLSP(ctx context.Context, publicID string) (*SAMLSP, error) {
	var out SAMLSP
	if err := c.do(ctx, "GET", "/api/v1/saml_service_providers/"+publicID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteSAMLSP(ctx context.Context, publicID string) error {
	return c.do(ctx, "DELETE", "/api/v1/saml_service_providers/"+publicID, nil, nil)
}
