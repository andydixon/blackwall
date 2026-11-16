// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"blackwall/internal/config"
)

// TestDiscovery_RequiredFields pins the set of fields the OpenID Foundation
// conformance suite checks. If a future cleanup removes one of these by
// accident, this test surfaces it as a fail rather than a 4-hour conformance
// debug session.
//
// We deliberately don't snapshot the exact JSON — only that the named fields
// are present and non-empty. Field ordering, additions, and value tweaks
// (e.g. adding ES256 to id_token_signing_alg_values_supported) shouldn't
// require touching this test.
func TestDiscovery_RequiredFields(t *testing.T) {
	cfg := &config.Config{AppURL: "https://test.example.com"}
	config.Set(cfg)
	h := &OAuthHandler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	h.Discovery(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Discovery returned %d", rec.Code)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Discovery body is not JSON: %v", err)
	}
	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"response_types_supported",
		"response_modes_supported",
		"grant_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"scopes_supported",
		"token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported",
		"claims_supported",
		"claim_types_supported",
	}
	for _, f := range required {
		if _, ok := got[f]; !ok {
			t.Errorf("discovery doc missing required field %q", f)
		}
	}
	// Explicit false-valued fields the suite checks for (presence + value).
	for _, f := range []string{
		"claims_parameter_supported",
		"request_parameter_supported",
		"request_uri_parameter_supported",
	} {
		v, present := got[f]
		if !present {
			t.Errorf("discovery doc missing required false-valued field %q", f)
			continue
		}
		if b, ok := v.(bool); !ok || b {
			t.Errorf("discovery doc field %q should be false, got %v", f, v)
		}
	}
	if got["issuer"] != "https://test.example.com" {
		t.Errorf("issuer mismatch: %v", got["issuer"])
	}
	responseModes, ok := got["response_modes_supported"].([]interface{})
	if !ok || len(responseModes) != 1 || responseModes[0] != "query" {
		t.Errorf("response_modes_supported should advertise only implemented query mode, got %v", got["response_modes_supported"])
	}
}
