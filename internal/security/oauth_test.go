// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package security

import (
	"net/url"
	"testing"
)

func TestValidateOAuthRequestMaxAge(t *testing.T) {
	base := url.Values{
		"response_type":         {"code"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"nonce":                 {"nonce"},
	}

	for _, tc := range []struct {
		name    string
		value   string
		present bool
		wantOK  bool
	}{
		{name: "omitted", wantOK: true},
		{name: "empty", present: true, wantOK: false},
		{name: "zero", value: "0", present: true, wantOK: true},
		{name: "positive", value: "604800", present: true, wantOK: true},
		{name: "negative", value: "-1", present: true, wantOK: false},
		{name: "non-numeric", value: "week", present: true, wantOK: false},
		{name: "overflow", value: "9223372036854775808", present: true, wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := make(url.Values, len(base))
			for key, values := range base {
				params[key] = append([]string(nil), values...)
			}
			if tc.present {
				params["max_age"] = []string{tc.value}
			}
			ok, code, _ := ValidateOAuthRequest(params, true)
			if ok != tc.wantOK {
				t.Fatalf("ValidateOAuthRequest() ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK && code != "invalid_request" {
				t.Fatalf("ValidateOAuthRequest() code = %q, want invalid_request", code)
			}
		})
	}

	t.Run("repeated", func(t *testing.T) {
		params := make(url.Values, len(base))
		for key, values := range base {
			params[key] = append([]string(nil), values...)
		}
		params["max_age"] = []string{"60", "120"}
		if ok, _, _ := ValidateOAuthRequest(params, true); ok {
			t.Fatal("ValidateOAuthRequest() accepted repeated max_age")
		}
	})

	t.Run("requires openid", func(t *testing.T) {
		params := make(url.Values, len(base))
		for key, values := range base {
			params[key] = append([]string(nil), values...)
		}
		params.Set("max_age", "60")
		if ok, _, _ := ValidateOAuthRequest(params, false); ok {
			t.Fatal("ValidateOAuthRequest() accepted max_age without OIDC")
		}
	})
}
