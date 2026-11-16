// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package provider

import "testing"

func TestValidateProviderHost(t *testing.T) {
	cases := map[string]bool{
		"https://auth.example.com":        true,
		"https://auth.example.com/":       true,
		"http://localhost:8080":           true,
		"http://127.0.0.1:8080":           true,
		"http://[::1]:8080":               true,
		"http://auth.example.com":         false,
		"https://user@example.com":        false,
		"https://auth.example.com/prefix": false,
		"auth.example.com":                false,
	}
	for raw, wantOK := range cases {
		err := validateProviderHost(raw)
		if (err == nil) != wantOK {
			t.Errorf("validateProviderHost(%q) error = %v, wantOK=%v", raw, err, wantOK)
		}
	}
}
