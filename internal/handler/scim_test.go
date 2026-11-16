// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeSCIMUserDefaultsActiveWhenOmitted(t *testing.T) {
	r := httptest.NewRequest("POST", "/scim/v2/Users", strings.NewReader(`{"userName":"alice@example.com"}`))
	in, err := decodeSCIMUser(r, true)
	if err != nil {
		t.Fatalf("decodeSCIMUser(): %v", err)
	}
	if !in.Active {
		t.Fatal("omitted active should default to true")
	}
}

func TestDecodeSCIMUserPreservesExplicitFalse(t *testing.T) {
	r := httptest.NewRequest("POST", "/scim/v2/Users", strings.NewReader(`{"userName":"alice@example.com","active":false}`))
	in, err := decodeSCIMUser(r, true)
	if err != nil {
		t.Fatalf("decodeSCIMUser(): %v", err)
	}
	if in.Active {
		t.Fatal("explicit active=false was not preserved")
	}
}
