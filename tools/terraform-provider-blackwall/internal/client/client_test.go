// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBodyBytes+1)))
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	err := c.do(context.Background(), http.MethodGet, "/", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("do() error = %v, want response size error", err)
	}
}

func TestDoDecodesBoundedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "token")
	var out map[string]bool
	if err := c.do(context.Background(), http.MethodGet, "/", nil, &out); err != nil {
		t.Fatalf("do(): %v", err)
	}
	if !out["ok"] {
		t.Fatalf("decoded response = %#v", out)
	}
}
