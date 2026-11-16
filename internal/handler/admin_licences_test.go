// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"reflect"
	"testing"
)

func TestSplitLicenceListAcceptsLinesAndCommas(t *testing.T) {
	got := splitLicenceList(" app.example.com\r\napi.example.com, 10.0.0.1\n\n")
	want := []string{"app.example.com", "api.example.com", "10.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
