// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import "testing"

func TestSumJobStats(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int64
	}{
		{"empty string", "", 0},
		{"cleanup_tokens shape", `{"auth_codes":3,"access_tokens":12,"refresh_tokens":4}`, 19},
		{"single counter", `{"deleted":7}`, 7},
		{"zero counters", `{"deleted":0}`, 0},
		{"empty object", `{}`, 0},
		{"null stats", `null`, 0},
		{"malformed json contributes nothing", `{"deleted":`, 0},
		{"non-numeric values ignored", `{"deleted":5,"note":"skipped"}`, 5},
		{"nested values ignored", `{"deleted":5,"detail":{"a":100}}`, 5},
		{"json array is not an object", `[1,2,3]`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sumJobStats(tc.in); got != tc.want {
				t.Errorf("sumJobStats(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
