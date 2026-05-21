package service

import (
	"strings"
	"testing"
	"time"
)

// TestTranslateSCIMFilter exercises the operator subset every major IdP
// emits. We don't (yet) support disjunctions; if the test set grows to
// include `or` we know the upgrade is needed.
func TestTranslateSCIMFilter(t *testing.T) {
	cases := []struct {
		name      string
		filter    string
		wantSQL   string
		wantArgs  []interface{}
		expectErr bool
	}{
		{
			name:     "eq on userName",
			filter:   `userName eq "alice@example.com"`,
			wantSQL:  `u.display_label=?`,
			wantArgs: []interface{}{"alice@example.com"},
		},
		{
			name:     "eq on externalId",
			filter:   `externalId eq "wd-12345"`,
			wantSQL:  `m.external_id=?`,
			wantArgs: []interface{}{"wd-12345"},
		},
		{
			name:     "sw on userName",
			filter:   `userName sw "alice"`,
			wantSQL:  `u.display_label LIKE ?`,
			wantArgs: []interface{}{"alice%"},
		},
		{
			name:     "co on userName",
			filter:   `userName co "@example.com"`,
			wantSQL:  `u.display_label LIKE ?`,
			wantArgs: []interface{}{"%@example.com%"},
		},
		{
			name:     "pr on externalId",
			filter:   `externalId pr`,
			wantSQL:  `m.external_id IS NOT NULL AND m.external_id<>''`,
			wantArgs: nil,
		},
		{
			name:     "active eq true",
			filter:   `active eq "true"`,
			wantSQL:  `u.status='active'`,
			wantArgs: nil,
		},
		{
			name:     "active eq false",
			filter:   `active eq "false"`,
			wantSQL:  `u.status!='active'`,
			wantArgs: nil,
		},
		{
			name:     "AND of two clauses",
			filter:   `userName eq "alice@example.com" and active eq "true"`,
			wantSQL:  `u.display_label=? AND u.status='active'`,
			wantArgs: []interface{}{"alice@example.com"},
		},
		{
			name:      "unsupported attribute",
			filter:    `nickname eq "alice"`,
			expectErr: true,
		},
		{
			name:      "malformed clause",
			filter:    `eq alice`,
			expectErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotSQL, gotArgs, err := translateSCIMFilter(tc.filter)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got SQL %q", gotSQL)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotSQL != tc.wantSQL {
				t.Errorf("SQL mismatch:\n got  %q\n want %q", gotSQL, tc.wantSQL)
			}
			if !argsEqual(gotArgs, tc.wantArgs) {
				t.Errorf("args mismatch: got %v, want %v", gotArgs, tc.wantArgs)
			}
		})
	}
}

func argsEqual(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBuildSCIMUser confirms a user's stored shape projects into the wire
// JSON correctly: emails populate iff label looks like an email, active
// derives from the status enum.
func TestBuildSCIMUser(t *testing.T) {
	u := buildSCIMUser("uuid-1", "alice@example.com", "active", "wd-1",
		mustParseTime("2025-01-01T00:00:00Z"), mustParseTime("2025-02-01T00:00:00Z"))
	if u.ID != "uuid-1" || u.UserName != "alice@example.com" {
		t.Errorf("identity mismatch: %+v", u)
	}
	if !u.Active {
		t.Errorf("active status should map to Active=true")
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "alice@example.com" || !u.Emails[0].Primary {
		t.Errorf("emails should be populated for email-shaped label: %v", u.Emails)
	}
	if u.Meta.Location != "/scim/v2/Users/uuid-1" {
		t.Errorf("location wrong: %s", u.Meta.Location)
	}

	// Non-email label → no Emails entry.
	u2 := buildSCIMUser("uuid-2", "bob", "disabled", "",
		mustParseTime("2025-01-01T00:00:00Z"), mustParseTime("2025-01-01T00:00:00Z"))
	if u2.Active {
		t.Errorf("disabled status should map to Active=false")
	}
	if len(u2.Emails) != 0 {
		t.Errorf("non-email label should yield no Emails entries, got %v", u2.Emails)
	}
}

func TestSplitFilterAndClauses(t *testing.T) {
	parts := splitFilterAndClauses(`a eq "x" and b sw "y" and c pr`)
	if len(parts) != 3 {
		t.Fatalf("expected 3 clauses, got %d: %v", len(parts), parts)
	}
	if !strings.HasPrefix(parts[0], "a eq") {
		t.Errorf("first clause wrong: %q", parts[0])
	}
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
