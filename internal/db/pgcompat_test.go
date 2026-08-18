package db

import (
	"fmt"
	"strings"
	"testing"
)

func TestRewritePlaceholders(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "no placeholders is byte-identical",
			in:   "SELECT COUNT(*) FROM users",
			want: "SELECT COUNT(*) FROM users",
		},
		{
			name: "single placeholder",
			in:   "SELECT id FROM users WHERE email = ?",
			want: "SELECT id FROM users WHERE email = $1",
		},
		{
			name: "numbering runs left to right",
			in:   "UPDATE users SET name = ?, email = ? WHERE id = ?",
			want: "UPDATE users SET name = $1, email = $2 WHERE id = $3",
		},
		{
			name: "ten or more placeholders keep multi-digit numbering",
			in:   "INSERT INTO t VALUES (?,?,?,?,?,?,?,?,?,?,?)",
			want: "INSERT INTO t VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
		},
		{
			name: "dynamic IN list",
			in:   "SELECT * FROM projects WHERE id IN (?,?,?) AND active = ?",
			want: "SELECT * FROM projects WHERE id IN ($1,$2,$3) AND active = $4",
		},
		{
			name: "question mark inside a string literal is preserved",
			in:   "SELECT ? FROM t WHERE label = 'what? really' AND id = ?",
			want: "SELECT $1 FROM t WHERE label = 'what? really' AND id = $2",
		},
		{
			name: "escaped quote inside a literal does not end it",
			in:   "SELECT ? WHERE s = 'it''s a ? here' AND x = ?",
			want: "SELECT $1 WHERE s = 'it''s a ? here' AND x = $2",
		},
		{
			name: "question mark inside a quoted identifier is preserved",
			in:   `SELECT "odd?col" FROM t WHERE id = ?`,
			want: `SELECT "odd?col" FROM t WHERE id = $1`,
		},
		{
			name: "line comment contents are preserved",
			in:   "SELECT ? -- is this a ? placeholder\nFROM t WHERE id = ?",
			want: "SELECT $1 -- is this a ? placeholder\nFROM t WHERE id = $2",
		},
		{
			name: "block comment contents are preserved",
			in:   "SELECT ? /* not a ? here */ FROM t WHERE id = ?",
			want: "SELECT $1 /* not a ? here */ FROM t WHERE id = $2",
		},
		{
			name: "nested block comments",
			in:   "SELECT ? /* outer /* inner ? */ still ? */ FROM t WHERE id = ?",
			want: "SELECT $1 /* outer /* inner ? */ still ? */ FROM t WHERE id = $2",
		},
		{
			name: "dollar quoted body is preserved",
			in:   "SELECT ? , $tag$ a ? b $tag$ , ?",
			want: "SELECT $1 , $tag$ a ? b $tag$ , $2",
		},
		{
			name: "bare dollar quote is preserved",
			in:   "SELECT ? , $$ a ? b $$ , ?",
			want: "SELECT $1 , $$ a ? b $$ , $2",
		},
		{
			name: "upsert with conflict target",
			in: "INSERT INTO user_oidc_claims (user_id, claim_key, claim_value) VALUES (?, ?, ?) " +
				"ON CONFLICT (user_id, claim_key) DO UPDATE SET claim_value = EXCLUDED.claim_value",
			want: "INSERT INTO user_oidc_claims (user_id, claim_key, claim_value) VALUES ($1, $2, $3) " +
				"ON CONFLICT (user_id, claim_key) DO UPDATE SET claim_value = EXCLUDED.claim_value",
		},
		{
			name: "returning clause is untouched",
			in:   "INSERT INTO audit_log (actor, action) VALUES (?, ?) RETURNING id",
			want: "INSERT INTO audit_log (actor, action) VALUES ($1, $2) RETURNING id",
		},
		{
			name: "interval arithmetic is untouched",
			in:   "DELETE FROM audit_log WHERE created_at < NOW() - (? * INTERVAL '1 day')",
			want: "DELETE FROM audit_log WHERE created_at < NOW() - ($1 * INTERVAL '1 day')",
		},
		{
			name: "multiline statement",
			in:   "INSERT INTO t\n  (a, b)\nVALUES\n  (?, ?)",
			want: "INSERT INTO t\n  (a, b)\nVALUES\n  ($1, $2)",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			name: "unterminated literal is copied through",
			in:   "SELECT ? WHERE s = 'unterminated",
			want: "SELECT $1 WHERE s = 'unterminated",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewritePlaceholders(tc.in); got != tc.want {
				t.Errorf("rewritePlaceholders(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
			}
		})
	}
}

// The rewritten statement must carry exactly as many distinct parameters as
// the original had placeholders — an off-by-one here would surface as a
// runtime "bind message supplies N parameters" failure rather than a
// compile error, so assert it directly.
func TestRewritePlaceholderCount(t *testing.T) {
	for n := 1; n <= 40; n++ {
		marks := make([]string, n)
		for i := range marks {
			marks[i] = "?"
		}
		got := rewritePlaceholders("INSERT INTO t VALUES (" + strings.Join(marks, ",") + ")")
		for i := 1; i <= n; i++ {
			want := fmt.Sprintf("$%d", i)
			if !strings.Contains(got, want) {
				t.Fatalf("n=%d: rewritten statement missing %s: %s", n, want, got)
			}
		}
		if strings.Contains(got, fmt.Sprintf("$%d", n+1)) {
			t.Fatalf("n=%d: rewritten statement has a surplus $%d: %s", n, n+1, got)
		}
		if strings.Contains(got, "?") {
			t.Fatalf("n=%d: rewritten statement still contains a placeholder: %s", n, got)
		}
	}
}

// Rewriting is applied on every execution, so it must not be quadratic or
// allocate wildly on the large statements in the admin panel.
func BenchmarkRewritePlaceholders(b *testing.B) {
	q := "SELECT a, b, c FROM t WHERE x = ? AND y = ? AND z IN (?,?,?,?,?) ORDER BY a LIMIT ?"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = rewritePlaceholders(q)
	}
}

func TestDollarTag(t *testing.T) {
	cases := []struct {
		in    string
		tag   string
		valid bool
	}{
		{"$$body$$", "$$", true},
		{"$tag$body$tag$", "$tag$", true},
		{"$a1$x$a1$", "$a1$", true},
		{"$1", "", false},   // positional parameter, not a tag
		{"$ ", "", false},   // not a tag
		{"", "", false},     // empty
		{"nope", "", false}, // does not start with $
	}
	for _, tc := range cases {
		tag, ok := dollarTag(tc.in)
		if ok != tc.valid || tag != tc.tag {
			t.Errorf("dollarTag(%q) = (%q, %v), want (%q, %v)", tc.in, tag, ok, tc.tag, tc.valid)
		}
	}
}
