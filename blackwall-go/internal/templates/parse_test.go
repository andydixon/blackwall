package templates

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"testing"
)

// TestAllAdminPagesParse confirms every embedded admin template parses cleanly
// when paired with the templates AdminPage/AdminDocsPage would load it with.
// This catches `{{...}}` syntax errors at test time rather than at runtime.
//
// We deliberately don't *execute* the templates here — that would require
// constructing dummy data shaped like every handler's output, which is a
// maintenance burden for diminishing return. Syntax errors are the bulk of
// the bugs we want caught early; data-shape mismatches will surface during
// actual handler exercise.
func TestAllAdminPagesParse(t *testing.T) {
	skip := map[string]bool{
		// layout.html and docs.html are chrome — they're parsed alongside
		// page templates by the helpers, never alone.
		"web/templates/admin/layout.html": true,
		"web/templates/admin/docs.html":   true,
	}

	err := fs.WalkDir(templateFS, "web/templates/admin", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".html") || skip[path] {
			return nil
		}

		t.Run(path, func(t *testing.T) {
			files := []string{"web/templates/admin/layout.html", path}
			if strings.HasPrefix(path, "web/templates/admin/docs/") {
				files = []string{
					"web/templates/admin/layout.html",
					"web/templates/admin/docs.html",
					path,
				}
			}
			if _, err := template.New("").Funcs(funcMap).ParseFS(templateFS, files...); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestStandalonePagesParse exercises templates rendered without admin chrome.
func TestStandalonePagesParse(t *testing.T) {
	err := fs.WalkDir(templateFS, "web/templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".html") {
			return nil
		}
		// Skip files inside admin/ — those are tested above.
		if strings.HasPrefix(path, "web/templates/admin/") {
			return nil
		}
		t.Run(path, func(t *testing.T) {
			if _, err := template.New("").Funcs(funcMap).ParseFS(templateFS, path); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestStandaloneRenders exercises the Standalone helper end-to-end with a
// trivial data shape so we catch regressions like the t.Templates()[0] bug
// (which made every standalone page error with `template: "" is an
// incomplete or empty template` because the empty root was being picked
// instead of the actual file).
func TestStandaloneRenders(t *testing.T) {
	// Files that don't reference any template variables are safe to render
	// with an empty data map; that's enough to validate the wiring.
	files := []string{"home.html", "error.html"}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			rec := &recordingResponseWriter{header: http.Header{}, status: 200}
			Standalone(rec, f, map[string]interface{}{
				"Title": "test",
				"Error": "",
			})
			if rec.status >= 500 {
				t.Fatalf("Standalone(%s) returned %d: %s", f, rec.status, rec.body.String())
			}
			if !bytes.Contains(rec.body.Bytes(), []byte("<html")) {
				t.Fatalf("Standalone(%s) produced no HTML body; got: %q", f, rec.body.String())
			}
		})
	}
}

// recordingResponseWriter is a minimal http.ResponseWriter so the test can
// assert on what Standalone wrote without spinning up a real server.
type recordingResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (r *recordingResponseWriter) Header() http.Header      { return r.header }
func (r *recordingResponseWriter) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recordingResponseWriter) WriteHeader(s int)        { r.status = s }
