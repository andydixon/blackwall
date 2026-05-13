package templates

import (
	"bytes"
	"encoding/json"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
)

//go:embed all:web/templates
var templateFS embed.FS

//go:embed all:web/static
var staticFS embed.FS

// StaticHandler returns an http.Handler that serves embedded static files.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

var funcMap = template.FuncMap{
	"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	"json": func(v interface{}) template.JS {
		b, err := json.Marshal(v)
		if err != nil {
			return template.JS("null")
		}
		return template.JS(b)
	},
	"add":      func(a, b int) int { return a + b },
	"sub":      func(a, b int) int { return a - b },
	"plusOne":  func(a int) int { return a + 1 },
	"minusOne": func(a int) int { return a - 1 },
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n]
	},
	"shortHash": func(s string) string {
		if len(s) <= 8 {
			return s
		}
		return s[:8] + "…"
	},
	"humanBytes": func(n int64) string {
		const unit = 1024
		if n < unit {
			return fmt.Sprintf("%d B", n)
		}
		div, exp := int64(unit), 0
		for x := n / unit; x >= unit; x /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
	},
	"durationSeconds": func(s int) string {
		if s <= 0 {
			return "—"
		}
		if s < 60 {
			return fmt.Sprintf("%ds", s)
		}
		if s < 3600 {
			return fmt.Sprintf("%dm %ds", s/60, s%60)
		}
		return fmt.Sprintf("%dh %dm", s/3600, (s%3600)/60)
	},
}

// AdminPage renders an admin page with the layout and page content template.
// pageFile is relative to web/templates/admin/ e.g. "dashboard.html"
func AdminPage(w http.ResponseWriter, pageFile string, data interface{}) {
	t, err := template.New("").Funcs(funcMap).ParseFS(templateFS,
		"web/templates/admin/layout.html",
		"web/templates/admin/"+pageFile,
	)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "Render error: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// AdminDocsPage renders the docs guide layout with the supplied body partial
// loaded alongside. The body file should define a "doc_body" template; the
// docs.html chrome file defines the "content" template that wraps it.
func AdminDocsPage(w http.ResponseWriter, bodyFile string, data interface{}) {
	t, err := template.New("").Funcs(funcMap).ParseFS(templateFS,
		"web/templates/admin/layout.html",
		"web/templates/admin/docs.html",
		"web/templates/admin/"+bodyFile,
	)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "Render error: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// Standalone renders a standalone page (no admin layout).
// file is relative to web/templates/ e.g. "oauth/login.html".
//
// We must execute by NAME (the basename of the file) rather than by index
// into t.Templates(). The previous implementation grabbed t.Templates()[0],
// which is non-deterministic in Go's html/template and frequently picked
// the empty "" root created by template.New("") — producing the cryptic
// "template: \"\" is an incomplete or empty template" error at runtime.
func Standalone(w http.ResponseWriter, file string, data interface{}) {
	name := path.Base(file)
	t, err := template.New(name).Funcs(funcMap).ParseFS(templateFS, "web/templates/"+file)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "Render error: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}
