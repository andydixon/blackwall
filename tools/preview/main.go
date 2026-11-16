// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

// Command preview renders the public marketing pages to standalone HTML so
// they can be eyeballed in a browser without running the full server.
// This is a scratch development aid and is not part of the shipped product.
package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"blackwall/internal/templates"
)

type page struct {
	name     string
	template string
	nav      string
}

func main() {
	out, err := filepath.Abs(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		panic(err)
	}
	static, err := filepath.Abs("internal/templates/web/static")
	if err != nil {
		panic(err)
	}

	pages := []page{
		{"home", "home.html", "home"},
		{"platform", "platform.html", "platform"},
		{"identity", "features/passwordless-identity.html", "identity"},
		{"oauth", "features/oauth-and-oidc.html", "oauth"},
		{"licensing", "features/software-licensing.html", "licensing"},
		{"administration", "features/administration.html", "administration"},
		{"assurance", "features/audit-and-assurance.html", "assurance"},
		{"federation", "features/enterprise-federation.html", "federation"},
		{"cryptbin", "features/cryptbin.html", "cryptbin"},
	}

	prefix := "file://" + filepath.ToSlash(static) + "/"
	for _, p := range pages {
		rec := httptest.NewRecorder()
		templates.PublicPage(rec, p.template, map[string]interface{}{
			"Title": "BlackWall preview", "Description": "preview", "Nav": p.nav,
		})
		if rec.Code != 200 {
			panic(fmt.Sprintf("%s returned %d: %s", p.name, rec.Code, rec.Body.String()))
		}
		body := rec.Body.String()
		body = strings.ReplaceAll(body, `href="/assets/`, `href="`+prefix)
		body = strings.ReplaceAll(body, `src="/assets/`, `src="`+prefix)
		// The hero fills the viewport by design, which means a tall capture
		// window stretches it and pushes the rest of the page out of frame.
		// Neutralise it for previews only so whole-page review is possible.
		body = strings.Replace(body, "</head>",
			"<style>.hero{min-height:auto !important;padding:5rem 0 !important}</style></head>", 1)
		if err := os.WriteFile(filepath.Join(out, p.name+".html"), []byte(body), 0o644); err != nil {
			panic(err)
		}
	}
	fmt.Println("wrote", len(pages), "pages to", out)
}
