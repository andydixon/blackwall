package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestBodyLimitRejectsKnownOversize(t *testing.T) {
	called := false
	h := RequestBodyLimit(4)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	if called {
		t.Fatal("oversized request reached handler")
	}
}

func TestRequestBodyLimitCapsStreamedBody(t *testing.T) {
	h := RequestBodyLimit(4)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected capped body read to fail")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}
