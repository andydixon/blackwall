package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSONAPIErrorHidesInternalDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	jsonAPIError(recorder, http.StatusInternalServerError, "database_error", "dial tcp 10.0.0.2:3306")

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["message"] != "internal server error" {
		t.Fatalf("unexpected message: %q", body["message"])
	}
}

func TestSCIMErrorHidesInternalDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	scimError(recorder, http.StatusInternalServerError, "sql: connection refused", "")

	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["detail"] != "internal server error" {
		t.Fatalf("unexpected detail: %q", body["detail"])
	}
}
