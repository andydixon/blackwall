// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maximumLicenceVerificationBody = 24 * 1024

// LicenceKeys publishes only Ed25519 public keys and their operational state.
// Private signing material and licensed entity records never cross this route.
func (h *AdminHandler) LicenceKeys(w http.ResponseWriter, r *http.Request) {
	if h.App.Licences == nil {
		writeLicenceJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "licence_service_unavailable",
		})
		return
	}
	keys, err := h.App.Licences.PublicKeys()
	if err != nil {
		writeLicenceJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "licence_key_registry_unavailable",
		})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	writeLicenceJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":    h.App.Licences.Issuer(),
		"algorithm": "Ed25519",
		"keys":      keys,
	})
}

// LicenceVerify is the authoritative online status check. A valid Ed25519
// signature is necessary but not sufficient: the service also enforces exact
// issuer, project, hostname, time, key state, database anchoring, and revocation.
func (h *AdminHandler) LicenceVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.App.Licences == nil {
		writeLicenceJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"valid": false, "code": "service_unavailable",
		})
		return
	}
	if h.App.RateLimit != nil && !h.App.RateLimit.Check("ip:"+getIP(r), "licence.verify", 120, 300) {
		w.Header().Set("Retry-After", "300")
		writeLicenceJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"valid": false, "code": "rate_limited",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maximumLicenceVerificationBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		Licence          string `json:"licence"`
		ExpectedHostname string `json:"expected_hostname"`
		ProjectUUID      string `json:"project_uuid"`
	}
	if err := decoder.Decode(&request); err != nil || ensureLicenceJSONEOF(decoder) != nil {
		writeLicenceJSON(w, http.StatusBadRequest, map[string]interface{}{
			"valid": false, "code": "invalid_request",
		})
		return
	}
	if strings.TrimSpace(request.Licence) == "" || strings.TrimSpace(request.ExpectedHostname) == "" || strings.TrimSpace(request.ProjectUUID) == "" {
		writeLicenceJSON(w, http.StatusBadRequest, map[string]interface{}{
			"valid": false, "code": "missing_required_field",
		})
		return
	}
	result := h.App.Licences.VerifyOnline(request.Licence, request.ExpectedHostname, request.ProjectUUID)
	writeLicenceJSON(w, http.StatusOK, result)
}

func ensureLicenceJSONEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errAdditionalJSONValue
		}
		return err
	}
	return nil
}

var errAdditionalJSONValue = errors.New("additional JSON value")

func writeLicenceJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
