package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	verifyURL       = "https://blackwall.cx/licences/v1/verify"
	expectedIssuer  = "https://blackwall.cx"
	maximumLicence  = 16 * 1024
	maximumResponse = 64 * 1024
)

type verificationResponse struct {
	Valid     bool      `json:"valid"`
	Code      string    `json:"code"`
	CheckedAt time.Time `json:"checked_at"`
	Claims    *claims   `json:"claims"`
}

type claims struct {
	Version            int             `json:"v"`
	LicenceID          string          `json:"licence_id"`
	Issuer             string          `json:"iss"`
	Audience           string          `json:"aud"`
	ProjectUUID        string          `json:"project_uuid"`
	Entity             json.RawMessage `json:"entity"`
	Hostnames          []string        `json:"hostnames"`
	Features           []string        `json:"features"`
	MaxInstances       int             `json:"max_instances"`
	IssuedAt           int64           `json:"iat"`
	NotBefore          int64           `json:"nbf"`
	ExpiresAt          int64           `json:"exp"`
	KeyID              string          `json:"kid"`
	StatusURL          string          `json:"status_url"`
	OnlineCheckSeconds int             `json:"online_check_seconds"`
}

func main() {
	if len(os.Args) != 4 {
		fatal("usage: go run . <licence-file> <hostname> <project-uuid>")
	}
	licenceBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal("read licence: " + err.Error())
	}
	licence := strings.TrimSpace(string(licenceBytes))
	if len(licence) == 0 || len(licence) > maximumLicence {
		fatal("licence file is empty or too large")
	}
	hostname, err := normaliseHostname(os.Args[2])
	if err != nil {
		fatal(err.Error())
	}
	projectUUID := strings.ToLower(os.Args[3])

	body, err := json.Marshal(map[string]string{
		"licence": licence, "expected_hostname": hostname, "project_uuid": projectUUID,
	})
	if err != nil {
		fatal(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request) // Default transport verifies TLS and hostname.
	if err != nil {
		fatal("verification request failed: " + err.Error())
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maximumResponse+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil || len(responseBody) > maximumResponse {
		fatal("verification response was unreadable or too large")
	}
	if response.StatusCode != http.StatusOK {
		fatal(fmt.Sprintf("verification service returned HTTP %d", response.StatusCode))
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var result verificationResponse
	if err := decoder.Decode(&result); err != nil {
		fatal("invalid verification JSON: " + err.Error())
	}
	if err := requireJSONEOF(decoder); err != nil {
		fatal(err.Error())
	}
	if !result.Valid || result.Code != "valid" || result.Claims == nil {
		fatal("licence rejected: " + result.Code)
	}

	now := time.Now().UTC()
	c := result.Claims
	if result.CheckedAt.IsZero() || durationAbs(now.Sub(result.CheckedAt)) > 5*time.Minute ||
		c.Version != 1 || c.Issuer != expectedIssuer || c.Audience != "blackwall-licence" ||
		c.ProjectUUID != projectUUID || !contains(c.Hostnames, hostname) ||
		now.Add(2*time.Minute).Unix() < c.NotBefore || now.Add(-2*time.Minute).Unix() > c.ExpiresAt {
		fatal("verified response did not match the local policy")
	}
	fmt.Printf("valid licence %s\n", c.LicenceID)
}

func normaliseHostname(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "*/\\@?#%") {
		return "", errors.New("invalid hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(host, ":") {
		return "", errors.New("ports are not allowed in hostnames")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS hostname")
		}
		for _, char := range []byte(label) {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return "", errors.New("invalid DNS hostname")
			}
		}
	}
	return host, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("verification response contained trailing JSON")
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func durationAbs(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "invalid:", message)
	os.Exit(1)
}
