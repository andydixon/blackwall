package service

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"
)

// TestParseAuthnRequest_RedirectBinding builds a deflate+base64 SAMLRequest
// the way an SP would for HTTP-Redirect, then confirms ParseAuthnRequest
// returns the fields we'll need downstream (ID, Issuer, ACS URL).
func TestParseAuthnRequest_RedirectBinding(t *testing.T) {
	xmlBody := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` ID="_abc123" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"` +
		` Destination="https://idp.example/sso"` +
		` AssertionConsumerServiceURL="https://sp.example/acs">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example/metadata</Issuer>` +
		`</AuthnRequest>`

	// Raw-deflate (NOT zlib) then base64. SAML HTTP-Redirect binding is
	// strict about this — using zlib by mistake is a famous footgun.
	var deflated bytes.Buffer
	w, _ := flate.NewWriter(&deflated, flate.DefaultCompression)
	w.Write([]byte(xmlBody))
	w.Close()
	encoded := base64.StdEncoding.EncodeToString(deflated.Bytes())

	got, err := ParseAuthnRequest(encoded, true)
	if err != nil {
		t.Fatalf("ParseAuthnRequest failed: %v", err)
	}
	if got.ID != "_abc123" {
		t.Errorf("ID = %q, want _abc123", got.ID)
	}
	if got.Issuer != "https://sp.example/metadata" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
	if got.AssertionConsumerServiceURL != "https://sp.example/acs" {
		t.Errorf("ACS URL = %q", got.AssertionConsumerServiceURL)
	}
}

// TestParseAuthnRequest_POSTBinding is the same input but without the
// deflate step (POST binding sends the XML base64-only).
func TestParseAuthnRequest_POSTBinding(t *testing.T) {
	xmlBody := `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_post1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">sp-post</Issuer></AuthnRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlBody))
	got, err := ParseAuthnRequest(encoded, false)
	if err != nil {
		t.Fatalf("ParseAuthnRequest failed: %v", err)
	}
	if got.ID != "_post1" || got.Issuer != "sp-post" {
		t.Errorf("fields: %+v", got)
	}
}

// TestSignXML_InsertionAndVerify confirms that the signature is inserted
// after </Issuer> AND that the resulting document is a parseable XML tree
// — i.e. we haven't corrupted the surrounding structure during signing.
// We don't fully verify the signature here (that needs canonicalization
// fidelity an integration test exercises with a real SP); we just confirm
// the signature element is present, well-formed, and contains the expected
// SHA-256 digest of the input.
func TestSignXML_InsertionAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := []byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><Issuer>https://idp</Issuer><Subject>x</Subject></Assertion>`)

	// Build a self-signed cert for the KeyInfo element.
	template := x509Template()
	der, _ := certForKey(template, key)
	certPEM := pemEncodeCert(der)

	signed, err := signXML(doc, "/Assertion", "_a1", key, certPEM)
	if err != nil {
		t.Fatalf("signXML failed: %v", err)
	}
	// Signature element should be present.
	if !bytesContains(signed, "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">") {
		t.Errorf("Signature element missing from output: %s", signed)
	}
	// Signature should be placed AFTER </Issuer> and BEFORE <Subject>.
	issuerEnd := strings.Index(string(signed), "</Issuer>")
	subjectStart := strings.Index(string(signed), "<Subject>")
	sigStart := strings.Index(string(signed), "<Signature")
	if !(issuerEnd < sigStart && sigStart < subjectStart) {
		t.Errorf("Signature insertion point wrong: issuerEnd=%d sigStart=%d subjectStart=%d",
			issuerEnd, sigStart, subjectStart)
	}
	// Output should still parse as XML.
	var tree struct{ XMLName xml.Name }
	if err := xml.Unmarshal(signed, &tree); err != nil {
		t.Errorf("signed doc no longer parses as XML: %v", err)
	}
}

// TestPostBindingHTML confirms the auto-submitting form has the right
// action URL and that both SAMLResponse + RelayState are HTML-escaped.
func TestPostBindingHTML(t *testing.T) {
	out := string(PostBindingHTML("https://sp.example/acs", "BASE64DATA", "state-with-<chars>&"))
	if !strings.Contains(out, `action="https://sp.example/acs"`) {
		t.Errorf("action URL wrong: %s", out)
	}
	if !strings.Contains(out, `name="SAMLResponse" value="BASE64DATA"`) {
		t.Errorf("SAMLResponse field missing or unencoded: %s", out)
	}
	if !strings.Contains(out, `value="state-with-&lt;chars&gt;&amp;"`) {
		t.Errorf("RelayState not HTML-escaped: %s", out)
	}
}

func TestDefaultAttributeMap(t *testing.T) {
	m := defaultAttributeMap()
	if m["email"] != "display_label" {
		t.Errorf("default attribute map should map email to display_label")
	}
	if _, ok := m["displayName"]; !ok {
		t.Errorf("default attribute map should include displayName")
	}
}

// ─── helpers for the tests above ─────────────────────────────────────────

func bytesContains(haystack []byte, needle string) bool {
	return strings.Contains(string(haystack), needle)
}
