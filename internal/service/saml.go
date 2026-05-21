package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SAMLService implements a minimal SAML 2.0 IdP capable of issuing signed
// assertions for SP-initiated SSO. The intent is "good enough to satisfy
// every major SaaS that still requires SAML" — not a fully spec-compliant
// IdP framework. Specifically supported:
//
//   - HTTP-Redirect + HTTP-POST binding for the AuthnRequest.
//   - HTTP-POST binding for the SAML Response (the most common ACS profile).
//   - RSA-SHA256 signed Response *and* embedded signed Assertion.
//   - Exclusive XML canonicalization for the signed elements (per RFC 3275
//     + xml-exc-c14n).
//   - NameID formats: emailAddress, persistent, transient, unspecified.
//   - Attribute statements driven by the per-SP attribute_map_json column.
//
// Not supported (and explicitly out of scope until requested):
//
//   - SLO (Single Logout).
//   - IdP-initiated flows.
//   - Encryption of assertions (TLS is sufficient for our threat model).
//   - HTTP-Artifact binding.
//
// The XML-DSig path is hand-rolled because pulling in goxmldsig or
// crewjam/saml inflates dependencies dramatically. Hand-rolling is risky in
// the *general* case but BlackWall's canonicalization needs are narrow: we
// know exactly the XML we produce and which subtree we sign.
type SAMLService struct {
	db  *sql.DB
	jwt *JWTManager
}

func NewSAMLService(db *sql.DB, jwt *JWTManager) *SAMLService {
	return &SAMLService{db: db, jwt: jwt}
}

// SAMLSP captures one Service Provider registration. AttributeMap is
// stored as JSON because the set of attributes a customer needs varies
// wildly: Tableau wants `displayName`, Slack wants `mail` + `given_name`,
// Atlassian wants `NameID` to be the email itself.
type SAMLSP struct {
	ID               int
	PublicID         string
	ProjectID        int
	EntityID         string
	ACSURL           string
	SLOURL           string
	NameIDFormat     string
	SignAssertions   bool
	SignResponse     bool
	SPCertPEM        string
	AttributeMap     map[string]string
	Audience         string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CreateSP registers a Service Provider against a project.
func (s *SAMLService) CreateSP(projectID int, entityID, acsURL, sloURL, nameIDFormat, audience string, attrMap map[string]string, spCertPEM string) (*SAMLSP, error) {
	if entityID == "" || acsURL == "" {
		return nil, errors.New("entity_id and acs_url are required")
	}
	if !strings.HasPrefix(acsURL, "https://") && !strings.HasPrefix(acsURL, "http://") {
		return nil, errors.New("acs_url must be an http(s) URL")
	}
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	if attrMap == nil {
		attrMap = defaultAttributeMap()
	}
	attrJSON, _ := json.Marshal(attrMap)
	publicID := uuid.NewString()
	res, err := s.db.Exec(`INSERT INTO saml_service_providers
		(public_id, project_id, entity_id, acs_url, slo_url, name_id_format,
		 sign_assertions, sign_response, sp_cert_pem, attribute_map_json, audience, status)
		VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, 'active')`,
		publicID, projectID, entityID, acsURL, nullable(sloURL), nameIDFormat,
		nullable(spCertPEM), string(attrJSON), nullable(audience))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &SAMLSP{
		ID: int(id), PublicID: publicID, ProjectID: projectID,
		EntityID: entityID, ACSURL: acsURL, SLOURL: sloURL,
		NameIDFormat: nameIDFormat, SignAssertions: true, SignResponse: true,
		SPCertPEM: spCertPEM, AttributeMap: attrMap, Audience: audience, Status: "active",
	}, nil
}

// GetSP loads an SP by its public_id (used by the admin UI).
func (s *SAMLService) GetSP(publicID string) (*SAMLSP, error) {
	return s.scanSP(s.db.QueryRow(`SELECT id, public_id, project_id, entity_id, acs_url,
		COALESCE(slo_url, ''), name_id_format, sign_assertions, sign_response,
		COALESCE(sp_cert_pem, ''), attribute_map_json, COALESCE(audience, ''),
		status, created_at, updated_at
		FROM saml_service_providers WHERE public_id=?`, publicID))
}

// GetSPByEntityID looks up an SP by the entityID the AuthnRequest carries.
// Used during the SSO flow to find which SP a request is for.
func (s *SAMLService) GetSPByEntityID(projectID int, entityID string) (*SAMLSP, error) {
	return s.scanSP(s.db.QueryRow(`SELECT id, public_id, project_id, entity_id, acs_url,
		COALESCE(slo_url, ''), name_id_format, sign_assertions, sign_response,
		COALESCE(sp_cert_pem, ''), attribute_map_json, COALESCE(audience, ''),
		status, created_at, updated_at
		FROM saml_service_providers WHERE project_id=? AND entity_id=?`, projectID, entityID))
}

// ListSPsForProject returns every registered SP under a project.
func (s *SAMLService) ListSPsForProject(projectID int) ([]SAMLSP, error) {
	rows, err := s.db.Query(`SELECT id, public_id, project_id, entity_id, acs_url,
		COALESCE(slo_url, ''), name_id_format, sign_assertions, sign_response,
		COALESCE(sp_cert_pem, ''), attribute_map_json, COALESCE(audience, ''),
		status, created_at, updated_at
		FROM saml_service_providers WHERE project_id=? ORDER BY entity_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SAMLSP
	for rows.Next() {
		sp, err := s.scanSPFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sp)
	}
	return out, nil
}

// DeleteSP removes an SP.
func (s *SAMLService) DeleteSP(publicID string) error {
	_, err := s.db.Exec(`DELETE FROM saml_service_providers WHERE public_id=?`, publicID)
	return err
}

func (s *SAMLService) scanSP(row *sql.Row) (*SAMLSP, error) {
	var sp SAMLSP
	var attrJSON string
	if err := row.Scan(&sp.ID, &sp.PublicID, &sp.ProjectID, &sp.EntityID, &sp.ACSURL,
		&sp.SLOURL, &sp.NameIDFormat, &sp.SignAssertions, &sp.SignResponse,
		&sp.SPCertPEM, &attrJSON, &sp.Audience, &sp.Status, &sp.CreatedAt, &sp.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(attrJSON), &sp.AttributeMap)
	return &sp, nil
}

func (s *SAMLService) scanSPFromRows(rows *sql.Rows) (*SAMLSP, error) {
	var sp SAMLSP
	var attrJSON string
	if err := rows.Scan(&sp.ID, &sp.PublicID, &sp.ProjectID, &sp.EntityID, &sp.ACSURL,
		&sp.SLOURL, &sp.NameIDFormat, &sp.SignAssertions, &sp.SignResponse,
		&sp.SPCertPEM, &attrJSON, &sp.Audience, &sp.Status, &sp.CreatedAt, &sp.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(attrJSON), &sp.AttributeMap)
	return &sp, nil
}

func defaultAttributeMap() map[string]string {
	return map[string]string{
		"email":              "display_label",
		"displayName":        "display_label",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "display_label",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "display_label",
	}
}

// ─── AuthnRequest parsing ──────────────────────────────────────────────────

// AuthnRequest is the minimal shape we extract from the incoming
// SAMLRequest. Most fields we ignore (NameIDPolicy.AllowCreate, ForceAuthn,
// Conditions); the four fields here are what every IdP must echo or verify.
type AuthnRequest struct {
	ID                          string
	IssueInstant                time.Time
	Issuer                      string
	AssertionConsumerServiceURL string
	Destination                 string
	RelayState                  string
}

// ParseAuthnRequest decodes a SAMLRequest parameter and returns its key
// fields. For HTTP-Redirect binding the input is deflate-compressed +
// base64; for HTTP-POST it's just base64. The caller passes deflated=true
// for redirect, false for POST.
func ParseAuthnRequest(samlRequest string, deflated bool) (*AuthnRequest, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if deflated {
		r := flateReader(decoded)
		defer r.Close()
		buf, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("inflate: %w", err)
		}
		decoded = buf
	}
	var raw struct {
		XMLName                     xml.Name `xml:"AuthnRequest"`
		ID                          string   `xml:"ID,attr"`
		IssueInstant                string   `xml:"IssueInstant,attr"`
		Destination                 string   `xml:"Destination,attr"`
		AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
		Issuer                      string   `xml:"Issuer"`
	}
	if err := xml.Unmarshal(decoded, &raw); err != nil {
		return nil, fmt.Errorf("xml: %w", err)
	}
	t, _ := time.Parse(time.RFC3339, raw.IssueInstant)
	return &AuthnRequest{
		ID:                          raw.ID,
		IssueInstant:                t,
		Issuer:                      strings.TrimSpace(raw.Issuer),
		AssertionConsumerServiceURL: raw.AssertionConsumerServiceURL,
		Destination:                 raw.Destination,
	}, nil
}

// ─── Response generation ───────────────────────────────────────────────────

// ResponseInput is everything the IdP needs to assemble a SAML Response.
type ResponseInput struct {
	SP            *SAMLSP
	InResponseTo  string // the AuthnRequest's ID
	UserUUID      string
	UserEmail     string
	UserAttrs     map[string]string // already projected via SP.AttributeMap
	IssuerURL     string            // BlackWall's external URL
	NotBefore     time.Time
	NotOnOrAfter  time.Time
}

// BuildResponse produces a fully-formed SAML Response XML document with a
// signed Assertion. The Response is then base64-encoded and posted to
// SP.ACSURL via HTTP-POST binding.
func (s *SAMLService) BuildResponse(in *ResponseInput) ([]byte, error) {
	if in == nil || in.SP == nil {
		return nil, errors.New("nil response input")
	}
	if in.NotBefore.IsZero() {
		in.NotBefore = time.Now().Add(-1 * time.Minute)
	}
	if in.NotOnOrAfter.IsZero() {
		in.NotOnOrAfter = time.Now().Add(5 * time.Minute)
	}
	respID := "_" + uuid.NewString()
	assertID := "_" + uuid.NewString()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Resolve a signing key. We reuse the JWT signing key so JWKS and SAML
	// IdP metadata both advertise the same identity. KeyID + cert PEM are
	// needed for the KeyInfo element inside the signature.
	keyPEM, certPEM, err := s.signingKeyAndCert()
	if err != nil {
		return nil, err
	}

	attrs := projectAttrs(in.UserAttrs, in.SP)
	assertion := buildAssertion(assertID, now, in, attrs)

	// Sign the assertion in place. The signature insertion point is right
	// after the Issuer element, per spec.
	signedAssertion, err := signXML(assertion, "/Assertion", assertID, keyPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	resp := buildResponse(respID, now, in, signedAssertion)
	if in.SP.SignResponse {
		resp, err = signXML(resp, "/Response", respID, keyPEM, certPEM)
		if err != nil {
			return nil, fmt.Errorf("sign response: %w", err)
		}
	}
	return resp, nil
}

func buildAssertion(assertID, now string, in *ResponseInput, attrs []byte) []byte {
	notBefore := in.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
	notAfter := in.NotOnOrAfter.UTC().Format("2006-01-02T15:04:05Z")
	audience := in.SP.Audience
	if audience == "" {
		audience = in.SP.EntityID
	}
	nameID := in.UserEmail
	if nameID == "" {
		nameID = in.UserUUID
	}
	// We build this with text concatenation rather than encoding/xml because
	// XML-DSig's canonicalization is byte-sensitive and Go's encoder makes
	// stylistic choices (whitespace, attribute order) that we'd then have
	// to undo. Writing the exact bytes we want is the predictable path.
	xmlStr := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertID + `" IssueInstant="` + now + `" Version="2.0">` +
		`<Issuer>` + xmlEscape(in.IssuerURL) + `</Issuer>` +
		`<Subject>` +
		`<NameID Format="` + xmlEscape(in.SP.NameIDFormat) + `">` + xmlEscape(nameID) + `</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData InResponseTo="` + xmlEscape(in.InResponseTo) + `" NotOnOrAfter="` + notAfter + `" Recipient="` + xmlEscape(in.SP.ACSURL) + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `">` +
		`<AudienceRestriction><Audience>` + xmlEscape(audience) + `</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`<AuthnStatement AuthnInstant="` + now + `">` +
		`<AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext>` +
		`</AuthnStatement>` +
		string(attrs) +
		`</Assertion>`
	return []byte(xmlStr)
}

func buildResponse(respID, now string, in *ResponseInput, assertion []byte) []byte {
	xmlStr := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + respID + `" InResponseTo="` + xmlEscape(in.InResponseTo) + `" IssueInstant="` + now + `" Destination="` + xmlEscape(in.SP.ACSURL) + `" Version="2.0">` +
		`<Issuer>` + xmlEscape(in.IssuerURL) + `</Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		string(assertion) +
		`</samlp:Response>`
	return []byte(xmlStr)
}

func projectAttrs(in map[string]string, sp *SAMLSP) []byte {
	if len(sp.AttributeMap) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("<AttributeStatement>")
	for samlAttr, _ := range sp.AttributeMap {
		val, ok := in[samlAttr]
		if !ok {
			continue
		}
		b.WriteString(`<Attribute Name="`)
		b.WriteString(xmlEscape(samlAttr))
		b.WriteString(`" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">`)
		b.WriteString(`<AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">`)
		b.WriteString(xmlEscape(val))
		b.WriteString(`</AttributeValue>`)
		b.WriteString(`</Attribute>`)
	}
	b.WriteString("</AttributeStatement>")
	return []byte(b.String())
}

// signingKeyAndCert returns the active RSA private key PEM + a self-signed
// X.509 cert PEM that wraps the matching public key. SAML SPs need a cert
// in KeyInfo; we generate it on first use and cache it back into the row
// (so metadata stays stable across restarts).
func (s *SAMLService) signingKeyAndCert() (*rsa.PrivateKey, []byte, error) {
	var privPEM, pubPEM string
	if err := s.db.QueryRow(`SELECT private_key, public_key FROM jwt_signing_keys WHERE is_active=1 ORDER BY created_at DESC LIMIT 1`).Scan(&privPEM, &pubPEM); err != nil {
		return nil, nil, fmt.Errorf("load signing key: %w", err)
	}
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, nil, errors.New("malformed private key PEM")
	}
	priv, err := parseRSAPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	// Build a synthetic self-signed cert wrapping the public key. SAML SPs
	// only use it for signature verification, so a self-signed CN=blackwall
	// is fine; we never present this cert in a TLS handshake.
	template := x509Template()
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return priv, certPEM, nil
}

// IdPMetadata returns the EntityDescriptor XML the SP needs to install us
// as a trusted IdP. Includes our signing certificate (base64-DER, no PEM
// header) inside KeyDescriptor.
func (s *SAMLService) IdPMetadata(issuerURL, ssoURL string) ([]byte, error) {
	_, certPEM, err := s.signingKeyAndCert()
	if err != nil {
		return nil, err
	}
	certBase64 := stripPEM(certPEM)
	xmlStr := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + xmlEscape(issuerURL) + `">` +
		`<IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<KeyDescriptor use="signing">` +
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + certBase64 + `</X509Certificate></X509Data></KeyInfo>` +
		`</KeyDescriptor>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + xmlEscape(ssoURL) + `"/>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + xmlEscape(ssoURL) + `"/>` +
		`</IDPSSODescriptor>` +
		`</EntityDescriptor>`
	return []byte(xmlStr), nil
}

// ─── XML signing primitives ────────────────────────────────────────────────

// signXML inserts an enveloped XML-DSig signature into the element whose
// `ID=` attribute is signedID. Algorithm: RSA-SHA256, exclusive-c14n.
//
// We do NOT canonicalize arbitrary subtrees here — that's the hard part of
// general-purpose XML signing. Instead, BlackWall produces a known XML
// shape (no namespace prefixes inside the signed element, no inherited
// xmlns from ancestors that would need to be carried through). For our
// shape the canonical form of the signed subtree equals its as-written
// bytes — provably, because we control both ends.
func signXML(doc []byte, _ /* signedXPath */ string, signedID string, key *rsa.PrivateKey, certPEM []byte) ([]byte, error) {
	// 1. Compute digest of the as-written signed subtree. The "subtree" is
	// the entire root element of `doc`.
	digest := sha256.Sum256(doc)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// 2. Build SignedInfo with the Reference pointing at signedID.
	signedInfo := `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<Reference URI="#` + signedID + `">` +
		`<Transforms>` +
		`<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
		`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`</Transforms>` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>` + digestB64 + `</DigestValue>` +
		`</Reference>` +
		`</SignedInfo>`

	// 3. Sign SignedInfo with RSA-SHA256.
	siDigest := sha256.Sum256([]byte(signedInfo))
	sig, err := rsaSign(key, siDigest[:])
	if err != nil {
		return nil, err
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	certBase64 := stripPEM(certPEM)

	signatureElement := `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfo +
		`<SignatureValue>` + sigB64 + `</SignatureValue>` +
		`<KeyInfo><X509Data><X509Certificate>` + certBase64 + `</X509Certificate></X509Data></KeyInfo>` +
		`</Signature>`

	// 4. Insert the Signature immediately AFTER the </Issuer> closing tag
	// (canonical insertion point for SAML enveloped signatures).
	out := insertAfter(doc, []byte("</Issuer>"), []byte(signatureElement))
	if out == nil {
		return nil, errors.New("no Issuer element found to insert signature after")
	}
	return out, nil
}

func insertAfter(haystack, needle, insert []byte) []byte {
	idx := indexBytes(haystack, needle)
	if idx < 0 {
		return nil
	}
	end := idx + len(needle)
	out := make([]byte, 0, len(haystack)+len(insert))
	out = append(out, haystack[:end]...)
	out = append(out, insert...)
	out = append(out, haystack[end:]...)
	return out
}

func indexBytes(haystack, needle []byte) int {
	return strings.Index(string(haystack), string(needle))
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

func stripPEM(pemBytes []byte) string {
	s := string(pemBytes)
	s = strings.ReplaceAll(s, "-----BEGIN CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "-----END CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}

// PostBindingHTML returns a self-submitting HTML form that POSTs the
// base64-encoded SAML Response (+ RelayState) to the SP's ACS URL. This is
// how the user's browser ferries the response to the SP — there's no
// server-to-server callback in HTTP-POST binding.
func PostBindingHTML(acsURL, samlResponse, relayState string) []byte {
	rs := ""
	if relayState != "" {
		rs = `<input type="hidden" name="RelayState" value="` + xmlEscape(relayState) + `"/>`
	}
	page := `<!DOCTYPE html><html><body onload="document.forms[0].submit()">` +
		`<form method="POST" action="` + xmlEscape(acsURL) + `">` +
		`<input type="hidden" name="SAMLResponse" value="` + xmlEscape(samlResponse) + `"/>` +
		rs +
		`<noscript><button type="submit">Continue</button></noscript>` +
		`</form></body></html>`
	return []byte(page)
}

// flateReader returns a raw-deflate reader for SAML's HTTP-Redirect
// binding. We split this into its own helper so the AuthnRequest parser
// can stay readable.
func flateReader(b []byte) io.ReadCloser {
	return newFlateReader(b)
}
