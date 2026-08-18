package service

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

// BrandingService resolves the per-organisation branding overlay that the
// login surface uses (logo, primary colour, custom login message, support
// email). Lookups happen by either the org's UUID/slug or by an inbound HTTP
// Host header that's been associated with the org via org_custom_domains.
//
// Defaults are returned when nothing is configured — the login page always
// renders with at least the platform-default brand, never with an empty UI.
type BrandingService struct {
	db *sql.DB
}

func NewBrandingService(db *sql.DB) *BrandingService {
	return &BrandingService{db: db}
}

// Branding is the resolved set of fields the templates consume. Empty strings
// signal "fall back to the platform default" and the templates check for that.
type Branding struct {
	OrganizationID int
	OrgUUID        string
	OrgName        string
	LogoURL        string
	PrimaryColor   string
	LoginMessage   string
	SupportEmail   string
}

// HostMatchesCustomDomain returns the resolved branding if the inbound HTTP
// host has been registered + verified as a custom domain for an organisation.
// Returns nil, nil when no match — the caller falls back to default branding.
func (s *BrandingService) HostMatchesCustomDomain(host string) (*Branding, error) {
	host = normaliseHost(host)
	if host == "" {
		return nil, nil
	}
	var orgID int
	err := s.db.QueryRow(`SELECT organization_id FROM org_custom_domains
		WHERE hostname=? AND verified=TRUE`, host).Scan(&orgID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetForOrg(orgID)
}

// GetForOrg returns the branding overlay for the organisation by internal ID.
// All branding columns are nullable; we coalesce to empty strings so the
// templates can use a simple `{{if .LogoURL}}` check.
func (s *BrandingService) GetForOrg(orgID int) (*Branding, error) {
	if orgID <= 0 {
		return nil, errors.New("organization_id required")
	}
	var b Branding
	var logo, color, msg, email sql.NullString
	err := s.db.QueryRow(`SELECT id, uuid, name, logo_url, primary_color, login_message, support_email
		FROM organizations WHERE id=?`, orgID).Scan(&b.OrganizationID, &b.OrgUUID, &b.OrgName, &logo, &color, &msg, &email)
	if err != nil {
		return nil, err
	}
	b.LogoURL = logo.String
	b.PrimaryColor = color.String
	b.LoginMessage = msg.String
	b.SupportEmail = email.String
	return &b, nil
}

// Update writes the branding overlay. Empty strings are stored as NULL so
// "clear this override" round-trips cleanly through the form.
func (s *BrandingService) Update(orgID int, logoURL, primaryColor, loginMessage, supportEmail string) error {
	if orgID <= 0 {
		return errors.New("organization_id required")
	}
	if logoURL != "" && !isHTTPURL(logoURL) {
		return errors.New("logo_url must be an http(s) URL")
	}
	if primaryColor != "" && !isHexColor(primaryColor) {
		return errors.New("primary_color must be a #RRGGBB hex string")
	}
	if len(loginMessage) > 2048 {
		return errors.New("login_message must be 2048 bytes or fewer")
	}
	_, err := s.db.Exec(`UPDATE organizations
		SET logo_url=?, primary_color=?, login_message=?, support_email=?
		WHERE id=?`,
		nullable(logoURL), nullable(primaryColor), nullable(loginMessage), nullable(supportEmail), orgID)
	return err
}

// AddCustomDomain registers a new hostname against the organisation. Returns
// an error if the host is already mapped (UNIQUE constraint on hostname).
// The hostname is stored verified=0; an out-of-band verification flow (TXT
// record check, or manual admin approval) flips it to verified=1.
func (s *BrandingService) AddCustomDomain(orgID int, host string) error {
	host = normaliseHost(host)
	if !isValidHostname(host) {
		return errors.New("invalid hostname")
	}
	_, err := s.db.Exec(`INSERT INTO org_custom_domains (organization_id, hostname, verified)
		VALUES (?, ?, FALSE)`, orgID, host)
	return err
}

// VerifyCustomDomain flips an org's domain row to verified=1. In production
// this would be gated on a DNS TXT-record challenge; admins can also flip it
// manually after confirming DNS is in place.
func (s *BrandingService) VerifyCustomDomain(orgID int, host string) error {
	host = normaliseHost(host)
	_, err := s.db.Exec(`UPDATE org_custom_domains SET verified=TRUE WHERE organization_id=? AND hostname=?`, orgID, host)
	return err
}

// DeleteCustomDomain removes a host mapping. Login traffic on that host
// reverts to default-domain handling on the next request.
func (s *BrandingService) DeleteCustomDomain(orgID int, host string) error {
	host = normaliseHost(host)
	_, err := s.db.Exec(`DELETE FROM org_custom_domains WHERE organization_id=? AND hostname=?`, orgID, host)
	return err
}

// ListCustomDomains returns every host associated with an org.
func (s *BrandingService) ListCustomDomains(orgID int) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`SELECT hostname, verified, created_at
		FROM org_custom_domains WHERE organization_id=? ORDER BY hostname`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var host string
		var verified bool
		var createdAt string
		if err := rows.Scan(&host, &verified, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"hostname":   host,
			"verified":   verified,
			"created_at": createdAt,
		})
	}
	return out, nil
}

var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func isValidHostname(h string) bool {
	if len(h) < 4 || len(h) > 253 {
		return false
	}
	return hostnameRE.MatchString(h)
}

func normaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	// Strip port suffix if present so admins can paste "example.com:8080"
	// without it silently never matching.
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

var hexColorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func isHexColor(s string) bool { return hexColorRE.MatchString(s) }
