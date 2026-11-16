// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AppEnv   string `yaml:"app_env"`
	AppDebug bool   `yaml:"app_debug"`
	AppURL   string `yaml:"app_url"`

	DBHost string `yaml:"db_host"`
	DBPort string `yaml:"db_port"`
	DBName string `yaml:"db_name"`
	DBUser string `yaml:"db_user"`
	DBPass string `yaml:"db_pass"`

	SessionName        string `yaml:"session_name"`
	SessionSecret      string `yaml:"session_secret"`
	SessionLifetime    int    `yaml:"session_lifetime"`
	SessionIdleTimeout int    `yaml:"session_idle_timeout"`
	SessionBindUA      bool   `yaml:"session_bind_user_agent"`

	CSRFSecret string `yaml:"csrf_secret"`

	CryptbinKEKBase64            string `yaml:"cryptbin_kek_base64"`
	CryptbinKEKVersion           string `yaml:"cryptbin_kek_version"`
	CryptbinStoragePath          string `yaml:"cryptbin_storage_path"`
	CryptbinMaxUploadBytes       int64  `yaml:"cryptbin_max_upload_bytes"`
	CryptbinMaxTextBytes         int64  `yaml:"cryptbin_max_text_bytes"`
	CryptbinAllowedMime          string `yaml:"cryptbin_allowed_mime"`
	CryptbinDefaultRetentionDays int    `yaml:"cryptbin_default_retention_days"`

	WebAuthnRPID    string `yaml:"webauthn_rp_id"`
	WebAuthnRPName  string `yaml:"webauthn_rp_name"`
	MinWebAuthnKeys int    `yaml:"min_webauthn_keys"`
	// Extra browser origins permitted to complete a WebAuthn ceremony, on top
	// of app_url. Comma-separated, scheme+host only (e.g.
	// "https://admin.blackwall.cx"). Needed when a reverse proxy fronts the
	// app on a second hostname: the browser reports its own origin in
	// clientDataJSON, which would otherwise fail the app_url comparison.
	// Every entry must sit under webauthn_rp_id, since credentials are scoped
	// to the RP ID and no other host could present them anyway.
	WebAuthnExtraOrigins string `yaml:"webauthn_extra_origins"`

	AdminSuperProjectName string `yaml:"admin_super_project_name"`
	AdminSuperProjectUUID string `yaml:"admin_super_project_uuid"`

	TrustProxy     bool   `yaml:"trust_proxy"`
	TrustedProxies string `yaml:"trusted_proxies"`

	RateLimitEnabled bool `yaml:"rate_limit_enabled"`

	AuditRetentionDays              int `yaml:"audit_retention_days"`
	ApprovalPendingMaxAgeDays       int `yaml:"approval_pending_max_age_days"`
	AdminMutationRateLimitAttempts  int `yaml:"admin_mutation_rate_limit_attempts"`
	AdminMutationRateLimitWindowSec int `yaml:"admin_mutation_rate_limit_window_seconds"`
	AdminApprovalPendingWarnDays    int `yaml:"admin_approval_pending_warning_days"`

	MetricsToken                   string `yaml:"metrics_token"`
	MetricsAllowUnauthenticated    bool   `yaml:"metrics_allow_unauthenticated"`
	EventMetricsPushEnabled        bool   `yaml:"event_metrics_push_enabled"`
	EventMetricsPushURL            string `yaml:"event_metrics_push_url"`
	EventMetricsPushMetricName     string `yaml:"event_metrics_push_metric_name"`
	EventMetricsPushTimeoutMs      int    `yaml:"event_metrics_push_timeout_ms"`
	EventMetricsPushIncludeOutcome bool   `yaml:"event_metrics_push_include_outcome"`
	EventMetricsPushStaticLabels   string `yaml:"event_metrics_push_static_labels"`

	ErrorTraceKey      string `yaml:"error_trace_key"`
	AuditExportSignKey string `yaml:"audit_export_signing_key"`

	// Licence signing uses a dedicated Ed25519 key held in a tightly
	// permissioned file. Keeping it separate from OAuth/JWT keys prevents
	// cross-protocol key reuse and lets operators rotate it independently.
	LicenceSigningKeyFile     string `yaml:"licence_signing_key_file"`
	LicenceMaxValidityDays    int    `yaml:"licence_max_validity_days"`
	LicenceClockSkewSeconds   int    `yaml:"licence_clock_skew_seconds"`
	LicenceOnlineCheckSeconds int    `yaml:"licence_online_check_seconds"`

	// Renewal reminders use a durable database queue and an authenticated,
	// encrypted SMTP connection. SMTP credentials are configuration secrets and
	// must be supplied through the deployment secret store rather than Git.
	LicenceRemindersEnabled        bool   `yaml:"licence_reminders_enabled"`
	LicenceReminderIntervalSeconds int    `yaml:"licence_reminder_interval_seconds"`
	SMTPHost                       string `yaml:"smtp_host"`
	SMTPPort                       int    `yaml:"smtp_port"`
	SMTPUsername                   string `yaml:"smtp_username"`
	SMTPPassword                   string `yaml:"smtp_password"`
	SMTPFromAddress                string `yaml:"smtp_from_address"`
	SMTPFromName                   string `yaml:"smtp_from_name"`
	SMTPTLSMode                    string `yaml:"smtp_tls_mode"`
	SMTPTimeoutSeconds             int    `yaml:"smtp_timeout_seconds"`

	ServerAddr          string `yaml:"server_addr"`
	RequestBodyMaxBytes int64  `yaml:"request_body_max_bytes"`
}

var global *Config

func Load(path string) (*Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parsing config file: %w", err)
			}
		}
	}

	overrideFromEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	global = cfg
	return cfg, nil
}

// Validate fails fast if a security-critical field is missing or too short.
// We treat short secrets as fatal because cookies and CSRF tokens depend on
// them; running with weak material is more dangerous than refusing to start.
func (c *Config) Validate() error {
	appURL, err := url.Parse(c.AppURL)
	if err != nil || appURL.Hostname() == "" || (appURL.Scheme != "http" && appURL.Scheme != "https") {
		return fmt.Errorf("config: app_url must be an absolute http(s) URL")
	}
	if appURL.User != nil || appURL.RawQuery != "" || appURL.Fragment != "" || (appURL.Path != "" && appURL.Path != "/") {
		return fmt.Errorf("config: app_url must contain only scheme and host")
	}
	if appURL.Scheme != "https" {
		host := strings.ToLower(strings.TrimSuffix(appURL.Hostname(), "."))
		ip := net.ParseIP(host)
		isLoopback := host == "localhost" || strings.HasSuffix(host, ".localhost") || (ip != nil && ip.IsLoopback())
		if strings.EqualFold(c.AppEnv, "production") || !isLoopback {
			return fmt.Errorf("config: app_url must use HTTPS except for loopback development addresses")
		}
	}
	c.AppURL = strings.TrimRight(c.AppURL, "/")
	if c.DBHost == "" || c.DBName == "" || c.DBUser == "" {
		return fmt.Errorf("config: db_host, db_name, db_user are required")
	}
	// 64 hex chars = 32 bytes of entropy, the minimum we want for both
	// session encryption and CSRF HMAC. Shorter values almost always mean
	// the operator forgot to fill the example placeholder.
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("config: session_secret must be at least 32 characters (use `openssl rand -hex 32`)")
	}
	if len(c.CSRFSecret) < 32 {
		return fmt.Errorf("config: csrf_secret must be at least 32 characters")
	}
	if c.SessionSecret == c.CSRFSecret {
		return fmt.Errorf("config: session_secret and csrf_secret must differ")
	}
	if c.SessionLifetime <= 0 {
		c.SessionLifetime = 7200
	}
	if c.SessionIdleTimeout <= 0 {
		c.SessionIdleTimeout = 1800
	}
	if c.CryptbinMaxUploadBytes <= 0 || c.CryptbinMaxTextBytes <= 0 {
		return fmt.Errorf("config: cryptbin size limits must be positive")
	}
	if c.RequestBodyMaxBytes <= 0 {
		c.RequestBodyMaxBytes = 8 * 1024 * 1024
	}
	requiredBodyBytes := c.CryptbinMaxUploadBytes + (c.CryptbinMaxUploadBytes+2)/3 + 64*1024
	if c.RequestBodyMaxBytes < requiredBodyBytes {
		return fmt.Errorf("config: request_body_max_bytes must be at least %d for cryptbin_max_upload_bytes=%d", requiredBodyBytes, c.CryptbinMaxUploadBytes)
	}
	if c.LicenceMaxValidityDays < 1 || c.LicenceMaxValidityDays > 3650 {
		return fmt.Errorf("config: licence_max_validity_days must be between 1 and 3650")
	}
	if c.LicenceClockSkewSeconds < 0 || c.LicenceClockSkewSeconds > 600 {
		return fmt.Errorf("config: licence_clock_skew_seconds must be between 0 and 600")
	}
	if c.LicenceOnlineCheckSeconds < 300 || c.LicenceOnlineCheckSeconds > 604800 {
		return fmt.Errorf("config: licence_online_check_seconds must be between 300 and 604800")
	}
	if c.LicenceReminderIntervalSeconds < 300 || c.LicenceReminderIntervalSeconds > 86400 {
		return fmt.Errorf("config: licence_reminder_interval_seconds must be between 300 and 86400")
	}
	if c.SMTPTimeoutSeconds < 1 || c.SMTPTimeoutSeconds > 60 {
		return fmt.Errorf("config: smtp_timeout_seconds must be between 1 and 60")
	}
	if c.LicenceRemindersEnabled {
		if err := c.validateReminderSMTP(); err != nil {
			return err
		}
	}
	if err := c.validateWebAuthnExtraOrigins(); err != nil {
		return err
	}
	return nil
}

// validateWebAuthnExtraOrigins rejects anything the browser could never
// legitimately present. Each entry has to be a bare https scheme+host that
// lives under webauthn_rp_id — a credential is bound to the RP ID, so an
// origin outside it can't hold one, and listing it would only ever widen the
// origin check for no gain.
func (c *Config) validateWebAuthnExtraOrigins() error {
	origins := splitList(c.WebAuthnExtraOrigins)
	if len(origins) == 0 {
		c.WebAuthnExtraOrigins = ""
		return nil
	}
	rpID := strings.ToLower(strings.TrimSuffix(c.WebAuthnRPID, "."))
	if rpID == "" {
		return fmt.Errorf("config: webauthn_extra_origins requires webauthn_rp_id (or app_url) to be set")
	}

	normalised := make([]string, 0, len(origins))
	for _, raw := range origins {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.Scheme != "https" {
			return fmt.Errorf("config: webauthn_extra_origins entry %q must be an absolute https URL", raw)
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("config: webauthn_extra_origins entry %q must contain only scheme and host", raw)
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("config: webauthn_extra_origins entry %q is not under webauthn_rp_id %q", raw, rpID)
		}
		normalised = append(normalised, u.Scheme+"://"+u.Host)
	}
	c.WebAuthnExtraOrigins = strings.Join(normalised, ",")
	return nil
}

// splitList turns a comma-separated config value into trimmed, non-empty
// entries.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) validateReminderSMTP() error {
	host := strings.TrimSpace(c.SMTPHost)
	if host == "" || strings.ContainsAny(host, "\r\n\t /:@[]") || !validSMTPHost(host) {
		return fmt.Errorf("config: smtp_host must be a hostname or IP address without a scheme or port")
	}
	if c.SMTPPort < 1 || c.SMTPPort > 65535 {
		return fmt.Errorf("config: smtp_port must be between 1 and 65535")
	}
	if c.SMTPTLSMode != "starttls" && c.SMTPTLSMode != "implicit" {
		return fmt.Errorf("config: smtp_tls_mode must be starttls or implicit")
	}
	if (c.SMTPUsername == "") != (c.SMTPPassword == "") {
		return fmt.Errorf("config: smtp_username and smtp_password must either both be set or both be blank")
	}
	if len(c.SMTPUsername) > 512 || len(c.SMTPPassword) > 4096 || len(c.SMTPFromName) > 200 || strings.ContainsAny(c.SMTPUsername+c.SMTPFromName, "\r\n") {
		return fmt.Errorf("config: SMTP identity fields are invalid")
	}
	from, err := mail.ParseAddress(strings.TrimSpace(c.SMTPFromAddress))
	if err != nil || from.Address == "" || !strings.EqualFold(from.Address, strings.TrimSpace(c.SMTPFromAddress)) {
		return fmt.Errorf("config: smtp_from_address must be one plain email address")
	}
	return nil
}

func validSMTPHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func Get() *Config {
	if global == nil {
		cfg := defaults()
		overrideFromEnv(cfg)
		global = cfg
	}
	return global
}

// Set replaces the process-global config. Intended for tests that need to
// pin specific values (e.g. AppURL) without spinning up the YAML loader.
// Production code should never call this; the boot path uses Load().
func Set(c *Config) {
	global = c
}

func defaults() *Config {
	return &Config{
		AppEnv:                          "production",
		AppDebug:                        false,
		AppURL:                          "https://localhost",
		DBHost:                          "localhost",
		DBPort:                          "3306",
		DBName:                          "blackwall",
		DBUser:                          "blackwall",
		DBPass:                          "",
		SessionName:                     "blackwall_session",
		SessionLifetime:                 7200,
		SessionIdleTimeout:              1800,
		SessionBindUA:                   true,
		CryptbinStoragePath:             "/var/lib/blackwall/cryptbin",
		CryptbinMaxUploadBytes:          5242880,
		CryptbinMaxTextBytes:            262144,
		CryptbinKEKVersion:              "v1",
		CryptbinDefaultRetentionDays:    0,
		WebAuthnRPName:                  "BlackWall OAuth",
		MinWebAuthnKeys:                 1,
		AdminSuperProjectName:           "BlackWall Admin",
		TrustProxy:                      false,
		RateLimitEnabled:                true,
		AuditRetentionDays:              180,
		ApprovalPendingMaxAgeDays:       14,
		AdminMutationRateLimitAttempts:  60,
		AdminMutationRateLimitWindowSec: 60,
		AdminApprovalPendingWarnDays:    3,
		EventMetricsPushMetricName:      "blackwall_event",
		EventMetricsPushTimeoutMs:       250,
		EventMetricsPushIncludeOutcome:  true,
		ServerAddr:                      ":8080",
		RequestBodyMaxBytes:             8 * 1024 * 1024,
		LicenceMaxValidityDays:          365,
		LicenceClockSkewSeconds:         120,
		LicenceOnlineCheckSeconds:       86400,
		LicenceReminderIntervalSeconds:  900,
		SMTPPort:                        587,
		SMTPFromName:                    "Blackwall",
		SMTPTLSMode:                     "starttls",
		SMTPTimeoutSeconds:              10,
	}
}

func overrideFromEnv(cfg *Config) {
	setStr := func(p *string, key string) {
		if v := os.Getenv(key); v != "" {
			*p = v
		}
	}
	setBool := func(p *bool, key string) {
		if v := os.Getenv(key); v != "" {
			*p = strings.EqualFold(v, "true") || v == "1"
		}
	}
	setInt := func(p *int, key string) {
		if v := os.Getenv(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*p = n
			}
		}
	}
	setInt64 := func(p *int64, key string) {
		if v := os.Getenv(key); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*p = n
			}
		}
	}

	setStr(&cfg.AppEnv, "APP_ENV")
	setBool(&cfg.AppDebug, "APP_DEBUG")
	setStr(&cfg.AppURL, "APP_URL")
	setStr(&cfg.DBHost, "DB_HOST")
	setStr(&cfg.DBPort, "DB_PORT")
	setStr(&cfg.DBName, "DB_NAME")
	setStr(&cfg.DBUser, "DB_USER")
	setStr(&cfg.DBPass, "DB_PASS")
	setStr(&cfg.SessionName, "SESSION_NAME")
	setStr(&cfg.SessionSecret, "SESSION_SECRET")
	setInt(&cfg.SessionLifetime, "SESSION_LIFETIME")
	setInt(&cfg.SessionIdleTimeout, "SESSION_IDLE_TIMEOUT")
	setBool(&cfg.SessionBindUA, "SESSION_BIND_USER_AGENT")
	setStr(&cfg.CSRFSecret, "CSRF_SECRET")
	setStr(&cfg.CryptbinKEKBase64, "CRYPTBIN_KEK_BASE64")
	setStr(&cfg.CryptbinKEKVersion, "CRYPTBIN_KEK_VERSION")
	setStr(&cfg.CryptbinStoragePath, "CRYPTBIN_STORAGE_PATH")
	setInt64(&cfg.CryptbinMaxUploadBytes, "CRYPTBIN_MAX_UPLOAD_BYTES")
	setInt64(&cfg.CryptbinMaxTextBytes, "CRYPTBIN_MAX_TEXT_BYTES")
	setStr(&cfg.CryptbinAllowedMime, "CRYPTBIN_ALLOWED_MIME")
	setInt(&cfg.CryptbinDefaultRetentionDays, "CRYPTBIN_DEFAULT_RETENTION_DAYS")
	setStr(&cfg.WebAuthnRPID, "WEBAUTHN_RP_ID")
	setStr(&cfg.WebAuthnRPName, "WEBAUTHN_RP_NAME")
	setStr(&cfg.WebAuthnExtraOrigins, "WEBAUTHN_EXTRA_ORIGINS")
	setInt(&cfg.MinWebAuthnKeys, "MIN_WEBAUTHN_KEYS")
	setStr(&cfg.AdminSuperProjectName, "ADMIN_SUPER_PROJECT_NAME")
	setStr(&cfg.AdminSuperProjectUUID, "ADMIN_SUPER_PROJECT_UUID")
	setBool(&cfg.TrustProxy, "TRUST_PROXY")
	setStr(&cfg.TrustedProxies, "TRUSTED_PROXIES")
	setBool(&cfg.RateLimitEnabled, "RATE_LIMIT_ENABLED")
	setInt(&cfg.AuditRetentionDays, "AUDIT_RETENTION_DAYS")
	setInt(&cfg.ApprovalPendingMaxAgeDays, "APPROVAL_PENDING_MAX_AGE_DAYS")
	setInt(&cfg.AdminMutationRateLimitAttempts, "ADMIN_MUTATION_RATE_LIMIT_ATTEMPTS")
	setInt(&cfg.AdminMutationRateLimitWindowSec, "ADMIN_MUTATION_RATE_LIMIT_WINDOW_SECONDS")
	setInt(&cfg.AdminApprovalPendingWarnDays, "ADMIN_APPROVAL_PENDING_WARNING_DAYS")
	setStr(&cfg.MetricsToken, "METRICS_TOKEN")
	setBool(&cfg.EventMetricsPushEnabled, "EVENT_METRICS_PUSH_ENABLED")
	setStr(&cfg.EventMetricsPushURL, "EVENT_METRICS_PUSH_URL")
	setStr(&cfg.EventMetricsPushMetricName, "EVENT_METRICS_PUSH_METRIC_NAME")
	setInt(&cfg.EventMetricsPushTimeoutMs, "EVENT_METRICS_PUSH_TIMEOUT_MS")
	setBool(&cfg.EventMetricsPushIncludeOutcome, "EVENT_METRICS_PUSH_INCLUDE_OUTCOME")
	setStr(&cfg.EventMetricsPushStaticLabels, "EVENT_METRICS_PUSH_STATIC_LABELS")
	setStr(&cfg.ErrorTraceKey, "ERROR_TRACE_KEY")
	setStr(&cfg.AuditExportSignKey, "AUDIT_EXPORT_SIGNING_KEY")
	setStr(&cfg.LicenceSigningKeyFile, "LICENCE_SIGNING_KEY_FILE")
	setInt(&cfg.LicenceMaxValidityDays, "LICENCE_MAX_VALIDITY_DAYS")
	setInt(&cfg.LicenceClockSkewSeconds, "LICENCE_CLOCK_SKEW_SECONDS")
	setInt(&cfg.LicenceOnlineCheckSeconds, "LICENCE_ONLINE_CHECK_SECONDS")
	setBool(&cfg.LicenceRemindersEnabled, "LICENCE_REMINDERS_ENABLED")
	setInt(&cfg.LicenceReminderIntervalSeconds, "LICENCE_REMINDER_INTERVAL_SECONDS")
	setStr(&cfg.SMTPHost, "SMTP_HOST")
	setInt(&cfg.SMTPPort, "SMTP_PORT")
	setStr(&cfg.SMTPUsername, "SMTP_USERNAME")
	setStr(&cfg.SMTPPassword, "SMTP_PASSWORD")
	setStr(&cfg.SMTPFromAddress, "SMTP_FROM_ADDRESS")
	setStr(&cfg.SMTPFromName, "SMTP_FROM_NAME")
	setStr(&cfg.SMTPTLSMode, "SMTP_TLS_MODE")
	setInt(&cfg.SMTPTimeoutSeconds, "SMTP_TIMEOUT_SECONDS")
	setStr(&cfg.ServerAddr, "SERVER_ADDR")
	setInt64(&cfg.RequestBodyMaxBytes, "REQUEST_BODY_MAX_BYTES")

	// Derive WebAuthnRPID from APP_URL if not set
	if cfg.WebAuthnRPID == "" && cfg.AppURL != "" {
		host := cfg.AppURL
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		cfg.WebAuthnRPID = host
	}

	// Use CSRF_SECRET as fallback for ErrorTraceKey
	if cfg.ErrorTraceKey == "" {
		cfg.ErrorTraceKey = cfg.CSRFSecret
	}
}
