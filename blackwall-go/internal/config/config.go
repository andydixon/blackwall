package config

import (
	"fmt"
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

	CryptbinKEKBase64          string `yaml:"cryptbin_kek_base64"`
	CryptbinKEKVersion         string `yaml:"cryptbin_kek_version"`
	CryptbinStoragePath        string `yaml:"cryptbin_storage_path"`
	CryptbinMaxUploadBytes     int64  `yaml:"cryptbin_max_upload_bytes"`
	CryptbinMaxTextBytes       int64  `yaml:"cryptbin_max_text_bytes"`
	CryptbinAllowedMime        string `yaml:"cryptbin_allowed_mime"`
	CryptbinDefaultRetentionDays int  `yaml:"cryptbin_default_retention_days"`

	WebAuthnRPID   string `yaml:"webauthn_rp_id"`
	WebAuthnRPName string `yaml:"webauthn_rp_name"`
	MinWebAuthnKeys int   `yaml:"min_webauthn_keys"`

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

	MetricsToken                string `yaml:"metrics_token"`
	MetricsAllowUnauthenticated bool   `yaml:"metrics_allow_unauthenticated"`
	EventMetricsPushEnabled   bool   `yaml:"event_metrics_push_enabled"`
	EventMetricsPushURL       string `yaml:"event_metrics_push_url"`
	EventMetricsPushMetricName string `yaml:"event_metrics_push_metric_name"`
	EventMetricsPushTimeoutMs int    `yaml:"event_metrics_push_timeout_ms"`
	EventMetricsPushIncludeOutcome bool `yaml:"event_metrics_push_include_outcome"`
	EventMetricsPushStaticLabels string `yaml:"event_metrics_push_static_labels"`

	ErrorTraceKey      string `yaml:"error_trace_key"`
	AuditExportSignKey string `yaml:"audit_export_signing_key"`

	ServerAddr string `yaml:"server_addr"`
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
	if c.AppURL == "" {
		return fmt.Errorf("config: app_url is required")
	}
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
	return nil
}

func Get() *Config {
	if global == nil {
		cfg := defaults()
		overrideFromEnv(cfg)
		global = cfg
	}
	return global
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
	setStr(&cfg.ServerAddr, "SERVER_ADDR")

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
