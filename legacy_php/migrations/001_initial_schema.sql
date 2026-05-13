-- BlackWall OAuth 2.1 + OIDC Authorization Server
-- MySQL Schema with comprehensive audit logging

-- Projects (multi-tenant)
CREATE TABLE IF NOT EXISTS projects (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    owner_user_id BIGINT UNSIGNED NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_uuid (uuid),
    INDEX idx_status (status),
    INDEX idx_owner (owner_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Users
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    display_label VARCHAR(255) NULL COMMENT 'Email or friendly name - NOT used for authentication',
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_uuid (uuid),
    INDEX idx_status (status),
    INDEX idx_display_label (display_label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- WebAuthn credentials (ONLY authentication method)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    credential_id VARCHAR(512) NOT NULL UNIQUE COMMENT 'Base64url encoded',
    public_key TEXT NOT NULL,
    aaguid VARCHAR(64) NULL,
    sign_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
    transports JSON NULL,
    attestation_type VARCHAR(64) NULL,
    label VARCHAR(255) NULL COMMENT 'User-friendly label for this key',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_credential_id (credential_id(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Project privilege levels (named per project)
CREATE TABLE IF NOT EXISTS project_privilege_levels (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    project_id BIGINT UNSIGNED NOT NULL,
    level INT NOT NULL COMMENT 'Numeric level: 1=highest (admin), 2=user, 3+ custom',
    name VARCHAR(100) NOT NULL COMMENT 'Display name: Owner, Admin, User, Read-only, etc',
    description VARCHAR(500) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_project_level (project_id, level),
    UNIQUE KEY uniq_project_name (project_id, name),
    INDEX idx_project_id (project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User-project role assignments
CREATE TABLE IF NOT EXISTS user_project_roles (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    privilege_level INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_user_project (user_id, project_id),
    INDEX idx_user_id (user_id),
    INDEX idx_project_id (project_id),
    INDEX idx_privilege_level (privilege_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth clients
CREATE TABLE IF NOT EXISTS oauth_clients (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id CHAR(64) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NULL COMMENT 'Null for public clients',
    project_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT NOT NULL COMMENT 'JSON array',
    grants TEXT NOT NULL COMMENT 'JSON array: authorization_code, refresh_token',
    scopes TEXT NULL COMMENT 'JSON array of allowed scope names',
    pkce_required TINYINT(1) NOT NULL DEFAULT 1,
    access_token_type ENUM('jwt', 'opaque') NOT NULL DEFAULT 'jwt',
    access_token_lifetime INT NOT NULL DEFAULT 3600 COMMENT 'Seconds',
    refresh_token_lifetime INT NOT NULL DEFAULT 2592000 COMMENT 'Seconds (30 days)',
    oidc_enabled TINYINT(1) NOT NULL DEFAULT 1,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_project_id (project_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth scopes
CREATE TABLE IF NOT EXISTS oauth_scopes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(500) NULL,
    is_default TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth authorization codes
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code_hash VARCHAR(255) NOT NULL UNIQUE,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NULL COMMENT 'JSON array',
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    nonce VARCHAR(255) NULL COMMENT 'OIDC nonce',
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    INDEX idx_code_hash (code_hash),
    INDEX idx_expires_at (expires_at),
    INDEX idx_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth access tokens (opaque only; JWTs are stateless)
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    scopes TEXT NULL COMMENT 'JSON array',
    privilege_level INT NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_expires_at (expires_at),
    INDEX idx_client_id (client_id),
    INDEX idx_user_id (user_id),
    INDEX idx_project_id (project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth refresh tokens
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    access_token_id BIGINT UNSIGNED NULL COMMENT 'Link to original access token if opaque',
    scopes TEXT NULL COMMENT 'JSON array',
    privilege_level INT NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_expires_at (expires_at),
    INDEX idx_client_id (client_id),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- JWT signing keys (for rotation)
CREATE TABLE IF NOT EXISTS jwt_signing_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    kid VARCHAR(64) NOT NULL UNIQUE COMMENT 'Key ID',
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm VARCHAR(10) NOT NULL DEFAULT 'RS256',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at DATETIME NULL,
    INDEX idx_kid (kid),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Comprehensive audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL COMMENT 'e.g., webauthn.authentication.success, oauth.token.issue',
    outcome ENUM('success', 'fail', 'info') NOT NULL,
    message VARCHAR(1000) NOT NULL,
    correlation_id CHAR(36) NOT NULL,
    ip_address VARCHAR(45) NOT NULL COMMENT 'IPv4 or IPv6',
    user_agent VARCHAR(500) NULL,
    actor_user_id BIGINT UNSIGNED NULL COMMENT 'User performing the action',
    actor_user_uuid CHAR(36) NULL,
    project_id BIGINT UNSIGNED NULL,
    project_uuid CHAR(36) NULL,
    oauth_client_id BIGINT UNSIGNED NULL,
    oauth_client_public_id CHAR(64) NULL COMMENT 'client_id string',
    webauthn_credential_id BIGINT UNSIGNED NULL,
    webauthn_credential_public_id VARCHAR(512) NULL COMMENT 'credential_id or hash',
    target_type VARCHAR(50) NULL COMMENT 'user, project, client, credential, etc',
    target_id VARCHAR(100) NULL,
    metadata_json JSON NULL COMMENT 'Flexible data: scopes, redirect_uri, error_code, failure_reason, etc',
    INDEX idx_created_at (created_at),
    INDEX idx_event_type (event_type),
    INDEX idx_outcome (outcome),
    INDEX idx_ip_address (ip_address),
    INDEX idx_correlation_id (correlation_id),
    INDEX idx_actor_user_id (actor_user_id),
    INDEX idx_project_uuid (project_uuid),
    INDEX idx_oauth_client_public_id (oauth_client_public_id),
    INDEX idx_webauthn_credential_public_id (webauthn_credential_public_id(255)),
    INDEX idx_project_created (project_uuid, created_at),
    INDEX idx_ip_created (ip_address, created_at),
    INDEX idx_credential_created (webauthn_credential_public_id(255), created_at),
    INDEX idx_client_created (oauth_client_public_id, created_at),
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL,
    FOREIGN KEY (oauth_client_id) REFERENCES oauth_clients(id) ON DELETE SET NULL,
    FOREIGN KEY (webauthn_credential_id) REFERENCES webauthn_credentials(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL COMMENT 'IP, user_id, or composite key',
    action VARCHAR(100) NOT NULL COMMENT 'oauth.token, webauthn.auth, etc',
    attempts INT UNSIGNED NOT NULL DEFAULT 1,
    window_start DATETIME NOT NULL,
    blocked_until DATETIME NULL,
    INDEX idx_identifier_action (identifier, action),
    INDEX idx_window_start (window_start),
    INDEX idx_blocked_until (blocked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bootstrap status
CREATE TABLE IF NOT EXISTS system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default scopes
INSERT INTO oauth_scopes (name, description, is_default) VALUES
('openid', 'OpenID Connect authentication', 0),
('profile', 'Access to basic profile information', 0),
('email', 'Access to email address', 0),
('offline_access', 'Refresh token support', 0)
ON DUPLICATE KEY UPDATE description = VALUES(description);
