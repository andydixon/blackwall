-- BlackWall MySQL base schema (MySQL 8.0+).
--
-- Converted from the PostgreSQL baseline when BlackWall moved back to MySQL,
-- and already includes migrations 1 through 8. Load it into an empty
-- database before first boot:
--
--   mysql -u blackwall -p blackwall < internal/db/schema.sql
--
-- It creates schema_migrations (normally created by Migrate()) and records
-- versions 1 to 8 as applied, so the folded-in migrations are not re-run.

SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE admin_api_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(36) NOT NULL,
    prefix VARCHAR(16) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    scopes_json LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    expires_at DATETIME NULL,
    revoked_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_admin_api_tokens_public_id (public_id),
    UNIQUE KEY uq_admin_api_tokens_token_hash (token_hash),
    KEY ix_admin_api_tokens_idx_aat_user (user_id, revoked_at),
    CONSTRAINT admin_api_tokens_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE admin_roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    role ENUM('super_admin', 'operator', 'auditor') NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_admin_roles_uniq_admin_user (user_id),
    KEY ix_admin_roles_idx_role_active (role, is_active),
    CONSTRAINT admin_roles_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE approval_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    action_type VARCHAR(100) NOT NULL,
    status ENUM('pending', 'approved', 'rejected', 'cancelled') NOT NULL DEFAULT 'pending',
    payload_json LONGTEXT NOT NULL,
    requested_by_user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NULL,
    approved_by_user_id BIGINT UNSIGNED NULL,
    decision_note VARCHAR(1000) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY ix_approval_requests_approved_by_user_id (approved_by_user_id),
    KEY ix_approval_requests_idx_action_status (action_type, status),
    KEY ix_approval_requests_idx_project_status_created (project_id, status, created_at),
    KEY ix_approval_requests_idx_requested_by (requested_by_user_id),
    KEY ix_approval_requests_idx_status_action_created (status, action_type, created_at),
    KEY ix_approval_requests_idx_status_created (status, created_at),
    CONSTRAINT ck_approval_requests_payload_json_json CHECK (json_valid(payload_json)),
    CONSTRAINT approval_requests_ibfk_1 FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT approval_requests_ibfk_2 FOREIGN KEY (approved_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_approval_requests_project FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE audit_chain_checkpoints (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    last_audit_id BIGINT UNSIGNED NOT NULL,
    last_chain_hash VARCHAR(64) NOT NULL,
    row_count BIGINT UNSIGNED NOT NULL,
    signature LONGTEXT NOT NULL,
    signing_key_id VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    exported_to VARCHAR(255) NULL,
    PRIMARY KEY (id),
    KEY ix_audit_chain_checkpoints_idx_ckpt_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL,
    outcome ENUM('success', 'fail', 'info') NOT NULL,
    message VARCHAR(1000) NOT NULL,
    correlation_id VARCHAR(36) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500) NULL,
    actor_user_id BIGINT UNSIGNED NULL,
    actor_user_uuid VARCHAR(36) NULL,
    project_id BIGINT UNSIGNED NULL,
    project_uuid VARCHAR(36) NULL,
    organization_id BIGINT UNSIGNED NULL,
    organization_uuid VARCHAR(36) NULL,
    oauth_client_id BIGINT UNSIGNED NULL,
    oauth_client_public_id VARCHAR(64) NULL,
    webauthn_credential_id BIGINT UNSIGNED NULL,
    webauthn_credential_public_id VARCHAR(512) NULL,
    target_type VARCHAR(50) NULL,
    target_id VARCHAR(100) NULL,
    metadata_json LONGTEXT NULL,
    chain_prev_hash VARCHAR(64) NULL,
    chain_hash VARCHAR(64) NULL,
    PRIMARY KEY (id),
    KEY ix_audit_log_idx_actor_user_id (actor_user_id),
    KEY ix_audit_log_idx_chain_hash (chain_hash),
    KEY ix_audit_log_idx_client_created (oauth_client_public_id, created_at),
    KEY ix_audit_log_idx_correlation_id (correlation_id),
    KEY ix_audit_log_idx_created_at (created_at),
    KEY ix_audit_log_idx_credential_created (webauthn_credential_public_id(255), created_at),
    KEY ix_audit_log_idx_event_type (event_type),
    KEY ix_audit_log_idx_ip_address (ip_address),
    KEY ix_audit_log_idx_ip_created (ip_address, created_at),
    KEY ix_audit_log_idx_oauth_client_public_id (oauth_client_public_id),
    KEY ix_audit_log_idx_org_created (organization_id, created_at),
    KEY ix_audit_log_idx_outcome (outcome),
    KEY ix_audit_log_idx_project_created (project_uuid, created_at),
    KEY ix_audit_log_idx_project_uuid (project_uuid),
    KEY ix_audit_log_idx_webauthn_credential_public_id (webauthn_credential_public_id(255)),
    KEY ix_audit_log_oauth_client_id (oauth_client_id),
    KEY ix_audit_log_project_id (project_id),
    KEY ix_audit_log_webauthn_credential_id (webauthn_credential_id),
    CONSTRAINT ck_audit_log_metadata_json_json CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
    CONSTRAINT audit_log_ibfk_1 FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT audit_log_ibfk_2 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL,
    CONSTRAINT audit_log_ibfk_3 FOREIGN KEY (oauth_client_id) REFERENCES oauth_clients (id) ON DELETE SET NULL,
    CONSTRAINT audit_log_ibfk_4 FOREIGN KEY (webauthn_credential_id) REFERENCES webauthn_credentials (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_organization FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE jwt_signing_keys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    kid VARCHAR(64) NOT NULL,
    private_key LONGTEXT NOT NULL,
    public_key LONGTEXT NOT NULL,
    algorithm VARCHAR(10) NOT NULL DEFAULT 'RS256',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_jwt_signing_keys_kid (kid),
    KEY ix_jwt_signing_keys_idx_is_active (is_active),
    KEY ix_jwt_signing_keys_idx_kid (kid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE licence_renewal_reminders (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    licence_id BIGINT UNSIGNED NOT NULL,
    threshold_days SMALLINT NOT NULL,
    recipient_user_id BIGINT UNSIGNED NOT NULL,
    recipient_email VARCHAR(254) NOT NULL,
    status ENUM('pending', 'sending', 'succeeded', 'exhausted', 'cancelled') NOT NULL DEFAULT 'pending',
    attempts SMALLINT NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL,
    locked_at DATETIME NULL,
    lock_token VARCHAR(36) NULL,
    last_error_code VARCHAR(64) NULL,
    sent_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_licence_renewal_reminders_uk_licence_reminder_recipient (licence_id, threshold_days, recipient_user_id),
    KEY ix_licence_renewal_reminders_idx_licence_reminder_project (licence_id, created_at),
    KEY ix_licence_renewal_reminders_idx_licence_reminder_queue (status, next_attempt_at),
    KEY ix_licence_renewal_reminders_recipient_user_id (recipient_user_id),
    CONSTRAINT licence_renewal_reminders_ibfk_1 FOREIGN KEY (licence_id) REFERENCES project_licences (id) ON DELETE CASCADE,
    CONSTRAINT licence_renewal_reminders_ibfk_2 FOREIGN KEY (recipient_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE licence_signing_keys (
    kid VARCHAR(64) NOT NULL,
    algorithm VARCHAR(16) NOT NULL,
    public_key_base64 VARCHAR(128) NOT NULL,
    status ENUM('active', 'retired', 'compromised') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at DATETIME NULL,
    PRIMARY KEY (kid),
    UNIQUE KEY uq_licence_signing_keys_uk_licence_public_key (public_key_base64)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE maintenance_job_runs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    job_name VARCHAR(100) NOT NULL,
    status ENUM('running', 'success', 'fail', 'skipped') NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    duration_ms BIGINT UNSIGNED NULL,
    message VARCHAR(1000) NULL,
    stats_json LONGTEXT NULL,
    error_trace LONGTEXT NULL,
    triggered_by VARCHAR(32) NOT NULL DEFAULT 'system',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY ix_maintenance_job_runs_idx_job_name_started (job_name, started_at),
    KEY ix_maintenance_job_runs_idx_status_started (status, started_at),
    CONSTRAINT ck_maintenance_job_runs_stats_json_json CHECK (stats_json IS NULL OR json_valid(stats_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE oauth_access_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_hash VARCHAR(255) NOT NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    scopes LONGTEXT NULL,
    privilege_level INT NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_oauth_access_tokens_token_hash (token_hash),
    KEY ix_oauth_access_tokens_idx_client_id (client_id),
    KEY ix_oauth_access_tokens_idx_expires_at (expires_at),
    KEY ix_oauth_access_tokens_idx_project_id (project_id),
    KEY ix_oauth_access_tokens_idx_token_hash (token_hash),
    KEY ix_oauth_access_tokens_idx_user_id (user_id),
    CONSTRAINT oauth_access_tokens_ibfk_1 FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    CONSTRAINT oauth_access_tokens_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT oauth_access_tokens_ibfk_3 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE oauth_auth_codes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code_hash VARCHAR(255) NOT NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    redirect_uri LONGTEXT NOT NULL,
    scopes LONGTEXT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    nonce VARCHAR(255) NULL,
    auth_time BIGINT UNSIGNED NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_oauth_auth_codes_code_hash (code_hash),
    KEY ix_oauth_auth_codes_idx_client_id (client_id),
    KEY ix_oauth_auth_codes_idx_code_hash (code_hash),
    KEY ix_oauth_auth_codes_idx_expires_at (expires_at),
    KEY ix_oauth_auth_codes_project_id (project_id),
    KEY ix_oauth_auth_codes_user_id (user_id),
    CONSTRAINT oauth_auth_codes_ibfk_1 FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    CONSTRAINT oauth_auth_codes_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT oauth_auth_codes_ibfk_3 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE oauth_clients (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id VARCHAR(64) NOT NULL,
    client_secret_hash VARCHAR(255) NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    redirect_uris LONGTEXT NOT NULL,
    grants LONGTEXT NOT NULL,
    scopes LONGTEXT NULL,
    pkce_required TINYINT(1) NOT NULL DEFAULT 1,
    access_token_type ENUM('jwt', 'opaque') NOT NULL DEFAULT 'jwt',
    access_token_lifetime INT NOT NULL DEFAULT 3600,
    refresh_token_lifetime INT NOT NULL DEFAULT 2592000,
    oidc_enabled TINYINT(1) NOT NULL DEFAULT 1,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_oauth_clients_client_id (client_id),
    KEY ix_oauth_clients_idx_client_id (client_id),
    KEY ix_oauth_clients_idx_project_id (project_id),
    KEY ix_oauth_clients_idx_status (status),
    CONSTRAINT oauth_clients_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE oauth_refresh_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_hash VARCHAR(255) NOT NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    access_token_id BIGINT UNSIGNED NULL,
    scopes LONGTEXT NULL,
    privilege_level INT NOT NULL,
    auth_time BIGINT UNSIGNED NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_oauth_refresh_tokens_token_hash (token_hash),
    KEY ix_oauth_refresh_tokens_idx_client_id (client_id),
    KEY ix_oauth_refresh_tokens_idx_expires_at (expires_at),
    KEY ix_oauth_refresh_tokens_idx_token_hash (token_hash),
    KEY ix_oauth_refresh_tokens_idx_user_id (user_id),
    KEY ix_oauth_refresh_tokens_project_id (project_id),
    CONSTRAINT oauth_refresh_tokens_ibfk_1 FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    CONSTRAINT oauth_refresh_tokens_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT oauth_refresh_tokens_ibfk_3 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE oauth_scopes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    is_default TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_oauth_scopes_name (name),
    KEY ix_oauth_scopes_idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE organizations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uuid VARCHAR(36) NOT NULL,
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(80) NOT NULL,
    logo_url VARCHAR(500) NULL,
    primary_color VARCHAR(16) NULL,
    login_message VARCHAR(2048) NULL,
    support_email VARCHAR(255) NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    admin_user_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_organizations_slug (slug),
    UNIQUE KEY uq_organizations_uuid (uuid),
    KEY ix_organizations_idx_org_admin_user (admin_user_id),
    KEY ix_organizations_idx_org_status (status),
    CONSTRAINT fk_organizations_admin_user FOREIGN KEY (admin_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE organization_oidc_claim_defaults (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    organization_id BIGINT UNSIGNED NOT NULL,
    claim_key VARCHAR(80) NOT NULL,
    claim_value LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_organization_oidc_claim_defaults_uk_org_claim_default (organization_id, claim_key),
    KEY ix_organization_oidc_claim_defaults_idx_org_claim_default (organization_id, claim_key),
    CONSTRAINT organization_oidc_claim_defaults_ibfk_1 FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE org_custom_domains (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    organization_id BIGINT UNSIGNED NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    verified TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_org_custom_domains_hostname (hostname),
    KEY ix_org_custom_domains_organization_id (organization_id),
    CONSTRAINT org_custom_domains_ibfk_1 FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE projects (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    organization_id BIGINT UNSIGNED NOT NULL,
    uuid VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    owner_user_id BIGINT UNSIGNED NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_projects_uuid (uuid),
    KEY ix_projects_idx_owner (owner_user_id),
    KEY ix_projects_idx_projects_org (organization_id),
    KEY ix_projects_idx_status (status),
    KEY ix_projects_idx_uuid (uuid),
    CONSTRAINT fk_projects_organization FOREIGN KEY (organization_id) REFERENCES organizations (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE project_features (
    project_id BIGINT UNSIGNED NOT NULL,
    webhooks_enabled TINYINT(1) NOT NULL DEFAULT 0,
    db_sessions_enabled TINYINT(1) NOT NULL DEFAULT 0,
    max_concurrent_sessions INT NOT NULL DEFAULT 0,
    custom_branding_enabled TINYINT(1) NOT NULL DEFAULT 0,
    step_up_required TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (project_id),
    CONSTRAINT project_features_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE project_licences (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(36) NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    entity_type ENUM('person', 'business') NOT NULL,
    entity_name VARCHAR(255) NOT NULL,
    entity_reference VARCHAR(255) NULL,
    hostnames_json LONGTEXT NOT NULL,
    features_json LONGTEXT NOT NULL,
    max_instances BIGINT UNSIGNED NOT NULL DEFAULT 1,
    not_before DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    issued_at DATETIME NOT NULL,
    issued_by_user_id BIGINT UNSIGNED NULL,
    revoked_at DATETIME NULL,
    revoked_by_user_id BIGINT UNSIGNED NULL,
    revocation_reason VARCHAR(500) NULL,
    signing_key_id VARCHAR(64) NOT NULL,
    payload_json LONGTEXT NOT NULL,
    signature_base64 VARCHAR(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_project_licences_public_id (public_id),
    KEY ix_project_licences_idx_licence_key (signing_key_id),
    KEY ix_project_licences_idx_licence_project_status (project_id, revoked_at, expires_at),
    KEY ix_project_licences_issued_by_user_id (issued_by_user_id),
    KEY ix_project_licences_revoked_by_user_id (revoked_by_user_id),
    CONSTRAINT project_licences_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    CONSTRAINT project_licences_ibfk_2 FOREIGN KEY (issued_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT project_licences_ibfk_3 FOREIGN KEY (revoked_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT project_licences_ibfk_4 FOREIGN KEY (signing_key_id) REFERENCES licence_signing_keys (kid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE project_oidc_claim_defaults (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    claim_key VARCHAR(80) NOT NULL,
    claim_value LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_project_oidc_claim_defaults_uk_project_claim_default (project_id, claim_key),
    KEY ix_project_oidc_claim_defaults_idx_project_claim_default (project_id, claim_key),
    CONSTRAINT project_oidc_claim_defaults_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE project_privilege_levels (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    level INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_project_privilege_levels_uniq_project_level (project_id, level),
    UNIQUE KEY uq_project_privilege_levels_uniq_project_name (project_id, name),
    KEY ix_project_privilege_levels_idx_project_id (project_id),
    CONSTRAINT project_privilege_levels_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE rate_limits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    identifier VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    attempts BIGINT UNSIGNED NOT NULL DEFAULT 1,
    window_start DATETIME NOT NULL,
    blocked_until DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rate_limits_uniq_identifier_action (identifier, action),
    KEY ix_rate_limits_idx_blocked_until (blocked_until),
    KEY ix_rate_limits_idx_identifier_action (identifier, action),
    KEY ix_rate_limits_idx_window_start (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE saml_service_providers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(36) NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    acs_url VARCHAR(2048) NOT NULL,
    slo_url VARCHAR(2048) NULL,
    name_id_format VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    sign_assertions TINYINT(1) NOT NULL DEFAULT 1,
    sign_response TINYINT(1) NOT NULL DEFAULT 1,
    sp_cert_pem LONGTEXT NULL,
    attribute_map_json LONGTEXT NOT NULL,
    audience VARCHAR(1024) NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_saml_service_providers_public_id (public_id),
    -- MySQL caps an index at 3072 bytes (MariaDB hashed this key instead), so
    -- uniqueness covers the first 760 characters of the entity ID.
    UNIQUE KEY uq_saml_service_providers_uk_saml_sp_entity (project_id, entity_id(760)),
    KEY ix_saml_service_providers_idx_saml_sp_project (project_id, status),
    CONSTRAINT saml_service_providers_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scim_user_mapping (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scim_user_mapping_uk_scim_external (project_id, external_id),
    KEY ix_scim_user_mapping_idx_scim_user (user_id, project_id),
    CONSTRAINT scim_user_mapping_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    CONSTRAINT scim_user_mapping_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE system_config (
    config_key VARCHAR(100) NOT NULL,
    config_value LONGTEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    organization_id BIGINT UNSIGNED NOT NULL,
    uuid VARCHAR(36) NOT NULL,
    display_label VARCHAR(255) NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_uuid (uuid),
    KEY ix_users_idx_display_label (display_label),
    KEY ix_users_idx_status (status),
    KEY ix_users_idx_users_org (organization_id),
    KEY ix_users_idx_uuid (uuid),
    CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_oidc_claims (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    claim_key VARCHAR(80) NOT NULL,
    claim_value LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_oidc_claims_uk_user_claim (user_id, claim_key),
    KEY ix_user_oidc_claims_idx_user_claim_key (user_id, claim_key),
    CONSTRAINT user_oidc_claims_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_project_oidc_claims (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    claim_key VARCHAR(80) NOT NULL,
    claim_value LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_project_oidc_claims_uk_user_project_claim (user_id, project_id, claim_key),
    KEY ix_user_project_oidc_claims_idx_upc (user_id, project_id, claim_key),
    KEY ix_user_project_oidc_claims_project_id (project_id),
    CONSTRAINT user_project_oidc_claims_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_project_oidc_claims_ibfk_2 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_project_roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    privilege_level INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_project_roles_uniq_user_project (user_id, project_id),
    KEY ix_user_project_roles_idx_privilege_level (privilege_level),
    KEY ix_user_project_roles_idx_project_id (project_id),
    KEY ix_user_project_roles_idx_user_id (user_id),
    CONSTRAINT user_project_roles_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_project_roles_ibfk_2 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id VARCHAR(43) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    scope ENUM('admin', 'portal') NOT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(512) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    revoked_reason VARCHAR(100) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_sessions_session_id (session_id),
    KEY ix_user_sessions_idx_us_expiry (expires_at, revoked_at),
    KEY ix_user_sessions_idx_us_user_active (user_id, revoked_at, expires_at),
    CONSTRAINT user_sessions_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE webauthn_credentials (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    credential_id VARCHAR(512) NOT NULL,
    public_key LONGTEXT NOT NULL,
    aaguid VARCHAR(64) NULL,
    sign_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
    transports LONGTEXT NULL,
    attestation_type VARCHAR(64) NULL,
    label VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_webauthn_credentials_credential_id (credential_id),
    KEY ix_webauthn_credentials_idx_credential_id (credential_id(255)),
    KEY ix_webauthn_credentials_idx_user_id (user_id),
    CONSTRAINT ck_webauthn_credentials_transports_json CHECK (transports IS NULL OR json_valid(transports)),
    CONSTRAINT webauthn_credentials_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE webhook_deliveries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    endpoint_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(80) NOT NULL,
    event_id VARCHAR(36) NOT NULL,
    payload_json LONGTEXT NOT NULL,
    status ENUM('pending', 'succeeded', 'failed', 'exhausted') NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    last_status_code INT NULL,
    last_response_excerpt LONGTEXT NULL,
    next_attempt_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY ix_webhook_deliveries_endpoint_id (endpoint_id),
    KEY ix_webhook_deliveries_idx_wd_event (event_id),
    KEY ix_webhook_deliveries_idx_wd_pending (status, next_attempt_at),
    CONSTRAINT webhook_deliveries_ibfk_1 FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE webhook_endpoints (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    public_id VARCHAR(36) NOT NULL,
    target_url VARCHAR(2048) NOT NULL,
    secret VARCHAR(128) NOT NULL,
    events_json LONGTEXT NOT NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    description VARCHAR(255) NULL,
    last_success_at DATETIME NULL,
    last_failure_at DATETIME NULL,
    consecutive_failures INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_webhook_endpoints_public_id (public_id),
    KEY ix_webhook_endpoints_idx_we_project (project_id, status),
    CONSTRAINT webhook_endpoints_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT UNSIGNED PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_migrations (version, description) VALUES
    (1, 'Custom OIDC claims (per-user and per-user-per-project key/value)'),
    (2, 'Default OIDC claims at organisation and project level (templates merged into every user)'),
    (3, 'Enterprise-tier scaffolding: project feature flags, webhook endpoints + deliveries, DB-backed user sessions, organisation branding, custom domains, audit chain checkpoints, and admin API tokens'),
    (4, 'SAML 2.0 service providers (per-project SP registry) and SCIM external_id mapping for round-tripping HRIS-driven provisioning.'),
    (5, 'Persist OIDC authentication time on authorization codes and refresh tokens'),
    (6, 'Ed25519-signed, hostname-bound project licences and signing-key registry'),
    (7, 'Durable, duplicate-safe project licence renewal reminders'),
    (8, 'Restore the organisation branding columns migration 3 failed to add');
