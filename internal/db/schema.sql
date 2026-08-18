-- BlackWall PostgreSQL baseline schema.
--
-- Originally generated from the live MariaDB schema by
-- tools/pgmigrate/gen_schema.py as a one-time bootstrap. MariaDB is no longer
-- the source of truth, so do NOT regenerate this file — it is now maintained
-- by hand, and every change must land here AND as a numbered migration in
-- migrations.go so fresh installs and existing databases converge.

CREATE EXTENSION IF NOT EXISTS citext;

-- MySQL's JSON_EXTRACT returns NULL for text that is not valid JSON;
-- a bare ::jsonb cast raises instead. This helper restores the lenient
-- behaviour the application relies on.
CREATE OR REPLACE FUNCTION bw_json_text(doc text, field text) RETURNS text AS $fn$
BEGIN
    RETURN (doc::jsonb) ->> field;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$fn$ LANGUAGE plpgsql IMMUTABLE;

-- Mirrors MySQL's json_valid() for the CHECK constraints below.
CREATE OR REPLACE FUNCTION bw_is_json(doc text) RETURNS boolean AS $fn$
BEGIN
    PERFORM doc::jsonb;
    RETURN TRUE;
EXCEPTION WHEN others THEN
    RETURN FALSE;
END;
$fn$ LANGUAGE plpgsql IMMUTABLE;

-- Replaces MySQL's ON UPDATE CURRENT_TIMESTAMP column attribute.
CREATE OR REPLACE FUNCTION bw_touch_updated_at() RETURNS trigger AS $fn$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TABLE admin_api_tokens (
    id BIGSERIAL NOT NULL,
    public_id CITEXT NOT NULL,
    CHECK (length(public_id) <= 36),
    prefix CITEXT NOT NULL,
    CHECK (length(prefix) <= 16),
    token_hash CITEXT NOT NULL,
    CHECK (length(token_hash) <= 64),
    user_id BIGINT NOT NULL,
    name CITEXT NOT NULL,
    CHECK (length(name) <= 255),
    scopes_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE admin_roles (
    id BIGSERIAL NOT NULL,
    user_id BIGINT NOT NULL,
    role TEXT NOT NULL,
    CHECK (role IN ('super_admin', 'operator', 'auditor')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE approval_requests (
    id BIGSERIAL NOT NULL,
    action_type CITEXT NOT NULL,
    CHECK (length(action_type) <= 100),
    status TEXT NOT NULL DEFAULT 'pending',
    CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    payload_json TEXT NOT NULL,
    requested_by_user_id BIGINT NOT NULL,
    project_id BIGINT,
    approved_by_user_id BIGINT,
    decision_note CITEXT,
    CHECK (length(decision_note) <= 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE audit_chain_checkpoints (
    id BIGSERIAL NOT NULL,
    last_audit_id BIGINT NOT NULL,
    last_chain_hash CITEXT NOT NULL,
    CHECK (length(last_chain_hash) <= 64),
    row_count BIGINT NOT NULL,
    signature TEXT NOT NULL,
    signing_key_id CITEXT NOT NULL,
    CHECK (length(signing_key_id) <= 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    exported_to CITEXT,
    CHECK (length(exported_to) <= 255)
);

CREATE TABLE audit_log (
    id BIGSERIAL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type CITEXT NOT NULL,
    CHECK (length(event_type) <= 100),
    outcome TEXT NOT NULL,
    CHECK (outcome IN ('success', 'fail', 'info')),
    message CITEXT NOT NULL,
    CHECK (length(message) <= 1000),
    correlation_id CITEXT NOT NULL,
    CHECK (length(correlation_id) <= 36),
    ip_address CITEXT NOT NULL,
    CHECK (length(ip_address) <= 45),
    user_agent CITEXT,
    CHECK (length(user_agent) <= 500),
    actor_user_id BIGINT,
    actor_user_uuid CITEXT,
    CHECK (length(actor_user_uuid) <= 36),
    project_id BIGINT,
    project_uuid CITEXT,
    CHECK (length(project_uuid) <= 36),
    organization_id BIGINT,
    organization_uuid CITEXT,
    CHECK (length(organization_uuid) <= 36),
    oauth_client_id BIGINT,
    oauth_client_public_id CITEXT,
    CHECK (length(oauth_client_public_id) <= 64),
    webauthn_credential_id BIGINT,
    webauthn_credential_public_id CITEXT,
    CHECK (length(webauthn_credential_public_id) <= 512),
    target_type CITEXT,
    CHECK (length(target_type) <= 50),
    target_id CITEXT,
    CHECK (length(target_id) <= 100),
    metadata_json TEXT,
    chain_prev_hash CITEXT,
    CHECK (length(chain_prev_hash) <= 64),
    chain_hash CITEXT,
    CHECK (length(chain_hash) <= 64)
);

CREATE TABLE jwt_signing_keys (
    id BIGSERIAL NOT NULL,
    kid CITEXT NOT NULL,
    CHECK (length(kid) <= 64),
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm CITEXT NOT NULL DEFAULT 'RS256',
    CHECK (length(algorithm) <= 10),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

CREATE TABLE licence_renewal_reminders (
    id BIGSERIAL NOT NULL,
    licence_id BIGINT NOT NULL,
    threshold_days SMALLINT NOT NULL,
    recipient_user_id BIGINT NOT NULL,
    recipient_email CITEXT NOT NULL,
    CHECK (length(recipient_email) <= 254),
    status TEXT NOT NULL DEFAULT 'pending',
    CHECK (status IN ('pending', 'sending', 'succeeded', 'exhausted', 'cancelled')),
    attempts SMALLINT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    locked_at TIMESTAMPTZ,
    lock_token CITEXT,
    CHECK (length(lock_token) <= 36),
    last_error_code CITEXT,
    CHECK (length(last_error_code) <= 64),
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE licence_signing_keys (
    kid CITEXT NOT NULL,
    CHECK (length(kid) <= 64),
    algorithm CITEXT NOT NULL,
    CHECK (length(algorithm) <= 16),
    public_key_base64 CITEXT NOT NULL,
    CHECK (length(public_key_base64) <= 128),
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'retired', 'compromised')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ
);

CREATE TABLE maintenance_job_runs (
    id BIGSERIAL NOT NULL,
    job_name CITEXT NOT NULL,
    CHECK (length(job_name) <= 100),
    status TEXT NOT NULL,
    CHECK (status IN ('running', 'success', 'fail', 'skipped')),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    duration_ms BIGINT,
    message CITEXT,
    CHECK (length(message) <= 1000),
    stats_json TEXT,
    error_trace TEXT,
    triggered_by CITEXT NOT NULL DEFAULT 'system',
    CHECK (length(triggered_by) <= 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_access_tokens (
    id BIGSERIAL NOT NULL,
    token_hash CITEXT NOT NULL,
    CHECK (length(token_hash) <= 255),
    client_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    scopes TEXT,
    privilege_level INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_auth_codes (
    id BIGSERIAL NOT NULL,
    code_hash CITEXT NOT NULL,
    CHECK (length(code_hash) <= 255),
    client_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT,
    code_challenge CITEXT NOT NULL,
    CHECK (length(code_challenge) <= 128),
    code_challenge_method CITEXT NOT NULL DEFAULT 'S256',
    CHECK (length(code_challenge_method) <= 10),
    nonce CITEXT,
    CHECK (length(nonce) <= 255),
    auth_time BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_clients (
    id BIGSERIAL NOT NULL,
    client_id CITEXT NOT NULL,
    CHECK (length(client_id) <= 64),
    client_secret_hash CITEXT,
    CHECK (length(client_secret_hash) <= 255),
    project_id BIGINT NOT NULL,
    name CITEXT NOT NULL,
    CHECK (length(name) <= 255),
    redirect_uris TEXT NOT NULL,
    grants TEXT NOT NULL,
    scopes TEXT,
    pkce_required BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_type TEXT NOT NULL DEFAULT 'jwt',
    CHECK (access_token_type IN ('jwt', 'opaque')),
    access_token_lifetime INTEGER NOT NULL DEFAULT 3600,
    refresh_token_lifetime INTEGER NOT NULL DEFAULT 2592000,
    oidc_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_refresh_tokens (
    id BIGSERIAL NOT NULL,
    token_hash CITEXT NOT NULL,
    CHECK (length(token_hash) <= 255),
    client_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    access_token_id BIGINT,
    scopes TEXT,
    privilege_level INTEGER NOT NULL,
    auth_time BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_scopes (
    id BIGSERIAL NOT NULL,
    name CITEXT NOT NULL,
    CHECK (length(name) <= 100),
    description CITEXT,
    CHECK (length(description) <= 500),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organizations (
    id BIGSERIAL NOT NULL,
    uuid CITEXT NOT NULL,
    CHECK (length(uuid) <= 36),
    name CITEXT NOT NULL,
    CHECK (length(name) <= 120),
    slug CITEXT NOT NULL,
    CHECK (length(slug) <= 80),
    logo_url CITEXT,
    CHECK (length(logo_url) <= 500),
    primary_color VARCHAR(16),
    login_message VARCHAR(2048),
    support_email VARCHAR(255),
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'disabled')),
    admin_user_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organization_oidc_claim_defaults (
    id BIGSERIAL NOT NULL,
    organization_id BIGINT NOT NULL,
    claim_key CITEXT NOT NULL,
    CHECK (length(claim_key) <= 80),
    claim_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE org_custom_domains (
    id BIGSERIAL NOT NULL,
    organization_id BIGINT NOT NULL,
    hostname CITEXT NOT NULL,
    CHECK (length(hostname) <= 253),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE projects (
    id BIGSERIAL NOT NULL,
    organization_id BIGINT NOT NULL,
    uuid CITEXT NOT NULL,
    CHECK (length(uuid) <= 36),
    name CITEXT NOT NULL,
    CHECK (length(name) <= 255),
    owner_user_id BIGINT,
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE project_features (
    project_id BIGINT NOT NULL,
    webhooks_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    db_sessions_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    max_concurrent_sessions INTEGER NOT NULL DEFAULT 0,
    custom_branding_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    step_up_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE project_licences (
    id BIGSERIAL NOT NULL,
    public_id CITEXT NOT NULL,
    CHECK (length(public_id) <= 36),
    project_id BIGINT NOT NULL,
    entity_type TEXT NOT NULL,
    CHECK (entity_type IN ('person', 'business')),
    entity_name CITEXT NOT NULL,
    CHECK (length(entity_name) <= 255),
    entity_reference CITEXT,
    CHECK (length(entity_reference) <= 255),
    hostnames_json TEXT NOT NULL,
    features_json TEXT NOT NULL,
    max_instances BIGINT NOT NULL DEFAULT 1,
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    issued_by_user_id BIGINT,
    revoked_at TIMESTAMPTZ,
    revoked_by_user_id BIGINT,
    revocation_reason CITEXT,
    CHECK (length(revocation_reason) <= 500),
    signing_key_id CITEXT NOT NULL,
    CHECK (length(signing_key_id) <= 64),
    payload_json TEXT NOT NULL,
    signature_base64 CITEXT NOT NULL,
    CHECK (length(signature_base64) <= 128)
);

CREATE TABLE project_oidc_claim_defaults (
    id BIGSERIAL NOT NULL,
    project_id BIGINT NOT NULL,
    claim_key CITEXT NOT NULL,
    CHECK (length(claim_key) <= 80),
    claim_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE project_privilege_levels (
    id BIGSERIAL NOT NULL,
    project_id BIGINT NOT NULL,
    level INTEGER NOT NULL,
    name CITEXT NOT NULL,
    CHECK (length(name) <= 100),
    description CITEXT,
    CHECK (length(description) <= 500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE rate_limits (
    id BIGSERIAL NOT NULL,
    identifier CITEXT NOT NULL,
    CHECK (length(identifier) <= 255),
    action CITEXT NOT NULL,
    CHECK (length(action) <= 100),
    attempts BIGINT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL,
    blocked_until TIMESTAMPTZ
);

CREATE TABLE saml_service_providers (
    id BIGSERIAL NOT NULL,
    public_id CITEXT NOT NULL,
    CHECK (length(public_id) <= 36),
    project_id BIGINT NOT NULL,
    entity_id CITEXT NOT NULL,
    CHECK (length(entity_id) <= 1024),
    acs_url CITEXT NOT NULL,
    CHECK (length(acs_url) <= 2048),
    slo_url CITEXT,
    CHECK (length(slo_url) <= 2048),
    name_id_format CITEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    CHECK (length(name_id_format) <= 255),
    sign_assertions BOOLEAN NOT NULL DEFAULT TRUE,
    sign_response BOOLEAN NOT NULL DEFAULT TRUE,
    sp_cert_pem TEXT,
    attribute_map_json TEXT NOT NULL,
    audience CITEXT,
    CHECK (length(audience) <= 1024),
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- schema_migrations is deliberately absent here: Migrate() in migrations.go
-- creates it before installing this baseline, so defining it twice would
-- collide. If you load this file by hand, that table is created on first boot.

CREATE TABLE scim_user_mapping (
    id BIGSERIAL NOT NULL,
    project_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    external_id CITEXT NOT NULL,
    CHECK (length(external_id) <= 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE system_config (
    config_key CITEXT NOT NULL,
    CHECK (length(config_key) <= 100),
    config_value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id BIGSERIAL NOT NULL,
    organization_id BIGINT NOT NULL,
    uuid CITEXT NOT NULL,
    CHECK (length(uuid) <= 36),
    display_label CITEXT,
    CHECK (length(display_label) <= 255),
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_oidc_claims (
    id BIGSERIAL NOT NULL,
    user_id BIGINT NOT NULL,
    claim_key CITEXT NOT NULL,
    CHECK (length(claim_key) <= 80),
    claim_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_project_oidc_claims (
    id BIGSERIAL NOT NULL,
    user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    claim_key CITEXT NOT NULL,
    CHECK (length(claim_key) <= 80),
    claim_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_project_roles (
    id BIGSERIAL NOT NULL,
    user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    privilege_level INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_sessions (
    id BIGSERIAL NOT NULL,
    session_id CITEXT NOT NULL,
    CHECK (length(session_id) <= 43),
    user_id BIGINT NOT NULL,
    scope TEXT NOT NULL,
    CHECK (scope IN ('admin', 'portal')),
    ip_address CITEXT,
    CHECK (length(ip_address) <= 45),
    user_agent CITEXT,
    CHECK (length(user_agent) <= 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason CITEXT,
    CHECK (length(revoked_reason) <= 100)
);

CREATE TABLE webauthn_credentials (
    id BIGSERIAL NOT NULL,
    user_id BIGINT NOT NULL,
    credential_id CITEXT NOT NULL,
    CHECK (length(credential_id) <= 512),
    public_key TEXT NOT NULL,
    aaguid CITEXT,
    CHECK (length(aaguid) <= 64),
    sign_counter BIGINT NOT NULL DEFAULT 0,
    transports TEXT,
    attestation_type CITEXT,
    CHECK (length(attestation_type) <= 64),
    label CITEXT,
    CHECK (length(label) <= 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE TABLE webhook_deliveries (
    id BIGSERIAL NOT NULL,
    endpoint_id BIGINT NOT NULL,
    event_type CITEXT NOT NULL,
    CHECK (length(event_type) <= 80),
    event_id CITEXT NOT NULL,
    CHECK (length(event_id) <= 36),
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    CHECK (status IN ('pending', 'succeeded', 'failed', 'exhausted')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_status_code INTEGER,
    last_response_excerpt TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_endpoints (
    id BIGSERIAL NOT NULL,
    project_id BIGINT NOT NULL,
    public_id CITEXT NOT NULL,
    CHECK (length(public_id) <= 36),
    target_url CITEXT NOT NULL,
    CHECK (length(target_url) <= 2048),
    secret CITEXT NOT NULL,
    CHECK (length(secret) <= 128),
    events_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    CHECK (status IN ('active', 'disabled')),
    description CITEXT,
    CHECK (length(description) <= 255),
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE admin_api_tokens ADD PRIMARY KEY (id);
ALTER TABLE admin_roles ADD PRIMARY KEY (id);
ALTER TABLE approval_requests ADD PRIMARY KEY (id);
ALTER TABLE audit_chain_checkpoints ADD PRIMARY KEY (id);
ALTER TABLE audit_log ADD PRIMARY KEY (id);
ALTER TABLE jwt_signing_keys ADD PRIMARY KEY (id);
ALTER TABLE licence_renewal_reminders ADD PRIMARY KEY (id);
ALTER TABLE licence_signing_keys ADD PRIMARY KEY (kid);
ALTER TABLE maintenance_job_runs ADD PRIMARY KEY (id);
ALTER TABLE oauth_access_tokens ADD PRIMARY KEY (id);
ALTER TABLE oauth_auth_codes ADD PRIMARY KEY (id);
ALTER TABLE oauth_clients ADD PRIMARY KEY (id);
ALTER TABLE oauth_refresh_tokens ADD PRIMARY KEY (id);
ALTER TABLE oauth_scopes ADD PRIMARY KEY (id);
ALTER TABLE organizations ADD PRIMARY KEY (id);
ALTER TABLE organization_oidc_claim_defaults ADD PRIMARY KEY (id);
ALTER TABLE org_custom_domains ADD PRIMARY KEY (id);
ALTER TABLE projects ADD PRIMARY KEY (id);
ALTER TABLE project_features ADD PRIMARY KEY (project_id);
ALTER TABLE project_licences ADD PRIMARY KEY (id);
ALTER TABLE project_oidc_claim_defaults ADD PRIMARY KEY (id);
ALTER TABLE project_privilege_levels ADD PRIMARY KEY (id);
ALTER TABLE rate_limits ADD PRIMARY KEY (id);
ALTER TABLE saml_service_providers ADD PRIMARY KEY (id);
ALTER TABLE scim_user_mapping ADD PRIMARY KEY (id);
ALTER TABLE system_config ADD PRIMARY KEY (config_key);
ALTER TABLE users ADD PRIMARY KEY (id);
ALTER TABLE user_oidc_claims ADD PRIMARY KEY (id);
ALTER TABLE user_project_oidc_claims ADD PRIMARY KEY (id);
ALTER TABLE user_project_roles ADD PRIMARY KEY (id);
ALTER TABLE user_sessions ADD PRIMARY KEY (id);
ALTER TABLE webauthn_credentials ADD PRIMARY KEY (id);
ALTER TABLE webhook_deliveries ADD PRIMARY KEY (id);
ALTER TABLE webhook_endpoints ADD PRIMARY KEY (id);
ALTER TABLE admin_api_tokens ADD CONSTRAINT uq_admin_api_tokens_public_id UNIQUE (public_id);
ALTER TABLE admin_api_tokens ADD CONSTRAINT uq_admin_api_tokens_token_hash UNIQUE (token_hash);
ALTER TABLE admin_roles ADD CONSTRAINT uq_admin_roles_uniq_admin_user UNIQUE (user_id);
ALTER TABLE jwt_signing_keys ADD CONSTRAINT uq_jwt_signing_keys_kid UNIQUE (kid);
ALTER TABLE licence_renewal_reminders ADD CONSTRAINT uq_licence_renewal_reminders_uk_licence_reminder_recipient UNIQUE (licence_id, threshold_days, recipient_user_id);
ALTER TABLE licence_signing_keys ADD CONSTRAINT uq_licence_signing_keys_uk_licence_public_key UNIQUE (public_key_base64);
ALTER TABLE oauth_access_tokens ADD CONSTRAINT uq_oauth_access_tokens_token_hash UNIQUE (token_hash);
ALTER TABLE oauth_auth_codes ADD CONSTRAINT uq_oauth_auth_codes_code_hash UNIQUE (code_hash);
ALTER TABLE oauth_clients ADD CONSTRAINT uq_oauth_clients_client_id UNIQUE (client_id);
ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT uq_oauth_refresh_tokens_token_hash UNIQUE (token_hash);
ALTER TABLE oauth_scopes ADD CONSTRAINT uq_oauth_scopes_name UNIQUE (name);
ALTER TABLE organizations ADD CONSTRAINT uq_organizations_slug UNIQUE (slug);
ALTER TABLE organizations ADD CONSTRAINT uq_organizations_uuid UNIQUE (uuid);
ALTER TABLE organization_oidc_claim_defaults ADD CONSTRAINT uq_organization_oidc_claim_defaults_uk_org_claim_default UNIQUE (organization_id, claim_key);
ALTER TABLE org_custom_domains ADD CONSTRAINT uq_org_custom_domains_hostname UNIQUE (hostname);
ALTER TABLE projects ADD CONSTRAINT uq_projects_uuid UNIQUE (uuid);
ALTER TABLE project_licences ADD CONSTRAINT uq_project_licences_public_id UNIQUE (public_id);
ALTER TABLE project_oidc_claim_defaults ADD CONSTRAINT uq_project_oidc_claim_defaults_uk_project_claim_default UNIQUE (project_id, claim_key);
ALTER TABLE project_privilege_levels ADD CONSTRAINT uq_project_privilege_levels_uniq_project_level UNIQUE (project_id, level);
ALTER TABLE project_privilege_levels ADD CONSTRAINT uq_project_privilege_levels_uniq_project_name UNIQUE (project_id, name);
ALTER TABLE rate_limits ADD CONSTRAINT uq_rate_limits_uniq_identifier_action UNIQUE (identifier, action);
ALTER TABLE saml_service_providers ADD CONSTRAINT uq_saml_service_providers_public_id UNIQUE (public_id);
ALTER TABLE saml_service_providers ADD CONSTRAINT uq_saml_service_providers_uk_saml_sp_entity UNIQUE (project_id, entity_id);
ALTER TABLE scim_user_mapping ADD CONSTRAINT uq_scim_user_mapping_uk_scim_external UNIQUE (project_id, external_id);
ALTER TABLE users ADD CONSTRAINT uq_users_uuid UNIQUE (uuid);
ALTER TABLE user_oidc_claims ADD CONSTRAINT uq_user_oidc_claims_uk_user_claim UNIQUE (user_id, claim_key);
ALTER TABLE user_project_oidc_claims ADD CONSTRAINT uq_user_project_oidc_claims_uk_user_project_claim UNIQUE (user_id, project_id, claim_key);
ALTER TABLE user_project_roles ADD CONSTRAINT uq_user_project_roles_uniq_user_project UNIQUE (user_id, project_id);
ALTER TABLE user_sessions ADD CONSTRAINT uq_user_sessions_session_id UNIQUE (session_id);
ALTER TABLE webauthn_credentials ADD CONSTRAINT uq_webauthn_credentials_credential_id UNIQUE (credential_id);
ALTER TABLE webhook_endpoints ADD CONSTRAINT uq_webhook_endpoints_public_id UNIQUE (public_id);

CREATE INDEX ix_admin_api_tokens_idx_aat_user ON admin_api_tokens (user_id, revoked_at);
CREATE INDEX ix_admin_roles_idx_role_active ON admin_roles (role, is_active);
CREATE INDEX ix_approval_requests_approved_by_user_id ON approval_requests (approved_by_user_id);
CREATE INDEX ix_approval_requests_idx_action_status ON approval_requests (action_type, status);
CREATE INDEX ix_approval_requests_idx_project_status_created ON approval_requests (project_id, status, created_at);
CREATE INDEX ix_approval_requests_idx_requested_by ON approval_requests (requested_by_user_id);
CREATE INDEX ix_approval_requests_idx_status_action_created ON approval_requests (status, action_type, created_at);
CREATE INDEX ix_approval_requests_idx_status_created ON approval_requests (status, created_at);
CREATE INDEX ix_audit_chain_checkpoints_idx_ckpt_created ON audit_chain_checkpoints (created_at);
CREATE INDEX ix_audit_log_idx_actor_user_id ON audit_log (actor_user_id);
CREATE INDEX ix_audit_log_idx_chain_hash ON audit_log (chain_hash);
CREATE INDEX ix_audit_log_idx_client_created ON audit_log (oauth_client_public_id, created_at);
CREATE INDEX ix_audit_log_idx_correlation_id ON audit_log (correlation_id);
CREATE INDEX ix_audit_log_idx_created_at ON audit_log (created_at);
CREATE INDEX ix_audit_log_idx_credential_created ON audit_log (left(webauthn_credential_public_id, 255), created_at);
CREATE INDEX ix_audit_log_idx_event_type ON audit_log (event_type);
CREATE INDEX ix_audit_log_idx_ip_address ON audit_log (ip_address);
CREATE INDEX ix_audit_log_idx_ip_created ON audit_log (ip_address, created_at);
CREATE INDEX ix_audit_log_idx_oauth_client_public_id ON audit_log (oauth_client_public_id);
CREATE INDEX ix_audit_log_idx_org_created ON audit_log (organization_id, created_at);
CREATE INDEX ix_audit_log_idx_outcome ON audit_log (outcome);
CREATE INDEX ix_audit_log_idx_project_created ON audit_log (project_uuid, created_at);
CREATE INDEX ix_audit_log_idx_project_uuid ON audit_log (project_uuid);
CREATE INDEX ix_audit_log_idx_webauthn_credential_public_id ON audit_log (left(webauthn_credential_public_id, 255));
CREATE INDEX ix_audit_log_oauth_client_id ON audit_log (oauth_client_id);
CREATE INDEX ix_audit_log_project_id ON audit_log (project_id);
CREATE INDEX ix_audit_log_webauthn_credential_id ON audit_log (webauthn_credential_id);
CREATE INDEX ix_jwt_signing_keys_idx_is_active ON jwt_signing_keys (is_active);
CREATE INDEX ix_jwt_signing_keys_idx_kid ON jwt_signing_keys (kid);
CREATE INDEX ix_licence_renewal_reminders_idx_licence_reminder_project ON licence_renewal_reminders (licence_id, created_at);
CREATE INDEX ix_licence_renewal_reminders_idx_licence_reminder_queue ON licence_renewal_reminders (status, next_attempt_at);
CREATE INDEX ix_licence_renewal_reminders_recipient_user_id ON licence_renewal_reminders (recipient_user_id);
CREATE INDEX ix_maintenance_job_runs_idx_job_name_started ON maintenance_job_runs (job_name, started_at);
CREATE INDEX ix_maintenance_job_runs_idx_status_started ON maintenance_job_runs (status, started_at);
CREATE INDEX ix_oauth_access_tokens_idx_client_id ON oauth_access_tokens (client_id);
CREATE INDEX ix_oauth_access_tokens_idx_expires_at ON oauth_access_tokens (expires_at);
CREATE INDEX ix_oauth_access_tokens_idx_project_id ON oauth_access_tokens (project_id);
CREATE INDEX ix_oauth_access_tokens_idx_token_hash ON oauth_access_tokens (token_hash);
CREATE INDEX ix_oauth_access_tokens_idx_user_id ON oauth_access_tokens (user_id);
CREATE INDEX ix_oauth_auth_codes_idx_client_id ON oauth_auth_codes (client_id);
CREATE INDEX ix_oauth_auth_codes_idx_code_hash ON oauth_auth_codes (code_hash);
CREATE INDEX ix_oauth_auth_codes_idx_expires_at ON oauth_auth_codes (expires_at);
CREATE INDEX ix_oauth_auth_codes_project_id ON oauth_auth_codes (project_id);
CREATE INDEX ix_oauth_auth_codes_user_id ON oauth_auth_codes (user_id);
CREATE INDEX ix_oauth_clients_idx_client_id ON oauth_clients (client_id);
CREATE INDEX ix_oauth_clients_idx_project_id ON oauth_clients (project_id);
CREATE INDEX ix_oauth_clients_idx_status ON oauth_clients (status);
CREATE INDEX ix_oauth_refresh_tokens_idx_client_id ON oauth_refresh_tokens (client_id);
CREATE INDEX ix_oauth_refresh_tokens_idx_expires_at ON oauth_refresh_tokens (expires_at);
CREATE INDEX ix_oauth_refresh_tokens_idx_token_hash ON oauth_refresh_tokens (token_hash);
CREATE INDEX ix_oauth_refresh_tokens_idx_user_id ON oauth_refresh_tokens (user_id);
CREATE INDEX ix_oauth_refresh_tokens_project_id ON oauth_refresh_tokens (project_id);
CREATE INDEX ix_oauth_scopes_idx_name ON oauth_scopes (name);
CREATE INDEX ix_organizations_idx_org_admin_user ON organizations (admin_user_id);
CREATE INDEX ix_organizations_idx_org_status ON organizations (status);
CREATE INDEX ix_organization_oidc_claim_defaults_idx_org_claim_default ON organization_oidc_claim_defaults (organization_id, claim_key);
CREATE INDEX ix_org_custom_domains_organization_id ON org_custom_domains (organization_id);
CREATE INDEX ix_projects_idx_owner ON projects (owner_user_id);
CREATE INDEX ix_projects_idx_projects_org ON projects (organization_id);
CREATE INDEX ix_projects_idx_status ON projects (status);
CREATE INDEX ix_projects_idx_uuid ON projects (uuid);
CREATE INDEX ix_project_licences_idx_licence_key ON project_licences (signing_key_id);
CREATE INDEX ix_project_licences_idx_licence_project_status ON project_licences (project_id, revoked_at, expires_at);
CREATE INDEX ix_project_licences_issued_by_user_id ON project_licences (issued_by_user_id);
CREATE INDEX ix_project_licences_revoked_by_user_id ON project_licences (revoked_by_user_id);
CREATE INDEX ix_project_oidc_claim_defaults_idx_project_claim_default ON project_oidc_claim_defaults (project_id, claim_key);
CREATE INDEX ix_project_privilege_levels_idx_project_id ON project_privilege_levels (project_id);
CREATE INDEX ix_rate_limits_idx_blocked_until ON rate_limits (blocked_until);
CREATE INDEX ix_rate_limits_idx_identifier_action ON rate_limits (identifier, action);
CREATE INDEX ix_rate_limits_idx_window_start ON rate_limits (window_start);
CREATE INDEX ix_saml_service_providers_idx_saml_sp_project ON saml_service_providers (project_id, status);
CREATE INDEX ix_scim_user_mapping_idx_scim_user ON scim_user_mapping (user_id, project_id);
CREATE INDEX ix_users_idx_display_label ON users (display_label);
CREATE INDEX ix_users_idx_status ON users (status);
CREATE INDEX ix_users_idx_users_org ON users (organization_id);
CREATE INDEX ix_users_idx_uuid ON users (uuid);
CREATE INDEX ix_user_oidc_claims_idx_user_claim_key ON user_oidc_claims (user_id, claim_key);
CREATE INDEX ix_user_project_oidc_claims_idx_upc ON user_project_oidc_claims (user_id, project_id, claim_key);
CREATE INDEX ix_user_project_oidc_claims_project_id ON user_project_oidc_claims (project_id);
CREATE INDEX ix_user_project_roles_idx_privilege_level ON user_project_roles (privilege_level);
CREATE INDEX ix_user_project_roles_idx_project_id ON user_project_roles (project_id);
CREATE INDEX ix_user_project_roles_idx_user_id ON user_project_roles (user_id);
CREATE INDEX ix_user_sessions_idx_us_expiry ON user_sessions (expires_at, revoked_at);
CREATE INDEX ix_user_sessions_idx_us_user_active ON user_sessions (user_id, revoked_at, expires_at);
CREATE INDEX ix_webauthn_credentials_idx_credential_id ON webauthn_credentials (left(credential_id, 255));
CREATE INDEX ix_webauthn_credentials_idx_user_id ON webauthn_credentials (user_id);
CREATE INDEX ix_webhook_deliveries_endpoint_id ON webhook_deliveries (endpoint_id);
CREATE INDEX ix_webhook_deliveries_idx_wd_event ON webhook_deliveries (event_id);
CREATE INDEX ix_webhook_deliveries_idx_wd_pending ON webhook_deliveries (status, next_attempt_at);
CREATE INDEX ix_webhook_endpoints_idx_we_project ON webhook_endpoints (project_id, status);

ALTER TABLE approval_requests ADD CONSTRAINT ck_approval_requests_payload_json_json CHECK (bw_is_json(payload_json));
ALTER TABLE audit_log ADD CONSTRAINT ck_audit_log_metadata_json_json CHECK (metadata_json IS NULL OR bw_is_json(metadata_json));
ALTER TABLE maintenance_job_runs ADD CONSTRAINT ck_maintenance_job_runs_stats_json_json CHECK (stats_json IS NULL OR bw_is_json(stats_json));
ALTER TABLE webauthn_credentials ADD CONSTRAINT ck_webauthn_credentials_transports_json CHECK (transports IS NULL OR bw_is_json(transports));

ALTER TABLE admin_api_tokens ADD CONSTRAINT admin_api_tokens_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE admin_roles ADD CONSTRAINT admin_roles_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_ibfk_1 FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_ibfk_2 FOREIGN KEY (approved_by_user_id) REFERENCES users (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE approval_requests ADD CONSTRAINT fk_approval_requests_project FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_ibfk_1 FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_ibfk_2 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_ibfk_3 FOREIGN KEY (oauth_client_id) REFERENCES oauth_clients (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_ibfk_4 FOREIGN KEY (webauthn_credential_id) REFERENCES webauthn_credentials (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE audit_log ADD CONSTRAINT fk_audit_organization FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE licence_renewal_reminders ADD CONSTRAINT licence_renewal_reminders_ibfk_1 FOREIGN KEY (licence_id) REFERENCES project_licences (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE licence_renewal_reminders ADD CONSTRAINT licence_renewal_reminders_ibfk_2 FOREIGN KEY (recipient_user_id) REFERENCES users (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_access_tokens ADD CONSTRAINT oauth_access_tokens_ibfk_1 FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_access_tokens ADD CONSTRAINT oauth_access_tokens_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_access_tokens ADD CONSTRAINT oauth_access_tokens_ibfk_3 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_auth_codes ADD CONSTRAINT oauth_auth_codes_ibfk_1 FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_auth_codes ADD CONSTRAINT oauth_auth_codes_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_auth_codes ADD CONSTRAINT oauth_auth_codes_ibfk_3 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT oauth_refresh_tokens_ibfk_1 FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT oauth_refresh_tokens_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT oauth_refresh_tokens_ibfk_3 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE organizations ADD CONSTRAINT fk_organizations_admin_user FOREIGN KEY (admin_user_id) REFERENCES users (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE organization_oidc_claim_defaults ADD CONSTRAINT organization_oidc_claim_defaults_ibfk_1 FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE org_custom_domains ADD CONSTRAINT org_custom_domains_ibfk_1 FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE projects ADD CONSTRAINT fk_projects_organization FOREIGN KEY (organization_id) REFERENCES organizations (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_features ADD CONSTRAINT project_features_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_licences ADD CONSTRAINT project_licences_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_licences ADD CONSTRAINT project_licences_ibfk_2 FOREIGN KEY (issued_by_user_id) REFERENCES users (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_licences ADD CONSTRAINT project_licences_ibfk_3 FOREIGN KEY (revoked_by_user_id) REFERENCES users (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_licences ADD CONSTRAINT project_licences_ibfk_4 FOREIGN KEY (signing_key_id) REFERENCES licence_signing_keys (kid) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_oidc_claim_defaults ADD CONSTRAINT project_oidc_claim_defaults_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE project_privilege_levels ADD CONSTRAINT project_privilege_levels_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE saml_service_providers ADD CONSTRAINT saml_service_providers_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE scim_user_mapping ADD CONSTRAINT scim_user_mapping_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE scim_user_mapping ADD CONSTRAINT scim_user_mapping_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE users ADD CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE user_oidc_claims ADD CONSTRAINT user_oidc_claims_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE user_project_oidc_claims ADD CONSTRAINT user_project_oidc_claims_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE user_project_oidc_claims ADD CONSTRAINT user_project_oidc_claims_ibfk_2 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE user_project_roles ADD CONSTRAINT user_project_roles_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE user_project_roles ADD CONSTRAINT user_project_roles_ibfk_2 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE user_sessions ADD CONSTRAINT user_sessions_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE webauthn_credentials ADD CONSTRAINT webauthn_credentials_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE webhook_deliveries ADD CONSTRAINT webhook_deliveries_ibfk_1 FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE webhook_endpoints ADD CONSTRAINT webhook_endpoints_ibfk_1 FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;

CREATE TRIGGER tg_admin_roles_updated_at BEFORE UPDATE ON admin_roles
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_licence_renewal_reminders_updated_at BEFORE UPDATE ON licence_renewal_reminders
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_oauth_clients_updated_at BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_organization_oidc_claim_defaults_updated_at BEFORE UPDATE ON organization_oidc_claim_defaults
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_projects_updated_at BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_project_features_updated_at BEFORE UPDATE ON project_features
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_project_oidc_claim_defaults_updated_at BEFORE UPDATE ON project_oidc_claim_defaults
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_project_privilege_levels_updated_at BEFORE UPDATE ON project_privilege_levels
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_saml_service_providers_updated_at BEFORE UPDATE ON saml_service_providers
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_system_config_updated_at BEFORE UPDATE ON system_config
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_user_oidc_claims_updated_at BEFORE UPDATE ON user_oidc_claims
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_user_project_oidc_claims_updated_at BEFORE UPDATE ON user_project_oidc_claims
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_user_project_roles_updated_at BEFORE UPDATE ON user_project_roles
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_webhook_deliveries_updated_at BEFORE UPDATE ON webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();
CREATE TRIGGER tg_webhook_endpoints_updated_at BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION bw_touch_updated_at();

