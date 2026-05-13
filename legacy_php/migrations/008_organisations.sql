-- Organisation tenancy foundation
SET @db_name := DATABASE();

CREATE TABLE IF NOT EXISTS organizations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(80) NOT NULL UNIQUE,
    logo_url VARCHAR(500) NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    admin_user_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_org_status (status),
    INDEX idx_org_admin_user (admin_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @default_org_uuid := '00000000-0000-0000-0000-000000000001';
INSERT INTO organizations (uuid, name, slug, status)
SELECT @default_org_uuid, 'Default Organisation', 'default', 'active'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM organizations WHERE uuid = @default_org_uuid);

SET @default_org_id := (SELECT id FROM organizations WHERE uuid = @default_org_uuid LIMIT 1);

SET @has_users_org_col := (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @db_name
      AND table_name = 'users'
      AND column_name = 'organization_id'
);
SET @sql_stmt := IF(
    @has_users_org_col = 0,
    'ALTER TABLE users ADD COLUMN organization_id BIGINT UNSIGNED NULL AFTER id',
    'SELECT 1'
);
PREPARE stmt FROM @sql_stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE users SET organization_id = @default_org_id WHERE organization_id IS NULL;

SET @sql_stmt := 'ALTER TABLE users MODIFY COLUMN organization_id BIGINT UNSIGNED NOT NULL';
PREPARE stmt2 FROM @sql_stmt;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

SET @has_users_org_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db_name
      AND table_name = 'users'
      AND index_name = 'idx_users_org'
);
SET @sql_stmt := IF(
    @has_users_org_idx = 0,
    'ALTER TABLE users ADD INDEX idx_users_org (organization_id)',
    'SELECT 1'
);
PREPARE stmt3 FROM @sql_stmt;
EXECUTE stmt3;
DEALLOCATE PREPARE stmt3;

SET @has_users_org_fk := (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = @db_name
      AND table_name = 'users'
      AND constraint_name = 'fk_users_organization'
);
SET @sql_stmt := IF(
    @has_users_org_fk = 0,
    'ALTER TABLE users ADD CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT',
    'SELECT 1'
);
PREPARE stmt4 FROM @sql_stmt;
EXECUTE stmt4;
DEALLOCATE PREPARE stmt4;

SET @has_projects_org_col := (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @db_name
      AND table_name = 'projects'
      AND column_name = 'organization_id'
);
SET @sql_stmt := IF(
    @has_projects_org_col = 0,
    'ALTER TABLE projects ADD COLUMN organization_id BIGINT UNSIGNED NULL AFTER id',
    'SELECT 1'
);
PREPARE stmt5 FROM @sql_stmt;
EXECUTE stmt5;
DEALLOCATE PREPARE stmt5;

UPDATE projects SET organization_id = @default_org_id WHERE organization_id IS NULL;

SET @sql_stmt := 'ALTER TABLE projects MODIFY COLUMN organization_id BIGINT UNSIGNED NOT NULL';
PREPARE stmt6 FROM @sql_stmt;
EXECUTE stmt6;
DEALLOCATE PREPARE stmt6;

SET @has_projects_org_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db_name
      AND table_name = 'projects'
      AND index_name = 'idx_projects_org'
);
SET @sql_stmt := IF(
    @has_projects_org_idx = 0,
    'ALTER TABLE projects ADD INDEX idx_projects_org (organization_id)',
    'SELECT 1'
);
PREPARE stmt7 FROM @sql_stmt;
EXECUTE stmt7;
DEALLOCATE PREPARE stmt7;

SET @has_projects_org_fk := (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = @db_name
      AND table_name = 'projects'
      AND constraint_name = 'fk_projects_organization'
);
SET @sql_stmt := IF(
    @has_projects_org_fk = 0,
    'ALTER TABLE projects ADD CONSTRAINT fk_projects_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT',
    'SELECT 1'
);
PREPARE stmt8 FROM @sql_stmt;
EXECUTE stmt8;
DEALLOCATE PREPARE stmt8;

SET @has_audit_org_col := (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @db_name
      AND table_name = 'audit_log'
      AND column_name = 'organization_id'
);
SET @sql_stmt := IF(
    @has_audit_org_col = 0,
    'ALTER TABLE audit_log ADD COLUMN organization_id BIGINT UNSIGNED NULL AFTER project_uuid',
    'SELECT 1'
);
PREPARE stmt9 FROM @sql_stmt;
EXECUTE stmt9;
DEALLOCATE PREPARE stmt9;

SET @has_audit_org_uuid_col := (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @db_name
      AND table_name = 'audit_log'
      AND column_name = 'organization_uuid'
);
SET @sql_stmt := IF(
    @has_audit_org_uuid_col = 0,
    'ALTER TABLE audit_log ADD COLUMN organization_uuid CHAR(36) NULL AFTER organization_id',
    'SELECT 1'
);
PREPARE stmt10 FROM @sql_stmt;
EXECUTE stmt10;
DEALLOCATE PREPARE stmt10;

UPDATE audit_log a
JOIN projects p ON p.id = a.project_id
SET a.organization_id = p.organization_id
WHERE a.organization_id IS NULL;

UPDATE audit_log a
JOIN users u ON u.id = a.actor_user_id
SET a.organization_id = u.organization_id
WHERE a.organization_id IS NULL;

UPDATE audit_log a
JOIN organizations o ON o.id = a.organization_id
SET a.organization_uuid = o.uuid
WHERE a.organization_id IS NOT NULL
  AND (a.organization_uuid IS NULL OR a.organization_uuid = '');

SET @has_audit_org_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db_name
      AND table_name = 'audit_log'
      AND index_name = 'idx_org_created'
);
SET @sql_stmt := IF(
    @has_audit_org_idx = 0,
    'ALTER TABLE audit_log ADD INDEX idx_org_created (organization_id, created_at)',
    'SELECT 1'
);
PREPARE stmt11 FROM @sql_stmt;
EXECUTE stmt11;
DEALLOCATE PREPARE stmt11;

SET @has_audit_org_fk := (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = @db_name
      AND table_name = 'audit_log'
      AND constraint_name = 'fk_audit_organization'
);
SET @sql_stmt := IF(
    @has_audit_org_fk = 0,
    'ALTER TABLE audit_log ADD CONSTRAINT fk_audit_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt12 FROM @sql_stmt;
EXECUTE stmt12;
DEALLOCATE PREPARE stmt12;

SET @has_org_admin_fk := (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = @db_name
      AND table_name = 'organizations'
      AND constraint_name = 'fk_organizations_admin_user'
);
SET @sql_stmt := IF(
    @has_org_admin_fk = 0,
    'ALTER TABLE organizations ADD CONSTRAINT fk_organizations_admin_user FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt13 FROM @sql_stmt;
EXECUTE stmt13;
DEALLOCATE PREPARE stmt13;

