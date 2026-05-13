-- Add project scope to approval requests so non-super admins can view in-scope queue activity.
SET @db_name := DATABASE();

SET @has_project_id_col := (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = @db_name
      AND table_name = 'approval_requests'
      AND column_name = 'project_id'
);
SET @sql_stmt := IF(
    @has_project_id_col = 0,
    'ALTER TABLE approval_requests ADD COLUMN project_id BIGINT UNSIGNED NULL AFTER requested_by_user_id',
    'SELECT 1'
);
PREPARE stmt FROM @sql_stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_project_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db_name
      AND table_name = 'approval_requests'
      AND index_name = 'idx_project_status_created'
);
SET @sql_stmt := IF(
    @has_project_idx = 0,
    'ALTER TABLE approval_requests ADD INDEX idx_project_status_created (project_id, status, created_at)',
    'SELECT 1'
);
PREPARE stmt2 FROM @sql_stmt;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

SET @has_project_fk := (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = @db_name
      AND table_name = 'approval_requests'
      AND constraint_name = 'fk_approval_requests_project'
);
SET @sql_stmt := IF(
    @has_project_fk = 0,
    'ALTER TABLE approval_requests ADD CONSTRAINT fk_approval_requests_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt3 FROM @sql_stmt;
EXECUTE stmt3;
DEALLOCATE PREPARE stmt3;

-- Best-effort backfill for existing requests.
UPDATE approval_requests ar
JOIN projects p
  ON p.uuid = JSON_UNQUOTE(JSON_EXTRACT(ar.payload_json, '$.project_uuid'))
SET ar.project_id = p.id
WHERE ar.project_id IS NULL
  AND ar.action_type IN ('update_project_settings', 'change_project_status', 'create_assignment');

UPDATE approval_requests ar
JOIN oauth_clients c
  ON c.client_id = JSON_UNQUOTE(JSON_EXTRACT(ar.payload_json, '$.client_public_id'))
SET ar.project_id = c.project_id
WHERE ar.project_id IS NULL
  AND ar.action_type IN ('update_client_settings', 'change_client_status');

UPDATE approval_requests ar
JOIN user_project_roles upr
  ON upr.id = CAST(JSON_UNQUOTE(JSON_EXTRACT(ar.payload_json, '$.assignment_id')) AS UNSIGNED)
SET ar.project_id = upr.project_id
WHERE ar.project_id IS NULL
  AND ar.action_type IN ('update_assignment', 'delete_assignment');

UPDATE approval_requests ar
JOIN project_privilege_levels ppl
  ON ppl.id = CAST(JSON_UNQUOTE(JSON_EXTRACT(ar.payload_json, '$.level_id')) AS UNSIGNED)
SET ar.project_id = ppl.project_id
WHERE ar.project_id IS NULL
  AND ar.action_type = 'delete_privilege_level';
