-- Ensure rate limit rows are unique per identifier/action so UPSERT semantics work.
DELETE rl1
FROM rate_limits rl1
JOIN rate_limits rl2
  ON rl1.id < rl2.id
 AND rl1.identifier = rl2.identifier
 AND rl1.action = rl2.action;

SET @db_name := DATABASE();
SET @has_unique := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db_name
      AND table_name = 'rate_limits'
      AND index_name = 'uniq_identifier_action'
);
SET @sql_stmt := IF(
    @has_unique = 0,
    'ALTER TABLE rate_limits ADD UNIQUE KEY uniq_identifier_action (identifier, action)',
    'SELECT 1'
);
PREPARE stmt FROM @sql_stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Helpful indexes for approval queue filtering.
SET @has_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db_name
      AND table_name = 'approval_requests'
      AND index_name = 'idx_status_action_created'
);
SET @sql_stmt := IF(
    @has_idx = 0,
    'ALTER TABLE approval_requests ADD INDEX idx_status_action_created (status, action_type, created_at)',
    'SELECT 1'
);
PREPARE stmt2 FROM @sql_stmt;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

