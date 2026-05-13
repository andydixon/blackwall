-- Add tamper-evident chain fields to audit log (idempotent)
SET @add_prev_hash := (
    SELECT IF(
        EXISTS(
            SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'audit_log'
              AND COLUMN_NAME = 'chain_prev_hash'
        ),
        'SELECT 1',
        'ALTER TABLE audit_log ADD COLUMN chain_prev_hash CHAR(64) NULL AFTER metadata_json'
    )
);
PREPARE stmt_prev_hash FROM @add_prev_hash;
EXECUTE stmt_prev_hash;
DEALLOCATE PREPARE stmt_prev_hash;

SET @add_hash := (
    SELECT IF(
        EXISTS(
            SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'audit_log'
              AND COLUMN_NAME = 'chain_hash'
        ),
        'SELECT 1',
        'ALTER TABLE audit_log ADD COLUMN chain_hash CHAR(64) NULL AFTER chain_prev_hash'
    )
);
PREPARE stmt_hash FROM @add_hash;
EXECUTE stmt_hash;
DEALLOCATE PREPARE stmt_hash;

SET @add_hash_index := (
    SELECT IF(
        EXISTS(
            SELECT 1
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'audit_log'
              AND INDEX_NAME = 'idx_chain_hash'
        ),
        'SELECT 1',
        'ALTER TABLE audit_log ADD INDEX idx_chain_hash (chain_hash)'
    )
);
PREPARE stmt_hash_index FROM @add_hash_index;
EXECUTE stmt_hash_index;
DEALLOCATE PREPARE stmt_hash_index;
