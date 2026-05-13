-- Maintenance job run history
CREATE TABLE IF NOT EXISTS maintenance_job_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_name VARCHAR(100) NOT NULL,
    status ENUM('running', 'success', 'fail', 'skipped') NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    duration_ms INT UNSIGNED NULL,
    message VARCHAR(1000) NULL,
    stats_json JSON NULL,
    error_trace TEXT NULL,
    triggered_by VARCHAR(32) NOT NULL DEFAULT 'system',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_job_name_started (job_name, started_at),
    INDEX idx_status_started (status, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
