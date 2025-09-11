<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Config;
use BlackWall\Database;
use PDO;

class MaintenanceService
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function cleanupTokens(): array
    {
        return $this->runJob('cleanup.tokens', function (): array {
            $stats = [];

            $stmt = $this->db->prepare(
                'DELETE FROM oauth_auth_codes
                 WHERE expires_at < NOW()
                    OR (used_at IS NOT NULL AND used_at < DATE_SUB(NOW(), INTERVAL 1 DAY))'
            );
            $stmt->execute();
            $stats['oauth_auth_codes_deleted'] = $stmt->rowCount();

            $stmt = $this->db->prepare(
                'DELETE FROM oauth_access_tokens
                 WHERE expires_at < NOW()
                    OR (revoked_at IS NOT NULL AND revoked_at < DATE_SUB(NOW(), INTERVAL 7 DAY))'
            );
            $stmt->execute();
            $stats['oauth_access_tokens_deleted'] = $stmt->rowCount();

            $stmt = $this->db->prepare(
                'DELETE FROM oauth_refresh_tokens
                 WHERE expires_at < NOW()
                    OR (revoked_at IS NOT NULL AND revoked_at < DATE_SUB(NOW(), INTERVAL 30 DAY))'
            );
            $stmt->execute();
            $stats['oauth_refresh_tokens_deleted'] = $stmt->rowCount();

            $stmt = $this->db->prepare(
                'DELETE FROM rate_limits
                 WHERE blocked_until IS NULL
                   AND window_start < DATE_SUB(NOW(), INTERVAL 2 DAY)'
            );
            $stmt->execute();
            $stats['rate_limits_deleted'] = $stmt->rowCount();

            return $stats;
        });
    }

    public function cleanupAudit(?int $retentionDays = null): array
    {
        $days = $retentionDays ?? Config::getInt('AUDIT_RETENTION_DAYS', 180);
        if ($days < 1) {
            $days = 1;
        }

        return $this->runJob('cleanup.audit', function () use ($days): array {
            $stmt = $this->db->prepare(
                'DELETE FROM audit_log
                 WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)'
            );
            $stmt->execute([$days]);

            return [
                'audit_retention_days' => $days,
                'audit_log_deleted' => $stmt->rowCount(),
            ];
        });
    }

    public function cleanupAll(?int $auditRetentionDays = null): array
    {
        return [
            'cleanup.tokens' => $this->cleanupTokens(),
            'cleanup.audit' => $this->cleanupAudit($auditRetentionDays),
        ];
    }

    public function getRecentRuns(int $limit = 50): array
    {
        $stmt = $this->db->prepare(
            'SELECT *
             FROM maintenance_job_runs
             ORDER BY started_at DESC, id DESC
             LIMIT ?'
        );
        $stmt->execute([$limit]);
        return $stmt->fetchAll();
    }

    private function runJob(string $jobName, callable $job): array
    {
        $lockName = 'blackwall:maintenance:' . $jobName;
        $lockStmt = $this->db->prepare('SELECT GET_LOCK(?, 0) AS acquired_lock');
        $lockStmt->execute([$lockName]);
        $lockResult = $lockStmt->fetch();
        $acquired = (int) ($lockResult['acquired_lock'] ?? 0) === 1;

        if (!$acquired) {
            $runId = $this->insertRun($jobName, 'skipped', 'Another run is already in progress');
            return [
                'run_id' => $runId,
                'job_name' => $jobName,
                'status' => 'skipped',
                'message' => 'Another run is already in progress',
                'stats' => [],
            ];
        }

        $startTs = microtime(true);
        $runId = $this->insertRun($jobName, 'running', 'Job started');

        try {
            $stats = (array) $job();
            $durationMs = (int) round((microtime(true) - $startTs) * 1000);
            $this->updateRun($runId, 'success', 'Job completed', $durationMs, $stats, null);

            return [
                'run_id' => $runId,
                'job_name' => $jobName,
                'status' => 'success',
                'message' => 'Job completed',
                'duration_ms' => $durationMs,
                'stats' => $stats,
            ];
        } catch (\Throwable $e) {
            $durationMs = (int) round((microtime(true) - $startTs) * 1000);
            $this->updateRun($runId, 'fail', $e->getMessage(), $durationMs, [], (string) $e);

            return [
                'run_id' => $runId,
                'job_name' => $jobName,
                'status' => 'fail',
                'message' => $e->getMessage(),
                'duration_ms' => $durationMs,
                'stats' => [],
            ];
        } finally {
            $unlockStmt = $this->db->prepare('SELECT RELEASE_LOCK(?)');
            $unlockStmt->execute([$lockName]);
        }
    }

    private function insertRun(string $jobName, string $status, string $message): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO maintenance_job_runs
             (job_name, status, started_at, message, triggered_by)
             VALUES (?, ?, NOW(), ?, ?)'
        );
        $stmt->execute([$jobName, $status, $message, PHP_SAPI === 'cli' ? 'cli' : 'web']);

        return (int) $this->db->lastInsertId();
    }

    private function updateRun(
        int $id,
        string $status,
        string $message,
        int $durationMs,
        array $stats,
        ?string $trace
    ): void {
        $stmt = $this->db->prepare(
            'UPDATE maintenance_job_runs
             SET status = ?, message = ?, duration_ms = ?, finished_at = NOW(),
                 stats_json = ?, error_trace = ?
             WHERE id = ?'
        );

        $stmt->execute([
            $status,
            substr($message, 0, 1000),
            $durationMs,
            !empty($stats) ? json_encode($stats) : null,
            $trace,
            $id,
        ]);
    }
}
