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

    public function cleanupAll(?int $auditRetentionDays = null, ?int $approvalPendingMaxAgeDays = null): array
    {
        return [
            'cleanup.tokens' => $this->cleanupTokens(),
            'cleanup.audit' => $this->cleanupAudit($auditRetentionDays),
            'cleanup.approvals' => $this->cleanupApprovals($approvalPendingMaxAgeDays),
        ];
    }

    public function cleanupApprovals(?int $maxPendingAgeDays = null): array
    {
        $days = $maxPendingAgeDays ?? Config::getInt('APPROVAL_PENDING_MAX_AGE_DAYS', 14);
        if ($days < 1) {
            $days = 1;
        }

        return $this->runJob('cleanup.approvals', function () use ($days): array {
            $stmt = $this->db->prepare(
                "UPDATE approval_requests
                 SET status = 'rejected',
                     decision_note = 'Auto-rejected: request expired',
                     decided_at = NOW()
                 WHERE status = 'pending'
                   AND created_at < DATE_SUB(NOW(), INTERVAL ? DAY)"
            );
            $stmt->execute([$days]);

            return [
                'approval_pending_max_age_days' => $days,
                'approval_requests_auto_rejected' => $stmt->rowCount(),
            ];
        });
    }

    public function verifyAuditChain(): array
    {
        return $this->runJob('audit.verify', function (): array {
            $stmt = $this->db->query(
                'SELECT id, event_type, outcome, message, correlation_id, ip_address, user_agent,
                        actor_user_id, actor_user_uuid, project_id, project_uuid,
                        oauth_client_id, oauth_client_public_id,
                        webauthn_credential_id, webauthn_credential_public_id,
                        target_type, target_id, metadata_json, chain_prev_hash, chain_hash
                 FROM audit_log
                 WHERE chain_hash IS NOT NULL
                 ORDER BY id ASC'
            );

            $rows = $stmt->fetchAll();
            $checked = 0;
            $broken = 0;
            $firstBrokenId = null;
            $prevHash = '';

            foreach ($rows as $row) {
                $payload = [
                    'event_type' => $row['event_type'],
                    'outcome' => $row['outcome'],
                    'message' => $row['message'],
                    'correlation_id' => $row['correlation_id'],
                    'ip_address' => $row['ip_address'],
                    'user_agent' => $row['user_agent'],
                    'actor_user_id' => $row['actor_user_id'],
                    'actor_user_uuid' => $row['actor_user_uuid'],
                    'project_id' => $row['project_id'],
                    'project_uuid' => $row['project_uuid'],
                    'oauth_client_id' => $row['oauth_client_id'],
                    'oauth_client_public_id' => $row['oauth_client_public_id'],
                    'webauthn_credential_id' => $row['webauthn_credential_id'],
                    'webauthn_credential_public_id' => $row['webauthn_credential_public_id'],
                    'target_type' => $row['target_type'],
                    'target_id' => $row['target_id'],
                    'metadata_json' => $row['metadata_json'],
                ];

                $payloadJson = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                $expectedHash = hash('sha256', $prevHash . '|' . $payloadJson);
                $currentPrevHash = (string) ($row['chain_prev_hash'] ?? '');
                $currentHash = (string) ($row['chain_hash'] ?? '');

                $checked++;
                if ($currentPrevHash !== $prevHash || $currentHash !== $expectedHash) {
                    $broken++;
                    if ($firstBrokenId === null) {
                        $firstBrokenId = (int) $row['id'];
                    }
                }

                $prevHash = $currentHash;
            }

            $result = [
                'checked' => $checked,
                'broken' => $broken,
                'first_broken_id' => $firstBrokenId,
            ];

            if ($broken > 0) {
                $first = $firstBrokenId !== null ? (string) $firstBrokenId : 'unknown';
                throw new \RuntimeException("Audit chain verification failed (broken={$broken}, first_broken_id={$first})");
            }

            return $result;
        });
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
