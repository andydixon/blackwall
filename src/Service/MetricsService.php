<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use PDO;

class MetricsService
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function collect(): array
    {
        $totals = [
            'users' => (int) $this->db->query('SELECT COUNT(*) FROM users')->fetchColumn(),
            'projects' => (int) $this->db->query('SELECT COUNT(*) FROM projects')->fetchColumn(),
            'oauth_clients' => (int) $this->db->query('SELECT COUNT(*) FROM oauth_clients')->fetchColumn(),
            'webauthn_credentials' => (int) $this->db->query('SELECT COUNT(*) FROM webauthn_credentials')->fetchColumn(),
        ];

        $auditTotals = [
            'all_time' => (int) $this->db->query('SELECT COUNT(*) FROM audit_log')->fetchColumn(),
            'last_24h' => 0,
            'last_7d' => 0,
            'outcome_last_24h' => ['success' => 0, 'fail' => 0, 'info' => 0],
        ];

        $stmt = $this->db->query(
            "SELECT
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS c24h,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS c7d
             FROM audit_log"
        );
        $counts = $stmt->fetch();
        if ($counts) {
            $auditTotals['last_24h'] = (int) ($counts['c24h'] ?? 0);
            $auditTotals['last_7d'] = (int) ($counts['c7d'] ?? 0);
        }

        $stmt = $this->db->query(
            "SELECT outcome, COUNT(*) AS c
             FROM audit_log
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
             GROUP BY outcome"
        );
        foreach ($stmt->fetchAll() as $row) {
            $outcome = (string) $row['outcome'];
            if (isset($auditTotals['outcome_last_24h'][$outcome])) {
                $auditTotals['outcome_last_24h'][$outcome] = (int) $row['c'];
            }
        }

        $oauth = [
            'authorize_success_24h' => 0,
            'authorize_fail_24h' => 0,
            'token_issue_24h' => 0,
            'token_fail_24h' => 0,
        ];
        $stmt = $this->db->query(
            "SELECT
                SUM(event_type = 'oauth.authorize.approve' AND outcome = 'success') AS authorize_success,
                SUM(event_type = 'oauth.authorize.fail' AND outcome = 'fail') AS authorize_fail,
                SUM(event_type = 'oauth.token.issue' AND outcome = 'success') AS token_issue,
                SUM(event_type = 'oauth.token.fail' AND outcome = 'fail') AS token_fail
             FROM audit_log
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
        $row = $stmt->fetch();
        if ($row) {
            $oauth = [
                'authorize_success_24h' => (int) ($row['authorize_success'] ?? 0),
                'authorize_fail_24h' => (int) ($row['authorize_fail'] ?? 0),
                'token_issue_24h' => (int) ($row['token_issue'] ?? 0),
                'token_fail_24h' => (int) ($row['token_fail'] ?? 0),
            ];
        }

        $webauthn = [
            'auth_success_24h' => 0,
            'auth_fail_24h' => 0,
            'registration_success_24h' => 0,
            'registration_fail_24h' => 0,
        ];
        $stmt = $this->db->query(
            "SELECT
                SUM(event_type IN ('webauthn.authentication.success', 'portal.login.success', 'admin.login.success') AND outcome = 'success') AS auth_success,
                SUM(event_type IN ('webauthn.authentication.fail', 'portal.login.fail', 'admin.login.fail') AND outcome = 'fail') AS auth_fail,
                SUM(event_type = 'webauthn.registration.success' AND outcome = 'success') AS reg_success,
                SUM(event_type = 'webauthn.registration.fail' AND outcome = 'fail') AS reg_fail
             FROM audit_log
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
        $row = $stmt->fetch();
        if ($row) {
            $webauthn = [
                'auth_success_24h' => (int) ($row['auth_success'] ?? 0),
                'auth_fail_24h' => (int) ($row['auth_fail'] ?? 0),
                'registration_success_24h' => (int) ($row['reg_success'] ?? 0),
                'registration_fail_24h' => (int) ($row['reg_fail'] ?? 0),
            ];
        }

        $rateLimit = [
            'currently_blocked' => (int) $this->db
                ->query("SELECT COUNT(*) FROM rate_limits WHERE blocked_until IS NOT NULL AND blocked_until > NOW()")
                ->fetchColumn(),
        ];

        $maintenance = [
            'last_run' => null,
            'last_failure' => null,
        ];

        $stmt = $this->db->query(
            "SELECT job_name, status, started_at, finished_at, duration_ms, message
             FROM maintenance_job_runs
             ORDER BY started_at DESC, id DESC
             LIMIT 1"
        );
        $maintenance['last_run'] = $stmt->fetch() ?: null;

        $stmt = $this->db->query(
            "SELECT job_name, status, started_at, finished_at, duration_ms, message
             FROM maintenance_job_runs
             WHERE status = 'fail'
             ORDER BY started_at DESC, id DESC
             LIMIT 1"
        );
        $maintenance['last_failure'] = $stmt->fetch() ?: null;

        return [
            'generated_at' => gmdate('c'),
            'totals' => $totals,
            'audit' => $auditTotals,
            'oauth' => $oauth,
            'webauthn' => $webauthn,
            'rate_limits' => $rateLimit,
            'maintenance' => $maintenance,
        ];
    }
}
