<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use PDO;

class ApprovalService
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(string $actionType, array $payload, int $requestedByUserId, ?int $projectId = null): int
    {
        $stmt = $this->db->prepare(
            "INSERT INTO approval_requests (action_type, status, payload_json, requested_by_user_id, project_id)
             VALUES (?, 'pending', ?, ?, ?)"
        );
        $stmt->execute([$actionType, json_encode($payload), $requestedByUserId, $projectId]);
        return (int) $this->db->lastInsertId();
    }

    public function getById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM approval_requests WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function list(int $limit = 100): array
    {
        $stmt = $this->db->prepare(
            "SELECT ar.*,
                    req.uuid AS requested_by_uuid,
                    req.display_label AS requested_by_display_label,
                    appr.uuid AS approved_by_uuid,
                    appr.display_label AS approved_by_display_label,
                    p.uuid AS project_uuid,
                    p.name AS project_name
             FROM approval_requests ar
             JOIN users req ON req.id = ar.requested_by_user_id
             LEFT JOIN users appr ON appr.id = ar.approved_by_user_id
             LEFT JOIN projects p ON p.id = ar.project_id
             ORDER BY
                CASE ar.status WHEN 'pending' THEN 0 ELSE 1 END,
                ar.created_at DESC
             LIMIT ?"
        );
        $stmt->execute([$limit]);
        return $stmt->fetchAll();
    }

    public function listVisibleToUser(int $userId, bool $includeAll, int $limit = 100): array
    {
        return $this->searchVisibleToUser($userId, $includeAll, [], $limit, 0);
    }

    public function summariseVisibleToUser(int $userId, bool $includeAll, array $visibleProjectIds = []): array
    {
        [$conditions, $params] = $this->buildVisibilityConditions(
            '',
            $userId,
            $includeAll,
            $visibleProjectIds
        );

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $stmt = $this->db->prepare(
            "SELECT
                status,
                SUM(created_at >= CURDATE()) AS today_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
             FROM approval_requests
             {$where}
             GROUP BY status"
        );
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        $summary = [
            'pending' => ['today' => 0, 'week' => 0, 'month' => 0],
            'approved' => ['today' => 0, 'week' => 0, 'month' => 0],
            'rejected' => ['today' => 0, 'week' => 0, 'month' => 0],
            'cancelled' => ['today' => 0, 'week' => 0, 'month' => 0],
        ];

        foreach ($rows as $row) {
            $status = (string) ($row['status'] ?? '');
            if (!isset($summary[$status])) {
                continue;
            }
            $summary[$status] = [
                'today' => (int) ($row['today_count'] ?? 0),
                'week' => (int) ($row['week_count'] ?? 0),
                'month' => (int) ($row['month_count'] ?? 0),
            ];
        }

        return $summary;
    }

    public function summariseSlaVisibleToUser(
        int $userId,
        bool $includeAll,
        array $visibleProjectIds = [],
        int $pendingWarningDays = 3
    ): array {
        [$conditions, $params] = $this->buildVisibilityConditions(
            '',
            $userId,
            $includeAll,
            $visibleProjectIds
        );

        $pendingWhere = $conditions;
        $pendingWhere[] = "status = 'pending'";
        $pendingClause = 'WHERE ' . implode(' AND ', $pendingWhere);
        $pendingStmt = $this->db->prepare(
            "SELECT
                SUM(created_at < DATE_SUB(NOW(), INTERVAL ? DAY)) AS pending_older_than_threshold,
                MIN(created_at) AS oldest_pending_created_at
             FROM approval_requests
             {$pendingClause}"
        );
        $pendingStmt->execute(array_merge([$pendingWarningDays], $params));
        $pendingRow = $pendingStmt->fetch() ?: [];

        $latencyWhere = $conditions;
        $latencyWhere[] = "status IN ('approved', 'rejected')";
        $latencyClause = 'WHERE ' . implode(' AND ', $latencyWhere);
        $latencyStmt = $this->db->prepare(
            "SELECT TIMESTAMPDIFF(SECOND, created_at, decided_at) AS decision_seconds
             FROM approval_requests
             {$latencyClause}
             ORDER BY decision_seconds ASC"
        );
        $latencyStmt->execute($params);
        $latencies = array_values(array_map(
            static fn(array $row): int => (int) ($row['decision_seconds'] ?? 0),
            $latencyStmt->fetchAll()
        ));
        $latencies = array_values(array_filter($latencies, static fn(int $v): bool => $v >= 0));

        return [
            'decision_count' => count($latencies),
            'median_seconds' => $this->percentileSeconds($latencies, 50),
            'p95_seconds' => $this->percentileSeconds($latencies, 95),
            'pending_older_than_threshold' => (int) ($pendingRow['pending_older_than_threshold'] ?? 0),
            'pending_warning_days' => $pendingWarningDays,
            'oldest_pending_created_at' => $pendingRow['oldest_pending_created_at'] ?? null,
        ];
    }

    public function searchVisibleToUser(
        int $userId,
        bool $includeAll,
        array $filters,
        int $limit = 100,
        int $offset = 0,
        array $visibleProjectIds = []
    ): array {
        [$conditions, $params] = $this->buildVisibilityConditions(
            'ar',
            $userId,
            $includeAll,
            $visibleProjectIds
        );
        $this->applyCommonFilters($conditions, $params, $filters, $includeAll, 'ar');

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $sql = "SELECT ar.*,
                       req.uuid AS requested_by_uuid,
                       req.display_label AS requested_by_display_label,
                       appr.uuid AS approved_by_uuid,
                       appr.display_label AS approved_by_display_label,
                       p.uuid AS project_uuid,
                       p.name AS project_name,
                       (
                           SELECT JSON_UNQUOTE(JSON_EXTRACT(al.metadata_json, '$.failure_reason'))
                           FROM audit_log al
                           WHERE al.event_type = 'admin.approval.decision.denied'
                             AND al.target_type = 'approval_request'
                             AND CAST(al.target_id AS UNSIGNED) = ar.id
                           ORDER BY al.id DESC
                           LIMIT 1
                       ) AS latest_denial_reason
                FROM approval_requests ar
                JOIN users req ON req.id = ar.requested_by_user_id
                LEFT JOIN users appr ON appr.id = ar.approved_by_user_id
                LEFT JOIN projects p ON p.id = ar.project_id
                {$where}
                ORDER BY
                   CASE ar.status WHEN 'pending' THEN 0 ELSE 1 END,
                   ar.created_at DESC
                LIMIT ? OFFSET ?";

        $params[] = $limit;
        $params[] = $offset;

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function countVisibleToUser(int $userId, bool $includeAll, array $filters, array $visibleProjectIds = []): int
    {
        [$conditions, $params] = $this->buildVisibilityConditions(
            'ar',
            $userId,
            $includeAll,
            $visibleProjectIds
        );
        $this->applyCommonFilters($conditions, $params, $filters, $includeAll, 'ar');

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $sql = "SELECT COUNT(*)
                FROM approval_requests ar
                JOIN users req ON req.id = ar.requested_by_user_id
                LEFT JOIN projects p ON p.id = ar.project_id
                {$where}";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int) $stmt->fetchColumn();
    }

    public function listPendingByRequester(int $requestedByUserId, int $limit = 10): array
    {
        $stmt = $this->db->prepare(
            "SELECT id, action_type, status, payload_json, created_at
             FROM approval_requests
             WHERE requested_by_user_id = ? AND status = 'pending'
             ORDER BY created_at DESC
             LIMIT ?"
        );
        $stmt->execute([$requestedByUserId, $limit]);
        return $stmt->fetchAll();
    }

    public function decide(int $id, string $status, int $approvedByUserId, ?string $note = null): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE approval_requests
             SET status = ?, approved_by_user_id = ?, decision_note = ?, decided_at = NOW()
             WHERE id = ? AND status = \'pending\''
        );
        $stmt->execute([$status, $approvedByUserId, $note, $id]);
        return $stmt->rowCount() > 0;
    }

    public function cancelByRequester(int $id, int $requestedByUserId, ?string $note = null): bool
    {
        $stmt = $this->db->prepare(
            "UPDATE approval_requests
             SET status = 'cancelled', decision_note = ?, decided_at = NOW()
             WHERE id = ? AND status = 'pending' AND requested_by_user_id = ?"
        );
        $stmt->execute([$note, $id, $requestedByUserId]);
        return $stmt->rowCount() > 0;
    }

    private function buildVisibilityConditions(
        string $alias,
        int $userId,
        bool $includeAll,
        array $visibleProjectIds
    ): array {
        $conditions = [];
        $params = [];
        $prefix = $alias !== '' ? $alias . '.' : '';

        if (!$includeAll) {
            if (empty($visibleProjectIds)) {
                $conditions[] = $prefix . 'requested_by_user_id = ?';
                $params[] = $userId;
            } else {
                $placeholders = implode(',', array_fill(0, count($visibleProjectIds), '?'));
                $conditions[] = '(' . $prefix . "requested_by_user_id = ? OR {$prefix}project_id IN ({$placeholders}))";
                $params[] = $userId;
                $params = array_merge($params, $visibleProjectIds);
            }
        }

        return [$conditions, $params];
    }

    private function applyCommonFilters(
        array &$conditions,
        array &$params,
        array $filters,
        bool $includeAll,
        string $approvalAlias
    ): void {
        if (!empty($filters['status'])) {
            $conditions[] = $approvalAlias . '.status = ?';
            $params[] = (string) $filters['status'];
        }

        if (!empty($filters['action_type'])) {
            $conditions[] = $approvalAlias . '.action_type LIKE ?';
            $params[] = '%' . (string) $filters['action_type'] . '%';
        }

        if ($includeAll && !empty($filters['requested_by_uuid'])) {
            $conditions[] = 'req.uuid = ?';
            $params[] = (string) $filters['requested_by_uuid'];
        }

        if (!empty($filters['project_uuid'])) {
            $conditions[] = 'p.uuid = ?';
            $params[] = (string) $filters['project_uuid'];
        }

        if (!empty($filters['failure_reason'])) {
            $conditions[] = "EXISTS (
                SELECT 1
                FROM audit_log al
                WHERE al.event_type = 'admin.approval.decision.denied'
                  AND al.target_type = 'approval_request'
                  AND CAST(al.target_id AS UNSIGNED) = {$approvalAlias}.id
                  AND JSON_UNQUOTE(JSON_EXTRACT(al.metadata_json, '$.failure_reason')) = ?
            )";
            $params[] = (string) $filters['failure_reason'];
        }

        if (!empty($filters['date_from'])) {
            $conditions[] = $approvalAlias . '.created_at >= ?';
            $params[] = (string) $filters['date_from'];
        }

        if (!empty($filters['date_to'])) {
            $conditions[] = $approvalAlias . '.created_at <= ?';
            $params[] = (string) $filters['date_to'];
        }
    }

    private function percentileSeconds(array $values, int $percentile): int
    {
        if (empty($values)) {
            return 0;
        }

        $n = count($values);
        $rank = max(1, (int) ceil(($percentile / 100) * $n));
        $index = min($n - 1, $rank - 1);
        return (int) $values[$index];
    }
}
