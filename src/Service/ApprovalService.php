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

    public function create(string $actionType, array $payload, int $requestedByUserId): int
    {
        $stmt = $this->db->prepare(
            "INSERT INTO approval_requests (action_type, status, payload_json, requested_by_user_id)
             VALUES (?, 'pending', ?, ?)"
        );
        $stmt->execute([$actionType, json_encode($payload), $requestedByUserId]);
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
                    appr.display_label AS approved_by_display_label
             FROM approval_requests ar
             JOIN users req ON req.id = ar.requested_by_user_id
             LEFT JOIN users appr ON appr.id = ar.approved_by_user_id
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

    public function searchVisibleToUser(
        int $userId,
        bool $includeAll,
        array $filters,
        int $limit = 100,
        int $offset = 0
    ): array {
        $conditions = [];
        $params = [];

        if (!$includeAll) {
            $conditions[] = 'ar.requested_by_user_id = ?';
            $params[] = $userId;
        }

        if (!empty($filters['status'])) {
            $conditions[] = 'ar.status = ?';
            $params[] = (string) $filters['status'];
        }

        if (!empty($filters['action_type'])) {
            $conditions[] = 'ar.action_type LIKE ?';
            $params[] = '%' . (string) $filters['action_type'] . '%';
        }

        if ($includeAll && !empty($filters['requested_by_uuid'])) {
            $conditions[] = 'req.uuid = ?';
            $params[] = (string) $filters['requested_by_uuid'];
        }

        if (!empty($filters['date_from'])) {
            $conditions[] = 'ar.created_at >= ?';
            $params[] = (string) $filters['date_from'];
        }

        if (!empty($filters['date_to'])) {
            $conditions[] = 'ar.created_at <= ?';
            $params[] = (string) $filters['date_to'];
        }

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $sql = "SELECT ar.*,
                       req.uuid AS requested_by_uuid,
                       req.display_label AS requested_by_display_label,
                       appr.uuid AS approved_by_uuid,
                       appr.display_label AS approved_by_display_label
                FROM approval_requests ar
                JOIN users req ON req.id = ar.requested_by_user_id
                LEFT JOIN users appr ON appr.id = ar.approved_by_user_id
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

    public function countVisibleToUser(int $userId, bool $includeAll, array $filters): int
    {
        $conditions = [];
        $params = [];

        if (!$includeAll) {
            $conditions[] = 'ar.requested_by_user_id = ?';
            $params[] = $userId;
        }

        if (!empty($filters['status'])) {
            $conditions[] = 'ar.status = ?';
            $params[] = (string) $filters['status'];
        }

        if (!empty($filters['action_type'])) {
            $conditions[] = 'ar.action_type LIKE ?';
            $params[] = '%' . (string) $filters['action_type'] . '%';
        }

        if ($includeAll && !empty($filters['requested_by_uuid'])) {
            $conditions[] = 'req.uuid = ?';
            $params[] = (string) $filters['requested_by_uuid'];
        }

        if (!empty($filters['date_from'])) {
            $conditions[] = 'ar.created_at >= ?';
            $params[] = (string) $filters['date_from'];
        }

        if (!empty($filters['date_to'])) {
            $conditions[] = 'ar.created_at <= ?';
            $params[] = (string) $filters['date_to'];
        }

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $sql = "SELECT COUNT(*)
                FROM approval_requests ar
                JOIN users req ON req.id = ar.requested_by_user_id
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
}
