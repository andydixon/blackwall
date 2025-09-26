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
