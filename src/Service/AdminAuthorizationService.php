<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use PDO;

class AdminAuthorizationService
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function hasConfiguredRoles(): bool
    {
        $stmt = $this->db->query('SELECT COUNT(*) FROM admin_roles WHERE is_active = 1');
        return (int) $stmt->fetchColumn() > 0;
    }

    public function isAdmin(int $userId): bool
    {
        if (!$this->hasConfiguredRoles()) {
            // Backward-compatible fallback while RBAC is being introduced.
            return true;
        }

        return $this->getRole($userId) !== null;
    }

    public function getRole(int $userId): ?string
    {
        if (!$this->hasConfiguredRoles()) {
            return 'super_admin';
        }

        $stmt = $this->db->prepare(
            'SELECT role FROM admin_roles WHERE user_id = ? AND is_active = 1 LIMIT 1'
        );
        $stmt->execute([$userId]);
        $role = $stmt->fetchColumn();
        return $role !== false ? (string) $role : null;
    }

    public function isSuperAdmin(int $userId): bool
    {
        return $this->getRole($userId) === 'super_admin';
    }

    public function listRoles(): array
    {
        $stmt = $this->db->query(
            "SELECT ar.id, ar.user_id, ar.role, ar.is_active, ar.created_at, ar.updated_at,
                    u.uuid AS user_uuid, u.display_label, u.status AS user_status
             FROM admin_roles ar
             JOIN users u ON u.id = ar.user_id
             ORDER BY ar.role ASC, ar.created_at DESC"
        );
        return $stmt->fetchAll();
    }

    public function upsertRole(int $userId, string $role): void
    {
        $stmt = $this->db->prepare(
            "INSERT INTO admin_roles (user_id, role, is_active)
             VALUES (?, ?, 1)
             ON DUPLICATE KEY UPDATE role = VALUES(role), is_active = 1"
        );
        $stmt->execute([$userId, $role]);
    }

    public function revokeRole(int $userId): void
    {
        $stmt = $this->db->prepare(
            'UPDATE admin_roles SET is_active = 0 WHERE user_id = ?'
        );
        $stmt->execute([$userId]);
    }

    public function countActiveRole(string $role): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM admin_roles WHERE role = ? AND is_active = 1'
        );
        $stmt->execute([$role]);
        return (int) $stmt->fetchColumn();
    }

    public function countActiveRoleOnActiveUsers(string $role): int
    {
        $stmt = $this->db->prepare(
            "SELECT COUNT(*)
             FROM admin_roles ar
             JOIN users u ON u.id = ar.user_id
             WHERE ar.role = ? AND ar.is_active = 1 AND u.status = 'active'"
        );
        $stmt->execute([$role]);
        return (int) $stmt->fetchColumn();
    }
}
