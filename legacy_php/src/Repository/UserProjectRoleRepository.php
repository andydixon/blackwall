<?php

declare(strict_types=1);

namespace BlackWall\Repository;

use BlackWall\Database;
use BlackWall\Domain\UserProjectRole;
use PDO;

class UserProjectRoleRepository
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(int $userId, int $projectId, int $privilegeLevel): UserProjectRole
    {
        $stmt = $this->db->prepare(
            'INSERT INTO user_project_roles (user_id, project_id, privilege_level) VALUES (?, ?, ?)'
        );
        $stmt->execute([$userId, $projectId, $privilegeLevel]);

        return $this->findById((int) $this->db->lastInsertId());
    }

    public function findById(int $id): ?UserProjectRole
    {
        $stmt = $this->db->prepare('SELECT * FROM user_project_roles WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByUserAndProject(int $userId, int $projectId): ?UserProjectRole
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM user_project_roles WHERE user_id = ? AND project_id = ?'
        );
        $stmt->execute([$userId, $projectId]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findAllByUser(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM user_project_roles WHERE user_id = ?'
        );
        $stmt->execute([$userId]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function findAllByProject(int $projectId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM user_project_roles WHERE project_id = ?'
        );
        $stmt->execute([$projectId]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function update(int $id, int $privilegeLevel): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE user_project_roles SET privilege_level = ? WHERE id = ?'
        );
        return $stmt->execute([$privilegeLevel, $id]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM user_project_roles WHERE id = ?');
        return $stmt->execute([$id]);
    }

    private function hydrate(array $row): UserProjectRole
    {
        return new UserProjectRole(
            id: (int) $row['id'],
            userId: (int) $row['user_id'],
            projectId: (int) $row['project_id'],
            privilegeLevel: (int) $row['privilege_level'],
            createdAt: new \DateTimeImmutable($row['created_at'])
        );
    }
}
