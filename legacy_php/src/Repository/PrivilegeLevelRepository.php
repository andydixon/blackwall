<?php

declare(strict_types=1);

namespace BlackWall\Repository;

use BlackWall\Database;
use BlackWall\Domain\PrivilegeLevel;
use PDO;

class PrivilegeLevelRepository
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(int $projectId, int $level, string $name, ?string $description): PrivilegeLevel
    {
        $stmt = $this->db->prepare(
            'INSERT INTO project_privilege_levels (project_id, level, name, description) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$projectId, $level, $name, $description]);

        return $this->findById((int) $this->db->lastInsertId());
    }

    public function findById(int $id): ?PrivilegeLevel
    {
        $stmt = $this->db->prepare('SELECT * FROM project_privilege_levels WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByProjectAndLevel(int $projectId, int $level): ?PrivilegeLevel
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM project_privilege_levels WHERE project_id = ? AND level = ?'
        );
        $stmt->execute([$projectId, $level]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByProjectAndName(int $projectId, string $name): ?PrivilegeLevel
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM project_privilege_levels WHERE project_id = ? AND name = ?'
        );
        $stmt->execute([$projectId, $name]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findAllByProject(int $projectId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM project_privilege_levels WHERE project_id = ? ORDER BY level ASC'
        );
        $stmt->execute([$projectId]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function update(int $id, string $name, ?string $description): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE project_privilege_levels SET name = ?, description = ? WHERE id = ?'
        );
        return $stmt->execute([$name, $description, $id]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM project_privilege_levels WHERE id = ?');
        return $stmt->execute([$id]);
    }

    public function isLevelInUse(int $projectId, int $level): bool
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM user_project_roles WHERE project_id = ? AND privilege_level = ?'
        );
        $stmt->execute([$projectId, $level]);
        return (int) $stmt->fetchColumn() > 0;
    }

    private function hydrate(array $row): PrivilegeLevel
    {
        return new PrivilegeLevel(
            id: (int) $row['id'],
            projectId: (int) $row['project_id'],
            level: (int) $row['level'],
            name: $row['name'],
            description: $row['description']
        );
    }
}
