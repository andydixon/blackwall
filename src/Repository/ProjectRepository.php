<?php

declare(strict_types=1);

namespace BlackWall\Repository;

use BlackWall\Database;
use BlackWall\Model\Project;
use PDO;

class ProjectRepository
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(string $uuid, string $name, ?int $ownerUserId, string $status = 'active'): Project
    {
        $stmt = $this->db->prepare(
            'INSERT INTO projects (uuid, name, owner_user_id, status) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$uuid, $name, $ownerUserId, $status]);

        return $this->findById((int) $this->db->lastInsertId());
    }

    public function findById(int $id): ?Project
    {
        $stmt = $this->db->prepare('SELECT * FROM projects WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByUuid(string $uuid): ?Project
    {
        $stmt = $this->db->prepare('SELECT * FROM projects WHERE uuid = ?');
        $stmt->execute([$uuid]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByName(string $name): ?Project
    {
        $stmt = $this->db->prepare('SELECT * FROM projects WHERE name = ?');
        $stmt->execute([$name]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findAll(int $limit = 100, int $offset = 0): array
    {
        $stmt = $this->db->prepare('SELECT * FROM projects ORDER BY created_at DESC LIMIT ? OFFSET ?');
        $stmt->execute([$limit, $offset]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function update(int $id, string $name, string $status): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE projects SET name = ?, status = ? WHERE id = ?'
        );
        return $stmt->execute([$name, $status, $id]);
    }

    private function hydrate(array $row): Project
    {
        return new Project(
            id: (int) $row['id'],
            uuid: $row['uuid'],
            name: $row['name'],
            ownerUserId: $row['owner_user_id'] ? (int) $row['owner_user_id'] : null,
            status: $row['status'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            updatedAt: new \DateTimeImmutable($row['updated_at'])
        );
    }
}
