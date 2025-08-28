<?php

declare(strict_types=1);

namespace BlackWall\Repository;

use BlackWall\Database;
use BlackWall\Model\User;
use PDO;

class UserRepository
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(string $uuid, ?string $displayLabel, string $status = 'active'): User
    {
        $stmt = $this->db->prepare(
            'INSERT INTO users (uuid, display_label, status) VALUES (?, ?, ?)'
        );
        $stmt->execute([$uuid, $displayLabel, $status]);

        return $this->findById((int) $this->db->lastInsertId());
    }

    public function findById(int $id): ?User
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByUuid(string $uuid): ?User
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE uuid = ?');
        $stmt->execute([$uuid]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findAll(int $limit = 100, int $offset = 0): array
    {
        $stmt = $this->db->prepare('SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?');
        $stmt->execute([$limit, $offset]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function count(): int
    {
        $stmt = $this->db->query('SELECT COUNT(*) FROM users');
        return (int) $stmt->fetchColumn();
    }

    public function update(int $id, ?string $displayLabel, string $status): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET display_label = ?, status = ? WHERE id = ?'
        );
        return $stmt->execute([$displayLabel, $status, $id]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM users WHERE id = ?');
        return $stmt->execute([$id]);
    }

    private function hydrate(array $row): User
    {
        return new User(
            id: (int) $row['id'],
            uuid: $row['uuid'],
            displayLabel: $row['display_label'],
            status: $row['status'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            updatedAt: new \DateTimeImmutable($row['updated_at'])
        );
    }
}
