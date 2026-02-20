<?php

declare(strict_types=1);

namespace BlackWall\Repository;

use BlackWall\Database;
use BlackWall\Model\Organization;
use PDO;

class OrganizationRepository
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(string $uuid, string $name, string $slug, ?string $logoUrl = null, ?int $adminUserId = null): Organization
    {
        $stmt = $this->db->prepare(
            'INSERT INTO organizations (uuid, name, slug, logo_url, status, admin_user_id) VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$uuid, $name, $slug, $logoUrl, 'active', $adminUserId]);

        return $this->findById((int) $this->db->lastInsertId());
    }

    public function findById(int $id): ?Organization
    {
        $stmt = $this->db->prepare('SELECT * FROM organizations WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByUuid(string $uuid): ?Organization
    {
        $stmt = $this->db->prepare('SELECT * FROM organizations WHERE uuid = ?');
        $stmt->execute([$uuid]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findBySlug(string $slug): ?Organization
    {
        $stmt = $this->db->prepare('SELECT * FROM organizations WHERE slug = ?');
        $stmt->execute([$slug]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findAll(int $limit = 100, int $offset = 0): array
    {
        $stmt = $this->db->prepare('SELECT * FROM organizations ORDER BY created_at DESC LIMIT ? OFFSET ?');
        $stmt->execute([$limit, $offset]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function update(int $id, string $name, string $slug, ?string $logoUrl, string $status, ?int $adminUserId): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE organizations SET name = ?, slug = ?, logo_url = ?, status = ?, admin_user_id = ? WHERE id = ?'
        );

        return $stmt->execute([$name, $slug, $logoUrl, $status, $adminUserId, $id]);
    }

    public function setAdminUser(int $id, int $adminUserId): bool
    {
        $stmt = $this->db->prepare('UPDATE organizations SET admin_user_id = ? WHERE id = ?');
        return $stmt->execute([$adminUserId, $id]);
    }

    public function findDefault(): ?Organization
    {
        return $this->findByUuid('00000000-0000-0000-0000-000000000001');
    }

    private function hydrate(array $row): Organization
    {
        return new Organization(
            id: (int) $row['id'],
            uuid: (string) $row['uuid'],
            name: (string) $row['name'],
            slug: (string) $row['slug'],
            logoUrl: $row['logo_url'] !== null ? (string) $row['logo_url'] : null,
            status: (string) $row['status'],
            adminUserId: $row['admin_user_id'] !== null ? (int) $row['admin_user_id'] : null,
            createdAt: new \DateTimeImmutable((string) $row['created_at']),
            updatedAt: new \DateTimeImmutable((string) $row['updated_at'])
        );
    }
}

