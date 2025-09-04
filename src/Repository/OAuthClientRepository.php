<?php

declare(strict_types=1);

namespace BlackWall\Repository;

use BlackWall\Database;
use BlackWall\Model\OAuthClient;
use PDO;

class OAuthClientRepository
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function create(array $data): OAuthClient
    {
        $stmt = $this->db->prepare(
            'INSERT INTO oauth_clients (client_id, client_secret_hash, project_id, name, redirect_uris, 
            grants, scopes, pkce_required, access_token_type, access_token_lifetime, 
            refresh_token_lifetime, oidc_enabled, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        
        $stmt->execute([
            $data['client_id'],
            $data['client_secret_hash'] ?? null,
            $data['project_id'],
            $data['name'],
            json_encode($data['redirect_uris']),
            json_encode($data['grants']),
            json_encode($data['scopes'] ?? []),
            $data['pkce_required'] ?? 1,
            $data['access_token_type'] ?? 'jwt',
            $data['access_token_lifetime'] ?? 3600,
            $data['refresh_token_lifetime'] ?? 2592000,
            $data['oidc_enabled'] ?? 1,
            $data['status'] ?? 'active'
        ]);

        return $this->findById((int) $this->db->lastInsertId());
    }

    public function findById(int $id): ?OAuthClient
    {
        $stmt = $this->db->prepare('SELECT * FROM oauth_clients WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findByClientId(string $clientId): ?OAuthClient
    {
        $stmt = $this->db->prepare('SELECT * FROM oauth_clients WHERE client_id = ?');
        $stmt->execute([$clientId]);
        $row = $stmt->fetch();

        return $row ? $this->hydrate($row) : null;
    }

    public function findAllByProject(int $projectId): array
    {
        $stmt = $this->db->prepare('SELECT * FROM oauth_clients WHERE project_id = ? ORDER BY created_at DESC');
        $stmt->execute([$projectId]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function update(int $id, array $data): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE oauth_clients SET name = ?, redirect_uris = ?, grants = ?, scopes = ?, 
            access_token_type = ?, access_token_lifetime = ?, refresh_token_lifetime = ?, 
            oidc_enabled = ?, status = ? WHERE id = ?'
        );

        return $stmt->execute([
            $data['name'],
            json_encode($data['redirect_uris']),
            json_encode($data['grants']),
            json_encode($data['scopes'] ?? []),
            $data['access_token_type'],
            $data['access_token_lifetime'],
            $data['refresh_token_lifetime'],
            $data['oidc_enabled'],
            $data['status'],
            $id
        ]);
    }

    private function hydrate(array $row): OAuthClient
    {
        return new OAuthClient(
            id: (int) $row['id'],
            clientId: $row['client_id'],
            clientSecretHash: $row['client_secret_hash'],
            projectId: (int) $row['project_id'],
            name: $row['name'],
            redirectUris: json_decode($row['redirect_uris'] ?? '[]', true) ?: [],
            grants: json_decode($row['grants'] ?? '[]', true) ?: [],
            scopes: json_decode($row['scopes'] ?? '[]', true) ?: [],
            pkceRequired: (bool) $row['pkce_required'],
            accessTokenType: $row['access_token_type'],
            accessTokenLifetime: (int) $row['access_token_lifetime'],
            refreshTokenLifetime: (int) $row['refresh_token_lifetime'],
            oidcEnabled: (bool) $row['oidc_enabled'],
            status: $row['status'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            updatedAt: new \DateTimeImmutable($row['updated_at'])
        );
    }
}
