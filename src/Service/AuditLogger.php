<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use PDO;

class AuditLogger
{
    private PDO $db;
    private ?string $correlationId = null;
    private ?string $ipAddress = null;
    private ?string $userAgent = null;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function setRequestContext(string $correlationId, string $ipAddress, ?string $userAgent): void
    {
        $this->correlationId = $correlationId;
        $this->ipAddress = $ipAddress;
        $this->userAgent = $userAgent;
    }

    public function logInfo(string $eventType, array $context = []): void
    {
        $this->log($eventType, 'info', $context);
    }

    public function logSuccess(string $eventType, array $context = []): void
    {
        $this->log($eventType, 'success', $context);
    }

    public function logFail(string $eventType, array $context = []): void
    {
        $this->log($eventType, 'fail', $context);
    }

    private function log(string $eventType, string $outcome, array $context): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO audit_log (
                created_at, event_type, outcome, message, correlation_id, ip_address, user_agent,
                actor_user_id, actor_user_uuid, project_id, project_uuid,
                oauth_client_id, oauth_client_public_id,
                webauthn_credential_id, webauthn_credential_public_id,
                target_type, target_id, metadata_json
            ) VALUES (
                NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )'
        );

        $metadata = $this->buildMetadata($context);

        $stmt->execute([
            $eventType,
            $outcome,
            $context['message'] ?? $this->generateMessage($eventType, $outcome),
            $context['correlation_id'] ?? $this->correlationId ?? $this->generateCorrelationId(),
            $context['ip_address'] ?? $this->ipAddress ?? '0.0.0.0',
            $context['user_agent'] ?? $this->userAgent,
            $context['actor_user_id'] ?? null,
            $context['actor_user_uuid'] ?? null,
            $context['project_id'] ?? null,
            $context['project_uuid'] ?? null,
            $context['oauth_client_id'] ?? null,
            $context['oauth_client_public_id'] ?? null,
            $context['webauthn_credential_id'] ?? null,
            $context['webauthn_credential_public_id'] ?? null,
            $context['target_type'] ?? null,
            $context['target_id'] ?? null,
            !empty($metadata) ? json_encode($metadata) : null
        ]);
    }

    private function buildMetadata(array $context): array
    {
        $metadata = [];
        
        $metadataKeys = [
            'requested_scopes', 'redirect_uri', 'error_code', 'failure_reason',
            'privilege_level', 'privilege_name', 'token_type', 'grant_type',
            'rp_id', 'origin', 'pkce_method', 'response_type', 'state'
        ];

        foreach ($metadataKeys as $key) {
            if (isset($context[$key])) {
                $metadata[$key] = $context[$key];
            }
        }

        return $metadata;
    }

    private function generateMessage(string $eventType, string $outcome): string
    {
        $action = str_replace(['.', '_'], ' ', $eventType);
        return ucfirst($action) . ' ' . $outcome;
    }

    private function generateCorrelationId(): string
    {
        return \Ramsey\Uuid\Uuid::uuid4()->toString();
    }

    public function search(array $filters, int $limit = 50, int $offset = 0): array
    {
        $conditions = [];
        $params = [];

        if (!empty($filters['date_from'])) {
            $conditions[] = 'created_at >= ?';
            $params[] = $filters['date_from'];
        }

        if (!empty($filters['date_to'])) {
            $conditions[] = 'created_at <= ?';
            $params[] = $filters['date_to'];
        }

        if (!empty($filters['project_uuid'])) {
            $conditions[] = 'project_uuid = ?';
            $params[] = $filters['project_uuid'];
        }

        if (!empty($filters['actor_user_uuid'])) {
            $conditions[] = 'actor_user_uuid = ?';
            $params[] = $filters['actor_user_uuid'];
        }

        if (!empty($filters['ip_address'])) {
            $conditions[] = 'ip_address = ?';
            $params[] = $filters['ip_address'];
        }

        if (!empty($filters['oauth_client_public_id'])) {
            $conditions[] = 'oauth_client_public_id = ?';
            $params[] = $filters['oauth_client_public_id'];
        }

        if (!empty($filters['event_type'])) {
            $conditions[] = 'event_type LIKE ?';
            $params[] = '%' . $filters['event_type'] . '%';
        }

        if (!empty($filters['outcome'])) {
            $conditions[] = 'outcome = ?';
            $params[] = $filters['outcome'];
        }

        if (!empty($filters['correlation_id'])) {
            $conditions[] = 'correlation_id = ?';
            $params[] = $filters['correlation_id'];
        }

        if (!empty($filters['search'])) {
            $conditions[] = '(message LIKE ? OR JSON_SEARCH(metadata_json, "one", ?) IS NOT NULL)';
            $searchTerm = '%' . $filters['search'] . '%';
            $params[] = $searchTerm;
            $params[] = $searchTerm;
        }

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $sql = "SELECT * FROM audit_log {$where} ORDER BY created_at DESC LIMIT ? OFFSET ?";
        
        $params[] = $limit;
        $params[] = $offset;

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetchAll();
    }

    public function countSearch(array $filters): int
    {
        $conditions = [];
        $params = [];

        if (!empty($filters['date_from'])) {
            $conditions[] = 'created_at >= ?';
            $params[] = $filters['date_from'];
        }

        if (!empty($filters['date_to'])) {
            $conditions[] = 'created_at <= ?';
            $params[] = $filters['date_to'];
        }

        if (!empty($filters['project_uuid'])) {
            $conditions[] = 'project_uuid = ?';
            $params[] = $filters['project_uuid'];
        }

        if (!empty($filters['actor_user_uuid'])) {
            $conditions[] = 'actor_user_uuid = ?';
            $params[] = $filters['actor_user_uuid'];
        }

        if (!empty($filters['ip_address'])) {
            $conditions[] = 'ip_address = ?';
            $params[] = $filters['ip_address'];
        }

        if (!empty($filters['event_type'])) {
            $conditions[] = 'event_type LIKE ?';
            $params[] = '%' . $filters['event_type'] . '%';
        }

        if (!empty($filters['outcome'])) {
            $conditions[] = 'outcome = ?';
            $params[] = $filters['outcome'];
        }

        $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $sql = "SELECT COUNT(*) FROM audit_log {$where}";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int) $stmt->fetchColumn();
    }
}
