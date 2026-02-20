<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Service\EventMetricPusher;
use BlackWall\Database;
use PDO;

class AuditLogger
{
    private PDO $db;
    private ?string $correlationId = null;
    private ?string $ipAddress = null;
    private ?string $userAgent = null;
    private EventMetricPusher $eventMetricPusher;

    public function __construct()
    {
        $this->db = Database::getInstance();
        $this->eventMetricPusher = new EventMetricPusher();
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
        if (isset($context['webauthn_credential_id']) && $context['webauthn_credential_id'] !== null) {
            $credentialId = (int) $context['webauthn_credential_id'];
            $checkStmt = $this->db->prepare('SELECT 1 FROM webauthn_credentials WHERE id = ?');
            $checkStmt->execute([$credentialId]);
            if (!$checkStmt->fetchColumn()) {
                $context['webauthn_credential_id'] = null;
            }
        }

        $metadata = $this->buildMetadata($context);
        $message = $context['message'] ?? $this->generateMessage($eventType, $outcome);
        $correlationId = $context['correlation_id'] ?? $this->correlationId ?? $this->generateCorrelationId();
        $ipAddress = $context['ip_address'] ?? $this->ipAddress ?? '0.0.0.0';
        $userAgent = $context['user_agent'] ?? $this->userAgent;
        $actorUserId = $context['actor_user_id'] ?? null;
        $actorUserUuid = $context['actor_user_uuid'] ?? null;
        $projectId = $context['project_id'] ?? null;
        $projectUuid = $context['project_uuid'] ?? null;
        $organizationId = $context['organization_id'] ?? null;
        $organizationUuid = $context['organization_uuid'] ?? null;
        $oauthClientId = $context['oauth_client_id'] ?? null;
        $oauthClientPublicId = $context['oauth_client_public_id'] ?? null;
        $credentialDbId = $context['webauthn_credential_id'] ?? null;
        $credentialPublicId = $context['webauthn_credential_public_id'] ?? null;
        $targetType = $context['target_type'] ?? null;
        $targetId = $context['target_id'] ?? null;
        $metadataJson = !empty($metadata) ? json_encode($metadata) : null;

        if ($organizationId === null && $projectId !== null) {
            $orgLookup = $this->db->prepare(
                'SELECT o.id, o.uuid
                 FROM projects p
                 JOIN organizations o ON o.id = p.organization_id
                 WHERE p.id = ?'
            );
            $orgLookup->execute([(int) $projectId]);
            $row = $orgLookup->fetch();
            if ($row) {
                $organizationId = (int) $row['id'];
                $organizationUuid = (string) $row['uuid'];
            }
        }
        if ($organizationId === null && $actorUserId !== null) {
            $orgLookup = $this->db->prepare(
                'SELECT o.id, o.uuid
                 FROM users u
                 JOIN organizations o ON o.id = u.organization_id
                 WHERE u.id = ?'
            );
            $orgLookup->execute([(int) $actorUserId]);
            $row = $orgLookup->fetch();
            if ($row) {
                $organizationId = (int) $row['id'];
                $organizationUuid = (string) $row['uuid'];
            }
        }
        if ($organizationId !== null && $organizationUuid === null) {
            $orgLookup = $this->db->prepare('SELECT uuid FROM organizations WHERE id = ?');
            $orgLookup->execute([(int) $organizationId]);
            $organizationUuid = (string) ($orgLookup->fetchColumn() ?: '');
            if ($organizationUuid === '') {
                $organizationUuid = null;
            }
        }

        $this->db->beginTransaction();

        $lockStmt = $this->db->prepare('SELECT GET_LOCK(?, 2) AS lock_acquired');
        $lockStmt->execute(['blackwall:audit_chain']);
        $lockRow = $lockStmt->fetch();
        $lockAcquired = (int) ($lockRow['lock_acquired'] ?? 0) === 1;
        if (!$lockAcquired) {
            $this->db->rollBack();
            throw new \RuntimeException('Failed to acquire audit chain lock');
        }

        $stmt = $this->db->prepare(
            'INSERT INTO audit_log (
                created_at, event_type, outcome, message, correlation_id, ip_address, user_agent,
                actor_user_id, actor_user_uuid, project_id, project_uuid, organization_id, organization_uuid,
                oauth_client_id, oauth_client_public_id,
                webauthn_credential_id, webauthn_credential_public_id,
                target_type, target_id, metadata_json,
                chain_prev_hash, chain_hash
            ) VALUES (
                NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )'
        );

        try {
            $prevHashStmt = $this->db->query(
                'SELECT chain_hash FROM audit_log
                 WHERE chain_hash IS NOT NULL
                 ORDER BY id DESC
                 LIMIT 1'
            );
            $prevHash = (string) ($prevHashStmt->fetchColumn() ?: '');

            $chainPayload = [
                'event_type' => $eventType,
                'outcome' => $outcome,
                'message' => $message,
                'correlation_id' => $correlationId,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
                'actor_user_id' => $actorUserId,
                'actor_user_uuid' => $actorUserUuid,
                'project_id' => $projectId,
                'project_uuid' => $projectUuid,
                'organization_id' => $organizationId,
                'organization_uuid' => $organizationUuid,
                'oauth_client_id' => $oauthClientId,
                'oauth_client_public_id' => $oauthClientPublicId,
                'webauthn_credential_id' => $credentialDbId,
                'webauthn_credential_public_id' => $credentialPublicId,
                'target_type' => $targetType,
                'target_id' => $targetId,
                'metadata_json' => $metadataJson,
            ];

            $payloadJson = json_encode($chainPayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $chainHash = hash('sha256', $prevHash . '|' . $payloadJson);
            $chainPrevHash = $prevHash !== '' ? $prevHash : null;

            $stmt->execute([
                $eventType,
                $outcome,
                $message,
                $correlationId,
                $ipAddress,
                $userAgent,
                $actorUserId,
                $actorUserUuid,
                $projectId,
                $projectUuid,
                $organizationId,
                $organizationUuid,
                $oauthClientId,
                $oauthClientPublicId,
                $credentialDbId,
                $credentialPublicId,
                $targetType,
                $targetId,
                $metadataJson,
                $chainPrevHash,
                $chainHash,
            ]);

            $this->db->commit();
            $this->eventMetricPusher->pushEvent($eventType, $outcome);
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        } finally {
            $unlockStmt = $this->db->prepare('SELECT RELEASE_LOCK(?)');
            $unlockStmt->execute(['blackwall:audit_chain']);
        }
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

        if (!empty($filters['organization_uuid'])) {
            $conditions[] = 'organization_uuid = ?';
            $params[] = $filters['organization_uuid'];
        }

        if (!empty($filters['organization_ids']) && is_array($filters['organization_ids'])) {
            $organizationIds = array_values(array_filter(array_map('intval', $filters['organization_ids']), static fn(int $v): bool => $v > 0));
            if (!empty($organizationIds)) {
                $placeholders = implode(',', array_fill(0, count($organizationIds), '?'));
                $conditions[] = "organization_id IN ({$placeholders})";
                foreach ($organizationIds as $organizationId) {
                    $params[] = $organizationId;
                }
            }
        }

        if (!empty($filters['project_ids']) && is_array($filters['project_ids'])) {
            $projectIds = array_values(array_filter(array_map('intval', $filters['project_ids']), static fn(int $v): bool => $v > 0));
            if (!empty($projectIds)) {
                $placeholders = implode(',', array_fill(0, count($projectIds), '?'));
                $conditions[] = "project_id IN ({$placeholders})";
                foreach ($projectIds as $projectId) {
                    $params[] = $projectId;
                }
            }
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

        if (!empty($filters['organization_uuid'])) {
            $conditions[] = 'organization_uuid = ?';
            $params[] = $filters['organization_uuid'];
        }

        if (!empty($filters['organization_ids']) && is_array($filters['organization_ids'])) {
            $organizationIds = array_values(array_filter(array_map('intval', $filters['organization_ids']), static fn(int $v): bool => $v > 0));
            if (!empty($organizationIds)) {
                $placeholders = implode(',', array_fill(0, count($organizationIds), '?'));
                $conditions[] = "organization_id IN ({$placeholders})";
                foreach ($organizationIds as $organizationId) {
                    $params[] = $organizationId;
                }
            }
        }

        if (!empty($filters['project_ids']) && is_array($filters['project_ids'])) {
            $projectIds = array_values(array_filter(array_map('intval', $filters['project_ids']), static fn(int $v): bool => $v > 0));
            if (!empty($projectIds)) {
                $placeholders = implode(',', array_fill(0, count($projectIds), '?'));
                $conditions[] = "project_id IN ({$placeholders})";
                foreach ($projectIds as $projectId) {
                    $params[] = $projectId;
                }
            }
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
