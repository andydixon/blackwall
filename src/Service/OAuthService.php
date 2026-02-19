<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use BlackWall\Domain\PrivilegeLabelResolver;
use BlackWall\Repository\OAuthClientRepository;
use BlackWall\Repository\UserProjectRoleRepository;
use BlackWall\Repository\PrivilegeLevelRepository;
use BlackWall\Security\TokenHasher;
use BlackWall\Security\PKCEValidator;
use BlackWall\Security\JWTManager;
use BlackWall\Security\RefreshTokenStatePolicy;
use PDO;

class OAuthService
{
    private PDO $db;
    private OAuthClientRepository $clientRepo;
    private UserProjectRoleRepository $roleRepo;
    private PrivilegeLevelRepository $privilegeRepo;
    private TokenHasher $hasher;
    private PKCEValidator $pkceValidator;
    private ?JWTManager $jwtManager;

    public function __construct()
    {
        $this->db = Database::getInstance();
        $this->clientRepo = new OAuthClientRepository();
        $this->roleRepo = new UserProjectRoleRepository();
        $this->privilegeRepo = new PrivilegeLevelRepository();
        $this->hasher = new TokenHasher();
        $this->pkceValidator = new PKCEValidator();
        $this->jwtManager = null;
    }

    private function getJWTManager(): JWTManager
    {
        if ($this->jwtManager === null) {
            $this->jwtManager = new JWTManager();
        }
        return $this->jwtManager;
    }

    public function createAuthorizationCode(array $data): string
    {
        $code = $this->hasher->generateBase64UrlToken(32);
        $codeHash = $this->hasher->hash($code);

        $expiresAt = (new \DateTimeImmutable())->modify('+10 minutes');

        $stmt = $this->db->prepare(
            'INSERT INTO oauth_auth_codes 
            (code_hash, client_id, user_id, project_id, redirect_uri, scopes, 
            code_challenge, code_challenge_method, nonce, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $codeHash,
            $data['client_id'],
            $data['user_id'],
            $data['project_id'],
            $data['redirect_uri'],
            json_encode($data['scopes'] ?? []),
            $data['code_challenge'],
            $data['code_challenge_method'] ?? 'S256',
            $data['nonce'] ?? null,
            $expiresAt->format('Y-m-d H:i:s'),
        ]);

        return $code;
    }

    public function exchangeAuthorizationCode(
        string $code,
        string $clientId,
        string $redirectUri,
        string $codeVerifier
    ): ?array {
        $codeHash = $this->hasher->hash($code);

        $stmt = $this->db->prepare(
            'SELECT ac.*, c.project_id, c.access_token_type, c.access_token_lifetime, 
            c.refresh_token_lifetime, c.oidc_enabled
            FROM oauth_auth_codes ac
            JOIN oauth_clients c ON c.id = ac.client_id
            WHERE ac.code_hash = ? AND c.client_id = ? AND c.status = ? AND ac.used_at IS NULL'
        );

        $stmt->execute([$codeHash, $clientId, 'active']);
        $authCode = $stmt->fetch();

        if (!$authCode) {
            return null;
        }

        if (new \DateTimeImmutable($authCode['expires_at']) < new \DateTimeImmutable()) {
            return null;
        }

        if ($authCode['redirect_uri'] !== $redirectUri) {
            return null;
        }

        if (!$this->pkceValidator->validateChallenge(
            $codeVerifier,
            $authCode['code_challenge'],
            $authCode['code_challenge_method']
        )) {
            return null;
        }

        $updateStmt = $this->db->prepare(
            'UPDATE oauth_auth_codes SET used_at = NOW() WHERE id = ? AND used_at IS NULL'
        );
        $updateStmt->execute([$authCode['id']]);
        if ($updateStmt->rowCount() !== 1) {
            return null;
        }

        $role = $this->roleRepo->findByUserAndProject(
            (int) $authCode['user_id'],
            (int) $authCode['project_id']
        );

        if (!$role) {
            return null;
        }

        $privilegeLevel = $this->privilegeRepo->findByProjectAndLevel(
            (int) $authCode['project_id'],
            $role->privilegeLevel
        );

        $scopes = json_decode($authCode['scopes'], true) ?: [];

        return $this->issueTokens(
            clientId: (int) $authCode['client_id'],
            userId: (int) $authCode['user_id'],
            projectId: (int) $authCode['project_id'],
            scopes: $scopes,
            privilegeLevel: $role->privilegeLevel,
            privilegeName: PrivilegeLabelResolver::resolve(
                $role->privilegeLevel,
                $privilegeLevel?->name
            ),
            tokenType: $authCode['access_token_type'],
            accessTokenLifetime: (int) $authCode['access_token_lifetime'],
            refreshTokenLifetime: (int) $authCode['refresh_token_lifetime'],
            nonce: $authCode['nonce'],
            oidcEnabled: (bool) $authCode['oidc_enabled']
        );
    }

    public function exchangeRefreshToken(string $refreshToken, string $clientPublicId): ?array
    {
        $refreshTokenHash = $this->hasher->hash($refreshToken);

        $stmt = $this->db->prepare(
            'SELECT
                rt.*,
                c.client_id AS oauth_client_public_id,
                c.access_token_type,
                c.access_token_lifetime,
                c.refresh_token_lifetime,
                c.oidc_enabled,
                c.status AS client_status
             FROM oauth_refresh_tokens rt
             JOIN oauth_clients c ON c.id = rt.client_id
             WHERE rt.token_hash = ? AND c.client_id = ?
             LIMIT 1'
        );
        $stmt->execute([$refreshTokenHash, $clientPublicId]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }

        if ((string) ($row['client_status'] ?? '') !== 'active') {
            return null;
        }

        $state = RefreshTokenStatePolicy::classify(
            $row['revoked_at'] ?? null,
            $row['expires_at'] ?? null
        );
        if ($state === RefreshTokenStatePolicy::STATE_REUSED) {
            $this->revokeTokenFamily((int) $row['client_id'], (int) $row['user_id'], (int) $row['project_id']);
            return null;
        }
        if ($state !== RefreshTokenStatePolicy::STATE_VALID) {
            return null;
        }

        $this->db->beginTransaction();
        try {
            $revokeCurrentStmt = $this->db->prepare(
                'UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE id = ? AND revoked_at IS NULL'
            );
            $revokeCurrentStmt->execute([(int) $row['id']]);
            if ($revokeCurrentStmt->rowCount() !== 1) {
                $this->db->rollBack();
                $this->revokeTokenFamily((int) $row['client_id'], (int) $row['user_id'], (int) $row['project_id']);
                return null;
            }

            $role = $this->roleRepo->findByUserAndProject(
                (int) $row['user_id'],
                (int) $row['project_id']
            );
            if (!$role) {
                $this->db->rollBack();
                return null;
            }

            $privilegeLevel = $this->privilegeRepo->findByProjectAndLevel(
                (int) $row['project_id'],
                $role->privilegeLevel
            );

            $scopes = json_decode((string) ($row['scopes'] ?? '[]'), true);
            $scopes = is_array($scopes) ? $scopes : [];

            $tokens = $this->issueTokens(
                clientId: (int) $row['client_id'],
                userId: (int) $row['user_id'],
                projectId: (int) $row['project_id'],
                scopes: $scopes,
                privilegeLevel: $role->privilegeLevel,
                privilegeName: PrivilegeLabelResolver::resolve(
                    $role->privilegeLevel,
                    $privilegeLevel?->name
                ),
                tokenType: (string) $row['access_token_type'],
                accessTokenLifetime: (int) $row['access_token_lifetime'],
                refreshTokenLifetime: (int) $row['refresh_token_lifetime'],
                nonce: null,
                oidcEnabled: (bool) $row['oidc_enabled']
            );

            $this->db->commit();
            return $tokens;
        } catch (\Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            return null;
        }
    }

    private function issueTokens(
        int $clientId,
        int $userId,
        int $projectId,
        array $scopes,
        int $privilegeLevel,
        string $privilegeName,
        string $tokenType,
        int $accessTokenLifetime,
        int $refreshTokenLifetime,
        ?string $nonce = null,
        bool $oidcEnabled = true
    ): ?array {
        $userStmt = $this->db->prepare("SELECT uuid, display_label FROM users WHERE id = ? AND status = 'active'");
        $userStmt->execute([$userId]);
        $user = $userStmt->fetch();
        if (!$user) {
            return null;
        }

        $projectStmt = $this->db->prepare("SELECT uuid FROM projects WHERE id = ? AND status = 'active'");
        $projectStmt->execute([$projectId]);
        $project = $projectStmt->fetch();
        if (!$project) {
            return null;
        }

        $clientStmt = $this->db->prepare("SELECT client_id FROM oauth_clients WHERE id = ? AND status = 'active'");
        $clientStmt->execute([$clientId]);
        $client = $clientStmt->fetch();
        if (!$client) {
            return null;
        }

        $response = [
            'token_type' => 'Bearer',
            'expires_in' => $accessTokenLifetime,
            'scope' => implode(' ', $scopes),
        ];
        if ($tokenType === 'jwt') {
            $expiresAt = (new \DateTimeImmutable())->modify("+{$accessTokenLifetime} seconds");
            $accessToken = $this->getJWTManager()->createAccessToken([
                'sub' => $user['uuid'],
                'aud' => $client['client_id'],
                'scope' => implode(' ', $scopes),
                'project_id' => $project['uuid'],
                'privilege_level' => $privilegeLevel,
                'privilege_name' => $privilegeName,
                'expires_in' => $accessTokenLifetime,
                'nonce' => $nonce,
            ]);

            $accessTokenHash = $this->hasher->hash($accessToken);
            $stmt = $this->db->prepare(
                'INSERT INTO oauth_access_tokens 
                (token_hash, client_id, user_id, project_id, scopes, privilege_level, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)'
            );
            $stmt->execute([
                $accessTokenHash,
                $clientId,
                $userId,
                $projectId,
                json_encode($scopes),
                $privilegeLevel,
                $expiresAt->format('Y-m-d H:i:s'),
            ]);

            $response['access_token'] = $accessToken;
        } else {
            $accessToken = $this->hasher->generateToken(32);
            $accessTokenHash = $this->hasher->hash($accessToken);
            $expiresAt = (new \DateTimeImmutable())->modify("+{$accessTokenLifetime} seconds");

            $stmt = $this->db->prepare(
                'INSERT INTO oauth_access_tokens 
                (token_hash, client_id, user_id, project_id, scopes, privilege_level, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $accessTokenHash,
                $clientId,
                $userId,
                $projectId,
                json_encode($scopes),
                $privilegeLevel,
                $expiresAt->format('Y-m-d H:i:s'),
            ]);
            $response['access_token'] = $accessToken;
        }

        if (in_array('offline_access', $scopes, true)) {
            $refreshToken = $this->hasher->generateToken(32);
            $refreshTokenHash = $this->hasher->hash($refreshToken);
            $refreshExpiresAt = (new \DateTimeImmutable())->modify("+{$refreshTokenLifetime} seconds");

            $stmt = $this->db->prepare(
                'INSERT INTO oauth_refresh_tokens 
                (token_hash, client_id, user_id, project_id, scopes, privilege_level, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $refreshTokenHash,
                $clientId,
                $userId,
                $projectId,
                json_encode($scopes),
                $privilegeLevel,
                $refreshExpiresAt->format('Y-m-d H:i:s'),
            ]);

            $response['refresh_token'] = $refreshToken;
        }

        if ($oidcEnabled && in_array('openid', $scopes, true)) {
            $idTokenClaims = [
                'sub' => $user['uuid'],
                'aud' => $client['client_id'],
                'nonce' => $nonce,
            ];

            if (in_array('email', $scopes, true) && $user['display_label']) {
                $idTokenClaims['email'] = $user['display_label'];
            }

            if (in_array('profile', $scopes, true) && $user['display_label']) {
                $idTokenClaims['name'] = $user['display_label'];
            }

            $response['id_token'] = $this->getJWTManager()->createIdToken($idTokenClaims);
        }

        return $response;
    }

    public function introspectToken(string $token, ?int $requestingClientId = null): array
    {
        $tokenHash = $this->hasher->hash($token);

        $sql = 'SELECT
                    t.id,
                    t.client_id AS token_client_id,
                    t.user_id,
                    t.project_id,
                    t.scopes,
                    t.privilege_level,
                    t.expires_at,
                    u.uuid AS user_uuid,
                    p.uuid AS project_uuid,
                    c.client_id AS token_client_public_id,
                    pl.name AS privilege_name
                FROM oauth_access_tokens t
                JOIN users u ON u.id = t.user_id
                JOIN projects p ON p.id = t.project_id
                JOIN oauth_clients c ON c.id = t.client_id
                LEFT JOIN project_privilege_levels pl ON pl.project_id = t.project_id AND pl.level = t.privilege_level
                WHERE t.token_hash = ? AND t.revoked_at IS NULL
                  AND u.status = \'active\'
                  AND p.status = \'active\'
                  AND c.status = \'active\'';
        $params = [$tokenHash];
        if ($requestingClientId !== null) {
            $sql .= ' AND t.client_id = ?';
            $params[] = $requestingClientId;
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $tokenData = $stmt->fetch();

        if (!$tokenData) {
            return ['active' => false];
        }

        $expiresAt = new \DateTimeImmutable($tokenData['expires_at']);
        if ($expiresAt < new \DateTimeImmutable()) {
            return ['active' => false];
        }

        return [
            'active' => true,
            'scope' => implode(' ', json_decode($tokenData['scopes'], true) ?: []),
            'client_id' => $tokenData['token_client_public_id'],
            'token_type' => 'Bearer',
            'exp' => $expiresAt->getTimestamp(),
            'sub' => $tokenData['user_uuid'],
            'aud' => $tokenData['token_client_public_id'],
            'iss' => \BlackWall\Config::get('APP_URL'),
            'project_id' => $tokenData['project_uuid'],
            'privilege_level' => (int) $tokenData['privilege_level'],
            'privilege_name' => PrivilegeLabelResolver::resolve(
                (int) $tokenData['privilege_level'],
                $tokenData['privilege_name'] ?? null
            ),
        ];
    }

    public function revokeToken(string $token, ?int $requestingClientId = null): bool
    {
        $tokenHash = $this->hasher->hash($token);

        $accessSql = 'UPDATE oauth_access_tokens SET revoked_at = NOW() WHERE token_hash = ?';
        $accessParams = [$tokenHash];
        if ($requestingClientId !== null) {
            $accessSql .= ' AND client_id = ?';
            $accessParams[] = $requestingClientId;
        }

        $stmt = $this->db->prepare($accessSql);
        $stmt->execute($accessParams);

        if ($stmt->rowCount() > 0) {
            return true;
        }

        $refreshSql = 'UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE token_hash = ?';
        $refreshParams = [$tokenHash];
        if ($requestingClientId !== null) {
            $refreshSql .= ' AND client_id = ?';
            $refreshParams[] = $requestingClientId;
        }

        $stmt = $this->db->prepare($refreshSql);
        $stmt->execute($refreshParams);

        return $stmt->rowCount() > 0;
    }

    private function revokeTokenFamily(int $clientId, int $userId, int $projectId): void
    {
        $refreshStmt = $this->db->prepare(
            'UPDATE oauth_refresh_tokens
             SET revoked_at = NOW()
             WHERE client_id = ? AND user_id = ? AND project_id = ? AND revoked_at IS NULL'
        );
        $refreshStmt->execute([$clientId, $userId, $projectId]);

        $accessStmt = $this->db->prepare(
            'UPDATE oauth_access_tokens
             SET revoked_at = NOW()
             WHERE client_id = ? AND user_id = ? AND project_id = ? AND revoked_at IS NULL'
        );
        $accessStmt->execute([$clientId, $userId, $projectId]);
    }
}
