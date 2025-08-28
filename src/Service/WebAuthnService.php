<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\ECDSA\ES256;
use PDO;

class WebAuthnService
{
    private PDO $db;
    private string $rpId;
    private string $rpName;

    public function __construct()
    {
        $this->db = Database::getInstance();
        $this->rpId = \BlackWall\Config::get('WEBAUTHN_RP_ID');
        $this->rpName = \BlackWall\Config::get('WEBAUTHN_RP_NAME');
    }

    public function generateRegistrationOptions(string $userUuid, string $userName): array
    {
        $rpEntity = new PublicKeyCredentialRpEntity(
            $this->rpName,
            $this->rpId
        );

        $userEntity = new PublicKeyCredentialUserEntity(
            $userName,
            $userUuid,
            $userName
        );

        $challenge = random_bytes(32);

        $publicKeyCredentialParametersList = [
            new PublicKeyCredentialParameters('public-key', -7),  // ES256
            new PublicKeyCredentialParameters('public-key', -257), // RS256
        ];

        $authenticatorSelection = new AuthenticatorSelectionCriteria(
            null,
            false,
            'preferred'
        );

        $options = new PublicKeyCredentialCreationOptions(
            $rpEntity,
            $userEntity,
            $challenge,
            $publicKeyCredentialParametersList
        );

        $options = $options
            ->setTimeout(60000)
            ->setAuthenticatorSelection($authenticatorSelection);

        return [
            'challenge' => base64_encode($challenge),
            'rp' => [
                'name' => $this->rpName,
                'id' => $this->rpId,
            ],
            'user' => [
                'id' => base64_encode($userUuid),
                'name' => $userName,
                'displayName' => $userName,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -257],
            ],
            'timeout' => 60000,
            'attestation' => 'none',
            'authenticatorSelection' => [
                'userVerification' => 'preferred',
            ],
        ];
    }

    public function generateAuthenticationOptions(int $userId): array
    {
        $challenge = random_bytes(32);

        $credentials = $this->getUserCredentials($userId);
        $allowCredentials = [];

        foreach ($credentials as $cred) {
            $allowCredentials[] = [
                'type' => 'public-key',
                'id' => $cred['credential_id'],
            ];
        }

        return [
            'challenge' => base64_encode($challenge),
            'timeout' => 60000,
            'rpId' => $this->rpId,
            'allowCredentials' => $allowCredentials,
            'userVerification' => 'preferred',
        ];
    }

    public function storeCredential(int $userId, array $credentialData, ?string $label = null): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO webauthn_credentials 
            (user_id, credential_id, public_key, aaguid, sign_counter, transports, attestation_type, label) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $userId,
            $credentialData['credential_id'],
            $credentialData['public_key'],
            $credentialData['aaguid'] ?? null,
            $credentialData['sign_counter'] ?? 0,
            isset($credentialData['transports']) ? json_encode($credentialData['transports']) : null,
            $credentialData['attestation_type'] ?? 'none',
            $label,
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function getUserCredentials(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC'
        );
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    public function getCredentialById(string $credentialId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM webauthn_credentials WHERE credential_id = ?'
        );
        $stmt->execute([$credentialId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function updateSignCounter(int $credentialId, int $signCounter): void
    {
        $stmt = $this->db->prepare(
            'UPDATE webauthn_credentials SET sign_counter = ?, last_used_at = NOW() WHERE id = ?'
        );
        $stmt->execute([$signCounter, $credentialId]);
    }

    public function deleteCredential(int $credentialId): bool
    {
        $stmt = $this->db->prepare('DELETE FROM webauthn_credentials WHERE id = ?');
        return $stmt->execute([$credentialId]);
    }
}
