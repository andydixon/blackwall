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
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorData;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Manager;
use Cose\Key\Key;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use PDO;

class WebAuthnService
{
    private PDO $db;
    private string $rpId;
    private string $rpName;
    private Manager $algorithmManager;

    public function __construct()
    {
        $this->db = Database::getInstance();
        $this->rpId = \BlackWall\Config::get('WEBAUTHN_RP_ID');
        $this->rpName = \BlackWall\Config::get('WEBAUTHN_RP_NAME');
        
        // Initialize algorithm manager for COSE signature verification
        $this->algorithmManager = Manager::create()
            ->add(ES256::create())
            ->add(RS256::create());
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
            'preferred',
            'required'  // Require resident key for usernameless login
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
                'residentKey' => 'required',
                'requireResidentKey' => true,
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

    /**
     * Extract public key from attestation object
     */
    public function extractPublicKeyFromAttestation(string $attestationObjectBase64): ?string
    {
        try {
            $attestationObject = base64_decode($attestationObjectBase64);
            
            // Decode CBOR attestation object
            $decoder = Decoder::create(
                TagObjectManager::create(),
                OtherObjectManager::create()
            );
            $attestation = $decoder->decode($attestationObject);
            
            if (!isset($attestation['authData'])) {
                return null;
            }
            
            // Parse authenticator data
            $authData = AuthenticatorData::createFromString($attestation['authData']);
            $attestedCredentialData = $authData->getAttestedCredentialData();
            
            if (!$attestedCredentialData) {
                return null;
            }
            
            // Get the COSE public key
            $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
            if (!$credentialPublicKey) {
                return null;
            }
            
            // Return as base64 encoded string for storage
            return base64_encode($credentialPublicKey);
        } catch (\Exception $e) {
            error_log("Failed to extract public key: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Verify WebAuthn authentication assertion with full cryptographic signature verification
     * 
     * @param string $credentialId The credential ID from the assertion
     * @param string $clientDataJSON Base64-encoded client data JSON
     * @param string $authenticatorData Base64-encoded authenticator data
     * @param string $signature Base64-encoded signature
     * @param string $expectedChallenge Base64-encoded expected challenge
     * @return bool True if verification succeeds
     */
    public function verifyAssertion(
        string $credentialId,
        string $clientDataJSON,
        string $authenticatorData,
        string $signature,
        string $expectedChallenge
    ): bool {
        try {
            // Get the stored credential
            $credential = $this->getCredentialById($credentialId);
            if (!$credential) {
                return false;
            }

            // Decode client data JSON
            $clientDataDecoded = base64_decode($clientDataJSON);
            $clientData = json_decode($clientDataDecoded, true);
            if (!$clientData) {
                return false;
            }

            // Verify the challenge matches
            if ($clientData['challenge'] !== $expectedChallenge) {
                return false;
            }

            // Verify the origin matches our RP ID
            $expectedOrigin = 'https://' . $this->rpId;
            if ($clientData['origin'] !== $expectedOrigin) {
                return false;
            }

            // Verify the type is webauthn.get
            if ($clientData['type'] !== 'webauthn.get') {
                return false;
            }

            // Decode authenticator data
            $authDataBinary = base64_decode($authenticatorData);
            if (strlen($authDataBinary) < 37) {
                return false;
            }

            // Check the User Present (UP) flag (bit 0 of flags byte at offset 32)
            $flags = ord($authDataBinary[32]);
            $userPresent = ($flags & 0x01) !== 0;
            if (!$userPresent) {
                return false;
            }

            // Verify the cryptographic signature
            // The signature is over: authenticatorData || hash(clientDataJSON)
            $clientDataHash = hash('sha256', $clientDataDecoded, true);
            $signedData = $authDataBinary . $clientDataHash;
            
            // Decode the public key from COSE format
            $publicKeyBinary = base64_decode($credential['public_key']);
            $decoder = Decoder::create(
                TagObjectManager::create(),
                OtherObjectManager::create()
            );
            $publicKeyCose = $decoder->decode($publicKeyBinary);
            
            // Create COSE Key object
            $publicKey = Key::create($publicKeyCose);
            
            // Get the algorithm
            $alg = $publicKey->get(-1); // -1 is the algorithm parameter in COSE
            $algorithm = $this->algorithmManager->get((int)$alg);
            
            // Verify the signature
            $signatureBinary = base64_decode($signature);
            $verified = $algorithm->verify($signedData, $publicKey, $signatureBinary);
            
            if (!$verified) {
                return false;
            }
            
            // Update sign counter if verification succeeded
            $signCounter = unpack('N', substr($authDataBinary, 33, 4))[1];
            $this->updateSignCounter((int)$credential['id'], $signCounter);

            return true;
        } catch (\Exception $e) {
            error_log("WebAuthn verification failed: " . $e->getMessage());
            return false;
        }
    }
}
