<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Database;
use BlackWall\Security\WebAuthnAssertionPolicy;
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

    private function b64urlDecode(string $data): string|false
    {
        $replaced = strtr($data, '-_', '+/');
        $pad = strlen($replaced) % 4;
        if ($pad) { $replaced .= str_repeat('=', 4 - $pad); }
        return base64_decode($replaced);
    }

    private function convertDERtoRaw(string $der): string
    {
        // DER signature format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        // We need raw format: [r][s] each 32 bytes
        if (strlen($der) < 8 || ord($der[0]) !== 0x30) {
            return $der; // Not DER, return as-is
        }
        $offset = 2; // Skip 0x30 and total length
        if (ord($der[$offset]) !== 0x02) {
            return $der;
        }
        $offset++;
        $rLength = ord($der[$offset++]);
        $r = substr($der, $offset, $rLength);
        $offset += $rLength;
        
        if (ord($der[$offset]) !== 0x02) {
            return $der;
        }
        $offset++;
        $sLength = ord($der[$offset++]);
        $s = substr($der, $offset, $sLength);
        
        // Remove leading zero bytes if present (DER adds them for positive numbers with high bit set)
        while (strlen($r) > 32 && ord($r[0]) === 0x00) {
            $r = substr($r, 1);
        }
        while (strlen($s) > 32 && ord($s[0]) === 0x00) {
            $s = substr($s, 1);
        }
        
        // Pad to 32 bytes if needed
        $r = str_pad($r, 32, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, 32, "\x00", STR_PAD_LEFT);
        
        return $r . $s;
    }

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
            $attestationObject = $this->b64urlDecode($attestationObjectBase64) ?: base64_decode($attestationObjectBase64);
            
            // Decode CBOR attestation object
            $decoder = Decoder::create();
            $attestation = $decoder->decode(\CBOR\StringStream::create($attestationObject));
            $att = is_object($attestation) && method_exists($attestation, 'normalize') ? $attestation->normalize() : $attestation;
            if (!is_array($att) || !isset($att['authData'])) {
                return null;
            }
            
            // Parse authenticator data to extract credentialPublicKey
            $authData = $att['authData'];
            if (!is_string($authData) || strlen($authData) < 55) {
                return null;
            }
            // Skip rpIdHash (32), flags (1), signCount (4)
            $offset = 37;
            // Read AAGUID (16)
            $offset += 16;
            // Read credential ID length (2 bytes, big-endian)
            $credIdLen = unpack('n', substr($authData, $offset, 2))[1] ?? null;
            if ($credIdLen === null) {
                return null;
            }
            $offset += 2;
            // Skip credential ID
            $offset += $credIdLen;
            // The remaining bytes start with the COSE credentialPublicKey CBOR
            $coseKeyBytes = substr($authData, $offset);
            if (!$coseKeyBytes) {
                return null;
            }
            // Store as base64-encoded CBOR
            return base64_encode($coseKeyBytes);
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
                error_log('verifyAssertion: credential not found for id '.$credentialId);
                return false;
            }

            // Decode client data JSON (base64url from client)
            $clientDataDecoded = $this->b64urlDecode($clientDataJSON) ?: base64_decode($clientDataJSON);
            $clientData = json_decode($clientDataDecoded ?: '', true);
            if (!$clientData) {
                error_log('verifyAssertion: clientDataJSON decode failed');
                return false;
            }

            // Verify the challenge bytes match (base64url vs base64)
            $clientChallenge = $this->b64urlDecode($clientData['challenge'] ?? '');
            $serverChallenge = base64_decode($expectedChallenge);
            if ($clientChallenge === false || $serverChallenge === false || $clientChallenge !== $serverChallenge) {
                error_log('verifyAssertion: challenge mismatch');
                return false;
            }

            // Verify the origin matches our RP ID
            $expectedOrigin = 'https://' . $this->rpId;
            if ($clientData['origin'] !== $expectedOrigin) {
                error_log('verifyAssertion: origin mismatch '.$clientData['origin'].' != '.$expectedOrigin);
                return false;
            }

            // Verify the type is webauthn.get
            if ($clientData['type'] !== 'webauthn.get') {
                error_log('verifyAssertion: type mismatch '.$clientData['type']);
                return false;
            }

            // Decode authenticator data (base64url from client)
            $authDataBinary = $this->b64urlDecode($authenticatorData) ?: base64_decode($authenticatorData);
            if (strlen($authDataBinary) < 37) {
                return false;
            }

            if (!WebAuthnAssertionPolicy::hasValidRpIdHash($authDataBinary, $this->rpId)) {
                error_log('verifyAssertion: rpId hash mismatch');
                return false;
            }

            // Check the User Present (UP) flag (bit 0 of flags byte at offset 32)
            $flags = ord($authDataBinary[32]);
            $userPresent = ($flags & 0x01) !== 0;
            if (!$userPresent) {
                error_log('verifyAssertion: user not present flag not set');
                return false;
            }

            // Verify the cryptographic signature
            // The signature is over: authenticatorData || hash(clientDataJSON)
            $clientDataHash = hash('sha256', $clientDataDecoded, true);
            $signedData = $authDataBinary . $clientDataHash;
            
            // Decode the public key from COSE format
            $publicKeyBinary = base64_decode($credential['public_key']);
            $decoder = Decoder::create();
            $publicKeyCose = $decoder->decode(\CBOR\StringStream::create($publicKeyBinary));
            
            // Create COSE Key object from normalized CBOR map
            $publicKey = Key::create($publicKeyCose->normalize());
            
            // Get the algorithm value from COSE label 3 (returns -7 for ES256, -257 for RS256)
            $alg = $publicKey->get(3);
            if ($alg === null) {
                error_log('verifyAssertion: algorithm label 3 not found in COSE key');
                return false;
            }
            // The value is the algorithm identifier (e.g., -7), cast to int and pass to manager
            try {
                $algorithm = $this->algorithmManager->get((int)$alg);
            } catch (\Exception $e) {
                error_log('verifyAssertion: unsupported algorithm ' . $alg . ': ' . $e->getMessage());
                return false;
            }
            
            // Verify the signature (base64url from client, may be DER-encoded for ES256)
            $signatureBinary = $this->b64urlDecode($signature);
            if ($signatureBinary === false) {
                $signatureBinary = base64_decode($signature);
            }
            if ($signatureBinary === false || strlen($signatureBinary) < 1) {
                error_log('verifyAssertion: signature decode failed');
                return false;
            }
            
            // For ES256, WebAuthn signatures are DER-encoded; convert to raw r||s (64 bytes)
            if (((int)$alg) === -7 && strlen($signatureBinary) !== 64) {
                $signatureBinary = $this->convertDERtoRaw($signatureBinary);
            }
            
            $verified = $algorithm->verify($signedData, $publicKey, $signatureBinary);
            
            if (!$verified) {
                error_log('verifyAssertion: signature verification failed');
                return false;
            }
            
            // Update sign counter if verification succeeded
            $signCounter = unpack('N', substr($authDataBinary, 33, 4))[1];
            $storedSignCounter = (int) ($credential['sign_counter'] ?? 0);
            if (!WebAuthnAssertionPolicy::hasValidSignCounter($storedSignCounter, (int) $signCounter)) {
                error_log('verifyAssertion: sign counter regression detected');
                return false;
            }

            $this->updateSignCounter((int)$credential['id'], $signCounter);

            return true;
        } catch (\Exception $e) {
            error_log("WebAuthn verification failed: " . $e->getMessage());
            return false;
        }
    }
}
