<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Model\OAuthClient;

class OAuthClientAuthenticator
{
    private TokenHasher $hasher;

    public function __construct(?TokenHasher $hasher = null)
    {
        $this->hasher = $hasher ?? new TokenHasher();
    }

    /**
     * @param callable(string): ?OAuthClient $findClientById
     * @return array{ok:bool,client:?OAuthClient,error:?string,auth_method:?string}
     */
    public function authenticate(string $authorizationHeader, array $body, callable $findClientById): array
    {
        $basic = $this->parseBasicAuthorizationHeader($authorizationHeader);
        if ($basic['present'] && $basic['client_id'] === null) {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
        }

        $bodyClientId = trim((string) ($body['client_id'] ?? ''));
        $bodySecret = array_key_exists('client_secret', $body) ? (string) $body['client_secret'] : null;
        $clientId = $basic['client_id'] ?? $bodyClientId;
        if ($clientId === '') {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
        }

        if (
            $basic['client_id'] !== null
            && $bodyClientId !== ''
            && !hash_equals($basic['client_id'], $bodyClientId)
        ) {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
        }

        $client = $findClientById($clientId);
        if (!$client || !$client->isActive()) {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
        }

        $method = 'none';
        if ($basic['client_id'] !== null) {
            $method = 'client_secret_basic';
        } elseif ($bodySecret !== null && $bodySecret !== '') {
            $method = 'client_secret_post';
        }

        if ($client->isConfidential()) {
            $providedSecret = $basic['client_secret'];
            if ($providedSecret === null && $bodySecret !== null) {
                $providedSecret = $bodySecret;
            }

            if ($providedSecret === null || $providedSecret === '') {
                return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
            }

            if (!$this->hasher->verify($providedSecret, (string) $client->clientSecretHash)) {
                return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
            }
        } else {
            // Public clients must use "none" at token endpoint auth.
            if ($basic['present']) {
                return ['ok' => false, 'client' => null, 'error' => 'unauthorized_client', 'auth_method' => null];
            }
            if ($bodySecret !== null && $bodySecret !== '') {
                return ['ok' => false, 'client' => null, 'error' => 'unauthorized_client', 'auth_method' => null];
            }
            if ($bodyClientId === '') {
                return ['ok' => false, 'client' => null, 'error' => 'invalid_client', 'auth_method' => null];
            }
        }

        return ['ok' => true, 'client' => $client, 'error' => null, 'auth_method' => $method];
    }

    /**
     * @return array{present:bool,client_id:?string,client_secret:?string}
     */
    private function parseBasicAuthorizationHeader(string $authorizationHeader): array
    {
        $header = trim($authorizationHeader);
        if ($header === '') {
            return ['present' => false, 'client_id' => null, 'client_secret' => null];
        }

        if (!preg_match('/^Basic\s+([A-Za-z0-9+\/=]+)$/', $header, $matches)) {
            return ['present' => true, 'client_id' => null, 'client_secret' => null];
        }

        $decoded = base64_decode($matches[1], true);
        if ($decoded === false) {
            return ['present' => true, 'client_id' => null, 'client_secret' => null];
        }

        $delimiterPos = strpos($decoded, ':');
        if ($delimiterPos === false) {
            return ['present' => true, 'client_id' => null, 'client_secret' => null];
        }

        $clientId = substr($decoded, 0, $delimiterPos);
        $clientSecret = substr($decoded, $delimiterPos + 1);
        if ($clientId === '') {
            return ['present' => true, 'client_id' => null, 'client_secret' => null];
        }

        return ['present' => true, 'client_id' => $clientId, 'client_secret' => $clientSecret];
    }
}
