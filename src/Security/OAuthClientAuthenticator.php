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
     * @return array{ok:bool,client:?OAuthClient,error:?string}
     */
    public function authenticate(string $authorizationHeader, array $body, callable $findClientById): array
    {
        $basic = $this->parseBasicAuthorizationHeader($authorizationHeader);
        if ($basic['present'] && $basic['client_id'] === null) {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client'];
        }

        $bodyClientId = trim((string) ($body['client_id'] ?? ''));
        $clientId = $basic['client_id'] ?? $bodyClientId;
        if ($clientId === '') {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client'];
        }

        if (
            $basic['client_id'] !== null
            && $bodyClientId !== ''
            && !hash_equals($basic['client_id'], $bodyClientId)
        ) {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client'];
        }

        $client = $findClientById($clientId);
        if (!$client || !$client->isActive()) {
            return ['ok' => false, 'client' => null, 'error' => 'invalid_client'];
        }

        if ($client->isConfidential()) {
            $providedSecret = $basic['client_secret'];
            if ($providedSecret === null && array_key_exists('client_secret', $body)) {
                $providedSecret = (string) $body['client_secret'];
            }

            if ($providedSecret === null || $providedSecret === '') {
                return ['ok' => false, 'client' => null, 'error' => 'invalid_client'];
            }

            if (!$this->hasher->verify($providedSecret, (string) $client->clientSecretHash)) {
                return ['ok' => false, 'client' => null, 'error' => 'invalid_client'];
            }
        }

        return ['ok' => true, 'client' => $client, 'error' => null];
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
