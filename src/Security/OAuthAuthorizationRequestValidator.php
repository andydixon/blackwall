<?php

declare(strict_types=1);

namespace BlackWall\Security;

class OAuthAuthorizationRequestValidator
{
    /**
     * @return array{ok:bool,error:?string,description:?string}
     */
    public function validate(array $params, bool $isOidcRequest, ?callable $nonceReplayCheck = null): array
    {
        $required = ['client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'state'];
        foreach ($required as $name) {
            if (!isset($params[$name]) || trim((string) $params[$name]) === '') {
                return ['ok' => false, 'error' => 'invalid_request', 'description' => "Missing parameter: {$name}"];
            }
        }

        if ((string) $params['response_type'] !== 'code') {
            return ['ok' => false, 'error' => 'unsupported_response_type', 'description' => null];
        }

        if ((string) $params['code_challenge_method'] !== 'S256') {
            return ['ok' => false, 'error' => 'invalid_request', 'description' => 'Only S256 supported'];
        }

        if ($isOidcRequest) {
            $nonce = trim((string) ($params['nonce'] ?? ''));
            if ($nonce === '') {
                return ['ok' => false, 'error' => 'invalid_request', 'description' => 'Missing parameter: nonce'];
            }
            if (strlen($nonce) < 8 || strlen($nonce) > 255) {
                return ['ok' => false, 'error' => 'invalid_request', 'description' => 'Invalid nonce'];
            }

            if ($nonceReplayCheck !== null && $nonceReplayCheck($nonce) === true) {
                return ['ok' => false, 'error' => 'invalid_request', 'description' => 'Nonce replay detected'];
            }
        }

        return ['ok' => true, 'error' => null, 'description' => null];
    }
}
