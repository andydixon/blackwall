<?php

declare(strict_types=1);

namespace BlackWall\Security;

class PKCEValidator
{
    public function validateChallenge(string $codeVerifier, string $codeChallenge, string $method = 'S256'): bool
    {
        if ($method !== 'S256') {
            return false;
        }

        if (!preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $codeVerifier)) {
            return false;
        }

        $expectedChallenge = $this->generateChallenge($codeVerifier, $method);
        
        return hash_equals($expectedChallenge, $codeChallenge);
    }

    public function generateChallenge(string $codeVerifier, string $method = 'S256'): string
    {
        if ($method !== 'S256') {
            return '';
        }

        $hash = hash('sha256', $codeVerifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }
}
