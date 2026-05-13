<?php

declare(strict_types=1);

namespace BlackWall\Security;

final class CryptbinKeyVerifier
{
    public static function validateKeyMaterial(string $keyB64Url): bool
    {
        $decoded = Base64Url::decode($keyB64Url);
        return $decoded !== false && strlen($decoded) === 32;
    }

    public static function createVerifier(string $keyB64Url): string
    {
        if (!self::validateKeyMaterial($keyB64Url)) {
            throw new \InvalidArgumentException('Invalid key material');
        }

        $verifier = password_hash($keyB64Url, PASSWORD_ARGON2ID);
        if ($verifier === false) {
            throw new \RuntimeException('Unable to create verifier');
        }

        return $verifier;
    }

    public static function verify(string $keyB64Url, string $verifier): bool
    {
        if ($keyB64Url === '' || $verifier === '') {
            return false;
        }

        if (!self::validateKeyMaterial($keyB64Url)) {
            return false;
        }

        return password_verify($keyB64Url, $verifier);
    }
}
