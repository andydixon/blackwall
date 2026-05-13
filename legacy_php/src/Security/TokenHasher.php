<?php

declare(strict_types=1);

namespace BlackWall\Security;

class TokenHasher
{
    public function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    public function verify(string $token, string $hash): bool
    {
        return hash_equals($hash, $this->hash($token));
    }

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function generateToken(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    public function generateBase64UrlToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
