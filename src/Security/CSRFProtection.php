<?php

declare(strict_types=1);

namespace BlackWall\Security;

class CSRFProtection
{
    public static function generateToken(): string
    {
        $token = bin2hex(random_bytes(32));
        SessionManager::set('csrf_token', $token);
        return $token;
    }

    public static function validateToken(string $token): bool
    {
        $sessionToken = SessionManager::get('csrf_token');
        
        if (!$sessionToken) {
            return false;
        }

        return hash_equals($sessionToken, $token);
    }

    public static function getToken(): string
    {
        $token = SessionManager::get('csrf_token');
        
        if (!$token) {
            $token = self::generateToken();
        }

        return $token;
    }
}
