<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Config;

class SessionManager
{
    private static bool $started = false;

    public static function start(): void
    {
        if (self::$started) {
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', '1');
        ini_set('session.cookie_samesite', 'Lax');
        ini_set('session.use_strict_mode', '1');

        session_name(Config::get('SESSION_NAME', 'blackwall_session'));
        session_start();

        if (!isset($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
            $_SESSION['created_at'] = time();
        }

        $maxLifetime = Config::getInt('SESSION_LIFETIME', 7200);
        if (isset($_SESSION['created_at']) && (time() - $_SESSION['created_at']) > $maxLifetime) {
            self::destroy();
            self::start();
        }

        self::$started = true;
    }

    public static function destroy(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            session_destroy();
        }
        self::$started = false;
    }

    public static function set(string $key, mixed $value): void
    {
        self::start();
        $_SESSION[$key] = $value;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        self::start();
        return $_SESSION[$key] ?? $default;
    }

    public static function has(string $key): bool
    {
        self::start();
        return isset($_SESSION[$key]);
    }

    public static function remove(string $key): void
    {
        self::start();
        unset($_SESSION[$key]);
    }

    public static function regenerateId(): void
    {
        self::start();
        session_regenerate_id(true);
    }
}
