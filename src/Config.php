<?php

declare(strict_types=1);

namespace BlackWall;

use Dotenv\Dotenv;

class Config
{
    private static ?Dotenv $dotenv = null;
    private static bool $loaded = false;

    public static function load(string $path): void
    {
        if (self::$loaded) {
            return;
        }

        self::$dotenv = Dotenv::createUnsafeImmutable($path);
        self::$dotenv->load();
        self::$loaded = true;
    }

    /**
     * Get configuration value with fallback chain.
     * Order: getenv() -> $_ENV -> $_SERVER -> default
     *
     * @throws \RuntimeException if key not found and no default
     */
    public static function get(string $key, ?string $default = null): string
    {
        // Try getenv first (works with putenv from dotenv)
        $value = getenv($key);
        if ($value !== false && $value !== '') {
            return $value;
        }

        // Try $_ENV
        if (isset($_ENV[$key]) && $_ENV[$key] !== '') {
            return $_ENV[$key];
        }

        // Try $_SERVER
        if (isset($_SERVER[$key]) && $_SERVER[$key] !== '') {
            return $_SERVER[$key];
        }

        // Use default or throw
        if ($default !== null) {
            return $default;
        }

        throw new \RuntimeException("Configuration key '{$key}' not found and no default provided");
    }

    public static function getBool(string $key, bool $default = false): bool
    {
        try {
            $value = self::get($key);
            return filter_var($value, FILTER_VALIDATE_BOOLEAN);
        } catch (\RuntimeException $e) {
            return $default;
        }
    }

    public static function getInt(string $key, int $default = 0): int
    {
        try {
            $value = self::get($key);
            return (int) $value;
        } catch (\RuntimeException $e) {
            return $default;
        }
    }

    public static function required(array $keys): void
    {
        $missing = [];
        foreach ($keys as $key) {
            try {
                self::get($key);
            } catch (\RuntimeException $e) {
                $missing[] = $key;
            }
        }

        if (!empty($missing)) {
            throw new \RuntimeException(
                'Missing required environment variables: ' . implode(', ', $missing)
            );
        }
    }
}
