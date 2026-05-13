<?php

declare(strict_types=1);

namespace BlackWall\Security;

class OAuthRedirectUriPolicy
{
    public static function allAllowed(array $redirectUris): bool
    {
        if ($redirectUris === []) {
            return false;
        }

        foreach ($redirectUris as $uri) {
            if (!is_string($uri) || !self::isAllowed(trim($uri))) {
                return false;
            }
        }

        return true;
    }

    public static function isAllowed(string $uri): bool
    {
        if ($uri === '' || str_contains($uri, '*')) {
            return false;
        }

        $parts = parse_url($uri);
        if (!is_array($parts)) {
            return false;
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($scheme === '' || $host === '') {
            return false;
        }
        if (isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        if ($scheme === 'https') {
            return true;
        }

        if ($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true)) {
            return true;
        }

        return false;
    }
}
