<?php

declare(strict_types=1);

namespace BlackWall\Security;

final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string|false
    {
        if ($data === '') {
            return '';
        }

        if (!preg_match('/^[A-Za-z0-9_-]+$/', $data)) {
            return false;
        }

        $normalized = strtr($data, '-_', '+/');
        $padding = strlen($normalized) % 4;
        if ($padding !== 0) {
            $normalized .= str_repeat('=', 4 - $padding);
        }

        return base64_decode($normalized, true);
    }
}
