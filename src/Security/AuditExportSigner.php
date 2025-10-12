<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Config;

class AuditExportSigner
{
    public static function sha256(string $payload): string
    {
        return hash('sha256', $payload);
    }

    public static function signIfConfigured(string $payload): ?array
    {
        $raw = trim((string) Config::get('AUDIT_EXPORT_SIGNING_KEY', ''));
        if ($raw === '') {
            return null;
        }

        $key = base64_decode($raw, true);
        if ($key === false) {
            $key = $raw;
        }

        $sig = hash_hmac('sha256', $payload, $key);

        return [
            'algorithm' => 'HMAC-SHA256',
            'signature' => $sig,
            'key_id' => 'env:AUDIT_EXPORT_SIGNING_KEY',
        ];
    }
}

