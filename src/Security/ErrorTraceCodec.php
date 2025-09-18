<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Config;

class ErrorTraceCodec
{
    private const CIPHER = 'aes-256-gcm';

    public static function encode(string $plaintext): string
    {
        $key = self::getKey();
        $iv = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Failed to encrypt trace payload');
        }

        $payload = [
            'v' => 1,
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ct' => base64_encode($ciphertext),
        ];

        return base64_encode(json_encode($payload));
    }

    public static function decode(string $encodedPayload): string
    {
        $decoded = base64_decode(trim($encodedPayload), true);
        if ($decoded === false) {
            throw new \RuntimeException('Payload is not valid base64');
        }

        $payload = json_decode($decoded, true);
        if (!is_array($payload) || ($payload['v'] ?? null) !== 1) {
            throw new \RuntimeException('Payload format is invalid');
        }

        $iv = base64_decode((string) ($payload['iv'] ?? ''), true);
        $tag = base64_decode((string) ($payload['tag'] ?? ''), true);
        $ciphertext = base64_decode((string) ($payload['ct'] ?? ''), true);

        if ($iv === false || $tag === false || $ciphertext === false) {
            throw new \RuntimeException('Payload fields are invalid');
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            self::getKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new \RuntimeException('Failed to decrypt payload');
        }

        return $plaintext;
    }

    private static function getKey(): string
    {
        $configured = Config::get('ERROR_TRACE_KEY', '');
        if ($configured !== '') {
            $raw = base64_decode($configured, true);
            if ($raw !== false && strlen($raw) === 32) {
                return $raw;
            }
        }

        $fallback = Config::get('CSRF_SECRET');
        return hash('sha256', $fallback, true);
    }
}
