<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Config;
use BlackWall\Security\Base64Url;

class CryptbinKekService
{
    private string $kek;
    private string $keyVersion;

    public function __construct(?string $kekBase64 = null, ?string $keyVersion = null)
    {
        if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            throw new \RuntimeException('libsodium extension is required for Cryptbin KEK wrapping');
        }

        $kekBase64 = $kekBase64 ?? Config::get('CRYPTBIN_KEK_BASE64');
        $decoded = base64_decode($kekBase64, true);

        if ($decoded === false || strlen($decoded) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new \RuntimeException('CRYPTBIN_KEK_BASE64 must be base64 for 32 bytes');
        }

        $this->kek = $decoded;
        $this->keyVersion = $keyVersion ?? Config::get('CRYPTBIN_KEK_VERSION', 'v1');
    }

    public function wrapDek(string $dek, string $id): array
    {
        if (strlen($dek) !== 32) {
            throw new \InvalidArgumentException('DEK must be 32 bytes');
        }

        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $aad = $this->aad($id);

        $wrapped = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $dek,
            $aad,
            $nonce,
            $this->kek
        );

        return [
            'wrapped_dek' => Base64Url::encode($wrapped),
            'wrapped_dek_nonce' => Base64Url::encode($nonce),
            'wrapped_dek_alg' => 'XCHACHA20POLY1305-IETF',
            'kek_version' => $this->keyVersion,
        ];
    }

    public function unwrapDek(array $metadata, string $id): string
    {
        if (($metadata['wrapped_dek_alg'] ?? '') !== 'XCHACHA20POLY1305-IETF') {
            throw new \RuntimeException('Unsupported wrapped DEK algorithm');
        }

        $wrapped = Base64Url::decode((string) ($metadata['wrapped_dek'] ?? ''));
        $nonce = Base64Url::decode((string) ($metadata['wrapped_dek_nonce'] ?? ''));

        if ($wrapped === false || $nonce === false) {
            throw new \RuntimeException('Invalid wrapped DEK encoding');
        }

        $dek = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $wrapped,
            $this->aad($id),
            $nonce,
            $this->kek
        );

        if ($dek === false || strlen($dek) !== 32) {
            throw new \RuntimeException('Failed to unwrap DEK');
        }

        return $dek;
    }

    private function aad(string $id): string
    {
        return 'cryptbin:dek-wrap:v1:' . $id;
    }
}
