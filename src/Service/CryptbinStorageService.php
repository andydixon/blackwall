<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Config;

class CryptbinStorageService
{
    private const ID_PATTERN = '/^[0-9A-Za-z]{16}$/';

    private string $storagePath;

    public function __construct(?string $storagePath = null)
    {
        $configuredPath = $storagePath ?? Config::get('CRYPTBIN_STORAGE_PATH', __DIR__ . '/../../tmp/cryptbin-storage');
        $this->storagePath = $this->normalizeStoragePath($configuredPath);
        $this->ensureStoragePath();
        $this->assertNotWebAccessible();
    }

    public static function isValidId(string $id): bool
    {
        return preg_match(self::ID_PATTERN, $id) === 1;
    }

    public function getStoragePath(): string
    {
        return $this->storagePath;
    }

    public function exists(string $id): bool
    {
        $this->assertValidId($id);
        return is_file($this->binPath($id)) && is_file($this->metaPath($id));
    }

    public function readMetadata(string $id): ?array
    {
        $this->assertValidId($id);

        $raw = @file_get_contents($this->metaPath($id));
        if ($raw === false) {
            return null;
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    public function readCiphertext(string $id): ?string
    {
        $this->assertValidId($id);
        $raw = @file_get_contents($this->binPath($id));
        return $raw === false ? null : $raw;
    }

    public function writeItem(string $id, string $ciphertext, array $metadata): void
    {
        $this->assertValidId($id);

        $metadata['id'] = $id;
        $metadata['size_bytes'] = strlen($ciphertext);

        $encodedMetadata = json_encode($metadata, JSON_UNESCAPED_SLASHES);
        if ($encodedMetadata === false) {
            throw new \RuntimeException('Failed to encode metadata JSON');
        }

        $binPath = $this->binPath($id);
        $metaPath = $this->metaPath($id);

        $tmpBin = $this->tempPath($id, 'bin');
        $tmpMeta = $this->tempPath($id, 'json');

        try {
            $this->writeAtomicFile($tmpBin, $ciphertext);
            $this->writeAtomicFile($tmpMeta, $encodedMetadata);

            if (!rename($tmpBin, $binPath)) {
                throw new \RuntimeException('Failed to move binary payload into place');
            }

            if (!rename($tmpMeta, $metaPath)) {
                throw new \RuntimeException('Failed to move metadata into place');
            }
        } finally {
            @unlink($tmpBin);
            @unlink($tmpMeta);
        }
    }

    public function deleteItem(string $id): bool
    {
        $this->assertValidId($id);

        $binPath = $this->binPath($id);
        $metaPath = $this->metaPath($id);

        if (!is_file($binPath) && !is_file($metaPath)) {
            return false;
        }

        $suffix = '.delete.' . bin2hex(random_bytes(8));
        $binTrash = $binPath . $suffix;
        $metaTrash = $metaPath . $suffix;

        $binMoved = !is_file($binPath) || rename($binPath, $binTrash);
        $metaMoved = !is_file($metaPath) || rename($metaPath, $metaTrash);

        if (!$binMoved || !$metaMoved) {
            if (is_file($binTrash) && !is_file($binPath)) {
                @rename($binTrash, $binPath);
            }
            if (is_file($metaTrash) && !is_file($metaPath)) {
                @rename($metaTrash, $metaPath);
            }
            return false;
        }

        $binDeleted = !is_file($binTrash) || @unlink($binTrash);
        $metaDeleted = !is_file($metaTrash) || @unlink($metaTrash);

        return $binDeleted && $metaDeleted;
    }

    public function sanitizeOriginalFilename(?string $filename, string $itemType): string
    {
        if ($itemType === 'text') {
            return 'cryptbin.txt';
        }

        $base = trim((string) $filename);
        if ($base === '') {
            return 'cryptbin.bin';
        }

        $base = basename($base);
        $base = preg_replace('/[^A-Za-z0-9._-]/', '_', $base) ?? 'cryptbin.bin';

        if ($base === '' || $base === '.' || $base === '..') {
            return 'cryptbin.bin';
        }

        return $base;
    }

    public function publicMetadata(array $metadata): array
    {
        unset($metadata['verifier'], $metadata['wrapped_dek'], $metadata['wrapped_dek_nonce'], $metadata['wrapped_dek_alg'], $metadata['kek_version']);
        return $metadata;
    }

    public function listItems(): array
    {
        $items = [];
        $pattern = $this->storagePath . '/*.json';
        $files = glob($pattern);

        if ($files === false) {
            return [];
        }

        foreach ($files as $metaFile) {
            $raw = @file_get_contents($metaFile);
            if ($raw === false) {
                continue;
            }

            $metadata = json_decode($raw, true);
            if (!is_array($metadata)) {
                continue;
            }

            $id = (string) ($metadata['id'] ?? basename($metaFile, '.json'));
            if (!self::isValidId($id)) {
                continue;
            }

            $ciphertextPath = $this->binPath($id);
            $metadata['id'] = $id;
            $metadata['size_bytes'] = isset($metadata['size_bytes'])
                ? (int) $metadata['size_bytes']
                : (is_file($ciphertextPath) ? (int) filesize($ciphertextPath) : 0);
            $metadata['ciphertext_exists'] = is_file($ciphertextPath);
            $metadata['metadata_mtime'] = @filemtime($metaFile) ?: null;

            $items[] = $metadata;
        }

        return $items;
    }

    private function normalizeStoragePath(string $path): string
    {
        if ($path === '') {
            throw new \RuntimeException('CRYPTBIN_STORAGE_PATH must not be empty');
        }

        if ($path[0] !== '/') {
            $path = dirname(__DIR__, 2) . '/' . ltrim($path, '/');
        }

        return rtrim($path, '/');
    }

    private function ensureStoragePath(): void
    {
        if (is_dir($this->storagePath)) {
            return;
        }

        if (!mkdir($this->storagePath, 0700, true) && !is_dir($this->storagePath)) {
            throw new \RuntimeException('Unable to create Cryptbin storage directory');
        }
    }

    private function assertNotWebAccessible(): void
    {
        $publicRoot = realpath(dirname(__DIR__, 2) . '/public_html');
        $storageReal = realpath($this->storagePath);

        if ($publicRoot !== false && $storageReal !== false) {
            if ($storageReal === $publicRoot || str_starts_with($storageReal, $publicRoot . DIRECTORY_SEPARATOR)) {
                throw new \RuntimeException('Cryptbin storage path must be outside public_html');
            }
        }
    }

    private function assertValidId(string $id): void
    {
        if (!self::isValidId($id)) {
            throw new \InvalidArgumentException('Invalid Cryptbin ID');
        }
    }

    private function binPath(string $id): string
    {
        return $this->storagePath . '/' . $id . '.bin';
    }

    private function metaPath(string $id): string
    {
        return $this->storagePath . '/' . $id . '.json';
    }

    private function tempPath(string $id, string $extension): string
    {
        return sprintf('%s/.%s.%s.%s.tmp', $this->storagePath, $id, bin2hex(random_bytes(6)), $extension);
    }

    private function writeAtomicFile(string $path, string $content): void
    {
        $written = file_put_contents($path, $content, LOCK_EX);
        if ($written === false || $written !== strlen($content)) {
            throw new \RuntimeException('Failed to write temporary file');
        }

        chmod($path, 0600);
    }
}
