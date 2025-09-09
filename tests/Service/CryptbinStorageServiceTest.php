<?php

declare(strict_types=1);

namespace BlackWall\Tests\Service;

use BlackWall\Service\CryptbinStorageService;
use PHPUnit\Framework\TestCase;

final class CryptbinStorageServiceTest extends TestCase
{
    private string $dir;
    private CryptbinStorageService $storage;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/cryptbin-test-' . bin2hex(random_bytes(6));
        $this->storage = new CryptbinStorageService($this->dir);
    }

    protected function tearDown(): void
    {
        @array_map('unlink', glob($this->dir . '/*') ?: []);
        @rmdir($this->dir);
        parent::tearDown();
    }

    public function testIdValidation(): void
    {
        self::assertTrue(CryptbinStorageService::isValidId('A1b2C3d4E5f6G7h8'));
        self::assertFalse(CryptbinStorageService::isValidId('short'));
        self::assertFalse(CryptbinStorageService::isValidId('A1b2C3d4E5f6G7h8_'));
        self::assertFalse(CryptbinStorageService::isValidId('A1b2C3d4E5f6G7h!'));
    }

    public function testMetadataAndCiphertextWriteReadAreAtomicEnoughForConsumers(): void
    {
        $id = 'A1b2C3d4E5f6G7h8';
        $ciphertext = random_bytes(128);

        $this->storage->writeItem($id, $ciphertext, [
            'item_type' => 'text',
            'cipher_alg' => 'AES-256-GCM',
            'cipher_nonce_b64url' => 'abc',
            'verifier' => 'hash',
            'wrapped_dek' => 'wrapped',
            'wrapped_dek_nonce' => 'nonce',
            'wrapped_dek_alg' => 'XCHACHA20POLY1305-IETF',
            'kek_version' => 'v1',
            'created_at' => gmdate('c'),
            'updated_at' => gmdate('c'),
        ]);

        $readMeta = $this->storage->readMetadata($id);
        $readCipher = $this->storage->readCiphertext($id);

        self::assertIsArray($readMeta);
        self::assertSame($id, $readMeta['id']);
        self::assertSame(128, $readMeta['size_bytes']);
        self::assertSame($ciphertext, $readCipher);
    }

    public function testInvalidIdPreventsPathTraversal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->storage->readMetadata('../etc/passwd');
    }

    public function testDeleteItemRemovesBothFiles(): void
    {
        $id = 'Z9y8X7w6V5u4T3s2';
        $ciphertext = random_bytes(64);

        $this->storage->writeItem($id, $ciphertext, [
            'item_type' => 'file',
            'cipher_alg' => 'AES-256-GCM',
            'cipher_nonce_b64url' => 'abc',
            'verifier' => 'hash',
            'wrapped_dek' => 'wrapped',
            'wrapped_dek_nonce' => 'nonce',
            'wrapped_dek_alg' => 'XCHACHA20POLY1305-IETF',
            'kek_version' => 'v1',
            'created_at' => gmdate('c'),
            'updated_at' => gmdate('c'),
        ]);

        self::assertTrue($this->storage->exists($id));
        self::assertTrue($this->storage->deleteItem($id));
        self::assertFalse($this->storage->exists($id));
    }
}
