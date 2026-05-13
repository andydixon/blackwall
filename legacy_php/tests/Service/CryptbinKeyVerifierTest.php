<?php

declare(strict_types=1);

namespace BlackWall\Tests\Service;

use BlackWall\Security\CryptbinKeyVerifier;
use PHPUnit\Framework\TestCase;

final class CryptbinKeyVerifierTest extends TestCase
{
    public function testCreateAndVerifyKeyVerifier(): void
    {
        $key = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $verifier = CryptbinKeyVerifier::createVerifier($key);

        self::assertNotSame('', $verifier);
        self::assertTrue(CryptbinKeyVerifier::verify($key, $verifier));

        $wrongKey = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        self::assertFalse(CryptbinKeyVerifier::verify($wrongKey, $verifier));
    }

    public function testInvalidKeyMaterialRejected(): void
    {
        self::assertFalse(CryptbinKeyVerifier::validateKeyMaterial('bad'));

        $this->expectException(\InvalidArgumentException::class);
        CryptbinKeyVerifier::createVerifier('bad');
    }
}
