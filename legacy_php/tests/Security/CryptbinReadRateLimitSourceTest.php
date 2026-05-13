<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class CryptbinReadRateLimitSourceTest extends TestCase
{
    public function testCryptbinMetadataAndCiphertextEndpointsHaveRateLimits(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/CryptbinController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("'cryptbin.metadata'", $source);
        $this->assertStringContainsString("'cryptbin.ciphertext'", $source);
        $this->assertStringContainsString("['error' => 'Rate limit exceeded']", $source);
    }
}
