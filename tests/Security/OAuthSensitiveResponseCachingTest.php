<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthSensitiveResponseCachingTest extends TestCase
{
    public function testOauthControllerSetsNoStoreHeadersOnSensitiveEndpoints(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("->withHeader('Cache-Control', 'no-store')", $source);
        $this->assertStringContainsString("->withHeader('Pragma', 'no-cache')", $source);
    }
}
