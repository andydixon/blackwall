<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthUserinfoLoggingTest extends TestCase
{
    public function testOauthUserinfoDoesNotEmitJwtDebugLogs(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);
        $this->assertStringNotContainsString('JWT parse result', $source);
        $this->assertStringNotContainsString('JWT validation result', $source);
    }
}
