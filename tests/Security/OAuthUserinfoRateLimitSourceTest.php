<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthUserinfoRateLimitSourceTest extends TestCase
{
    public function testUserinfoEndpointHasRateLimitProtection(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("'oauth.userinfo'", $source);
        $this->assertStringContainsString("'error' => 'too_many_requests'", $source);
        $this->assertStringContainsString('Rate limit exceeded for userinfo endpoint', $source);
    }
}
