<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthControlEndpointRateLimitSourceTest extends TestCase
{
    public function testRevokeAndIntrospectEndpointsHaveRateLimits(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("'oauth.revoke'", $source);
        $this->assertStringContainsString("'oauth.introspect'", $source);
        $this->assertStringContainsString("'error' => 'too_many_requests'", $source);
    }
}
