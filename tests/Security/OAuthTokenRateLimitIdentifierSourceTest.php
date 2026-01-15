<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthTokenRateLimitIdentifierSourceTest extends TestCase
{
    public function testTokenEndpointUsesNamespacedIpRateLimitIdentifier(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString("check('ip:' . \$ipAddress, 'oauth.token'", $source);
    }
}
