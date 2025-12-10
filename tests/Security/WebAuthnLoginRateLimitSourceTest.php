<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginRateLimitSourceTest extends TestCase
{
    public function testAdminLoginVerifyIncludesRateLimitGuard(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString('webauthn.login.admin.verify', $source);
        $this->assertStringContainsString('too_many_requests', $source);
    }

    public function testPortalLoginVerifyIncludesRateLimitGuard(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString('webauthn.login.portal.verify', $source);
        $this->assertStringContainsString('too_many_requests', $source);
    }

    public function testOAuthLoginVerifyIncludesRateLimitGuard(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString('webauthn.login.oauth.verify', $source);
        $this->assertStringContainsString('too_many_requests', $source);
    }
}
