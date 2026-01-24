<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginActiveUserEnforcementSourceTest extends TestCase
{
    public function testPortalAndOauthLoginVerifyRequireActiveUserStatus(): void
    {
        $portal = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $oauth = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');

        $this->assertIsString($portal);
        $this->assertIsString($oauth);

        $this->assertStringContainsString("SELECT status FROM users WHERE id = ? LIMIT 1", $portal);
        $this->assertStringContainsString("SELECT status FROM users WHERE id = ? LIMIT 1", $oauth);
        $this->assertStringContainsString('User account inactive', $portal);
        $this->assertStringContainsString('User account inactive', $oauth);
    }
}
