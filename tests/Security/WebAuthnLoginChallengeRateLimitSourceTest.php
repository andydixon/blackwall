<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginChallengeRateLimitSourceTest extends TestCase
{
    public function testAdminAndPortalLoginChallengeAreRateLimited(): void
    {
        $admin = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $portal = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $this->assertIsString($admin);
        $this->assertIsString($portal);

        $this->assertStringContainsString("'webauthn.login.admin.challenge'", $admin);
        $this->assertStringContainsString("'webauthn.login.portal.challenge'", $portal);
        $this->assertStringContainsString("json_encode(['error' => 'too_many_requests'])", $admin);
        $this->assertStringContainsString("json_encode(['error' => 'too_many_requests'])", $portal);
    }
}
