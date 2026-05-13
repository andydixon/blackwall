<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginCsrfProtectionSourceTest extends TestCase
{
    public function testLoginChallengeAndVerifyHandlersValidateCsrfTokens(): void
    {
        $admin = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $portal = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $oauth = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $oauthTemplate = file_get_contents(dirname(__DIR__, 2) . '/templates/oauth/login.php');

        $this->assertIsString($admin);
        $this->assertIsString($portal);
        $this->assertIsString($oauth);
        $this->assertIsString($oauthTemplate);

        $this->assertStringContainsString("failure_reason' => 'admin.login_verify", $admin);
        $this->assertStringContainsString("failure_reason' => 'portal.login_verify", $portal);
        $this->assertStringContainsString("failure_reason' => 'oauth.login_verify", $oauth);
        $this->assertStringContainsString("CSRFProtection::validateToken", $admin);
        $this->assertStringContainsString("CSRFProtection::validateToken", $portal);
        $this->assertStringContainsString("CSRFProtection::validateToken", $oauth);
        $this->assertStringContainsString('csrf_token: csrfToken', $oauthTemplate);
    }
}
