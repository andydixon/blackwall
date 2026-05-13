<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginChallengeSingleUseSourceTest extends TestCase
{
    public function testAdminPortalAndOauthConsumeLoginChallengeBeforeVerification(): void
    {
        $admin = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $portal = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $oauth = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');

        $this->assertIsString($admin);
        $this->assertIsString($portal);
        $this->assertIsString($oauth);

        $this->assertStringContainsString("SessionManager::remove('webauthn_challenge');", $admin);
        $this->assertStringContainsString("SessionManager::remove('portal_webauthn_challenge');", $portal);
        $this->assertStringContainsString("SessionManager::remove('oauth_webauthn_challenge');", $oauth);

        $this->assertLessThan(
            strpos($admin, 'verifyAssertion('),
            strpos($admin, "SessionManager::remove('webauthn_challenge');")
        );
        $this->assertLessThan(
            strpos($portal, 'verifyAssertion('),
            strpos($portal, "SessionManager::remove('portal_webauthn_challenge');")
        );
        $this->assertLessThan(
            strpos($oauth, 'verifyAssertion('),
            strpos($oauth, "SessionManager::remove('oauth_webauthn_challenge');")
        );
    }
}
