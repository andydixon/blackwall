<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthJwtRevocationEnforcementSourceTest extends TestCase
{
    public function testJwtTokensArePersistedAndCheckedForRevocationAtUserinfo(): void
    {
        $serviceSource = file_get_contents(dirname(__DIR__, 2) . '/src/Service/OAuthService.php');
        $controllerSource = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');

        $this->assertIsString($serviceSource);
        $this->assertIsString($controllerSource);

        $this->assertStringContainsString('$accessTokenHash = $this->hasher->hash($accessToken);', $serviceSource);
        $this->assertStringContainsString('INSERT INTO oauth_access_tokens', $serviceSource);
        $this->assertStringContainsString('JWT token revoked or expired', $controllerSource);
        $this->assertStringContainsString('WHERE t.token_hash = ? AND t.revoked_at IS NULL AND t.expires_at > NOW() AND c.client_id = ? AND c.status = ?', $controllerSource);
    }
}
