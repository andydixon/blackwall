<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthEntryRateLimitSourceTest extends TestCase
{
    public function testAuthorizeAndOAuthLoginChallengeIncludeRateLimitGuards(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString("'oauth.authorize'", $source);
        $this->assertStringContainsString("'webauthn.login.oauth.challenge'", $source);
        $this->assertStringContainsString("json_encode(['error' => 'too_many_requests'])", $source);
    }
}
