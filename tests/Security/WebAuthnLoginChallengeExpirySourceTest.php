<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginChallengeExpirySourceTest extends TestCase
{
    public function testLoginChallengesUseTtlBackedSessionStateAcrossControllers(): void
    {
        $admin = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $portal = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $oauth = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');

        $this->assertIsString($admin);
        $this->assertIsString($portal);
        $this->assertIsString($oauth);

        $this->assertStringContainsString('private const LOGIN_CHALLENGE_TTL_SECONDS = 120;', $admin);
        $this->assertStringContainsString('private const LOGIN_CHALLENGE_TTL_SECONDS = 120;', $portal);
        $this->assertStringContainsString('private const LOGIN_CHALLENGE_TTL_SECONDS = 120;', $oauth);

        $this->assertStringContainsString("'expires_at' => time() + self::LOGIN_CHALLENGE_TTL_SECONDS", $admin);
        $this->assertStringContainsString("'expires_at' => time() + self::LOGIN_CHALLENGE_TTL_SECONDS", $portal);
        $this->assertStringContainsString("'expires_at' => time() + self::LOGIN_CHALLENGE_TTL_SECONDS", $oauth);

        $this->assertStringContainsString('($expiresAt > 0 && $expiresAt < time())', $admin);
        $this->assertStringContainsString('($expiresAt > 0 && $expiresAt < time())', $portal);
        $this->assertStringContainsString('($expiresAt > 0 && $expiresAt < time())', $oauth);
    }
}
