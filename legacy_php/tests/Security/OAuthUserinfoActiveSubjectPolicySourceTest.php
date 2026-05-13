<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthUserinfoActiveSubjectPolicySourceTest extends TestCase
{
    public function testUserinfoRequiresActiveUserAndProjectForJwtAndOpaqueTokens(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('FROM users WHERE uuid = ? AND status = ?', $source);
        $this->assertStringContainsString('FROM projects WHERE uuid = ? AND status = ?', $source);
        $this->assertStringContainsString('User or project inactive for JWT token', $source);
        $this->assertStringContainsString('AND u.status = ? AND p.status = ?', $source);
    }
}
