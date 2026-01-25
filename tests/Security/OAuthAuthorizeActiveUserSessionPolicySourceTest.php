<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthAuthorizeActiveUserSessionPolicySourceTest extends TestCase
{
    public function testAuthorizeAndConsentSubmitRequireActiveSessionUser(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('if ($userId !== null && !$this->isActiveUserId((int) $userId)) {', $source);
        $this->assertStringContainsString('if (!$this->isActiveUserId((int) $userId)) {', $source);
        $this->assertStringContainsString('User account inactive', $source);
        $this->assertStringContainsString("SELECT 1 FROM users WHERE id = ? AND status = 'active' LIMIT 1", $source);
    }
}
