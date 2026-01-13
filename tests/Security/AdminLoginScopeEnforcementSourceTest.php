<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminLoginScopeEnforcementSourceTest extends TestCase
{
    public function testAdminLoginVerifyRequiresAdminScopeBeforeSessionAuthentication(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('Credential user lacks admin scope', $source);

        $scopeCheckPos = strpos($source, '$adminScope = $this->getAdminScope($userId);');
        $sessionSetPos = strpos($source, "SessionManager::set('user_id', \$userId);");
        $this->assertNotFalse($scopeCheckPos);
        $this->assertNotFalse($sessionSetPos);
        $this->assertLessThan($sessionSetPos, $scopeCheckPos);
    }
}
