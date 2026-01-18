<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminScopeActiveUserRequirementSourceTest extends TestCase
{
    public function testAdminScopeResolverRequiresActiveUserStatus(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("SELECT 1 FROM users WHERE id = ? AND status = 'active' LIMIT 1", $source);
        $this->assertStringContainsString("'is_admin' => false", $source);
        $this->assertStringContainsString("'is_super_admin' => false", $source);
    }
}
