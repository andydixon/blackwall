<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminRoleScopeIntegrationSourceTest extends TestCase
{
    public function testAdminScopeIncludesConfiguredAdminRoles(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('$this->adminAuthz->hasConfiguredRoles()', $source);
        $this->assertStringContainsString('$this->adminAuthz->getRole($userId)', $source);
        $this->assertStringContainsString("'is_admin' => \$isSuperAdmin || \$hasRoleBasedAdmin || !empty(\$organizationIds)", $source);
        $this->assertStringContainsString("'admin_role' => \$effectiveAdminRole", $source);
    }
}
