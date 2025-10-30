<?php

declare(strict_types=1);

namespace Tests\Integration;

use BlackWall\Security\AdminScopedViewPolicy;
use PHPUnit\Framework\TestCase;

class AdminScopeAccessIntegrationTest extends TestCase
{
    public function testProjectAdminCannotAccessOutOfScopeProjectPage(): void
    {
        $scope = [
            'is_super_admin' => false,
            'project_ids' => [10, 20],
            'project_uuid_set' => ['project-10' => true, 'project-20' => true],
        ];

        $this->assertFalse(AdminScopedViewPolicy::canAccessProjectId($scope, 30));
        $this->assertFalse(AdminScopedViewPolicy::canAccessProjectUuid($scope, 'project-30'));
    }

    public function testProjectAdminCanAccessInScopeProjectAndClientPages(): void
    {
        $scope = [
            'is_super_admin' => false,
            'project_ids' => [10, 20],
            'project_uuid_set' => ['project-10' => true, 'project-20' => true],
        ];

        $this->assertTrue(AdminScopedViewPolicy::canAccessProjectId($scope, 20));
        $this->assertTrue(AdminScopedViewPolicy::canAccessProjectUuid($scope, 'project-20'));
    }

    public function testProjectAdminCanOnlyAccessUsersInSharedProjects(): void
    {
        $scope = [
            'is_super_admin' => false,
            'project_ids' => [10, 20],
            'project_uuid_set' => ['project-10' => true, 'project-20' => true],
        ];

        $this->assertTrue(AdminScopedViewPolicy::canAccessUserByProjects($scope, [99, 20]));
        $this->assertFalse(AdminScopedViewPolicy::canAccessUserByProjects($scope, [99, 30]));
    }

    public function testSuperAdminCanAccessProjectsUsersAndAuditScopes(): void
    {
        $scope = [
            'is_super_admin' => true,
            'project_ids' => [],
            'project_uuid_set' => [],
        ];

        $this->assertTrue(AdminScopedViewPolicy::canAccessProjectId($scope, 999));
        $this->assertTrue(AdminScopedViewPolicy::canAccessProjectUuid($scope, 'any-project'));
        $this->assertTrue(AdminScopedViewPolicy::canAccessUserByProjects($scope, [1, 2, 3]));
        $this->assertTrue(AdminScopedViewPolicy::canAccessUserByProjects($scope, []));
    }
}
