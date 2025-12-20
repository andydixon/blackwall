<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\SuperAdminProjectPolicy;
use PHPUnit\Framework\TestCase;

class SuperAdminProjectPolicyTest extends TestCase
{
    public function testRequiresConfiguredUuidForSuperAdminProject(): void
    {
        $this->assertFalse(SuperAdminProjectPolicy::isSuperProject('11111111-1111-1111-1111-111111111111', ''));
    }

    public function testMatchesOnlyConfiguredSuperAdminProjectUuid(): void
    {
        $configured = '00000000-0000-0000-0000-000000000123';
        $this->assertTrue(SuperAdminProjectPolicy::isSuperProject($configured, $configured));
        $this->assertFalse(SuperAdminProjectPolicy::isSuperProject('11111111-1111-1111-1111-111111111111', $configured));
    }
}
