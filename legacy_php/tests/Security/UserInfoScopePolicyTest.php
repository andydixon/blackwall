<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\UserInfoScopePolicy;
use PHPUnit\Framework\TestCase;

class UserInfoScopePolicyTest extends TestCase
{
    public function testDetectsOpenIdScopePresence(): void
    {
        $this->assertTrue(UserInfoScopePolicy::hasOpenIdScope(['openid', 'profile']));
        $this->assertTrue(UserInfoScopePolicy::hasOpenIdScope(['profile', 'openid']));
        $this->assertFalse(UserInfoScopePolicy::hasOpenIdScope(['profile', 'email']));
        $this->assertFalse(UserInfoScopePolicy::hasOpenIdScope([]));
    }
}
