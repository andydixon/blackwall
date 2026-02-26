<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\OAuthScopePolicy;
use PHPUnit\Framework\TestCase;

class OAuthScopePolicyTest extends TestCase
{
    public function testFirstDisallowedReturnsNullWhenAllScopesAllowed(): void
    {
        $this->assertNull(
            OAuthScopePolicy::firstDisallowed(['openid', 'profile'], ['openid', 'profile', 'email'])
        );
    }

    public function testFirstDisallowedReturnsUnexpectedScope(): void
    {
        $this->assertSame(
            'offline_access',
            OAuthScopePolicy::firstDisallowed(['openid', 'offline_access'], ['openid', 'profile'])
        );
    }

    public function testFirstDisallowedIgnoresBlankScopeTokens(): void
    {
        $this->assertNull(
            OAuthScopePolicy::firstDisallowed(['openid', '', '   '], ['openid'])
        );
    }
}
