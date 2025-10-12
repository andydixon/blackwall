<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\AdminMutationPolicy;
use PHPUnit\Framework\TestCase;

class AdminMutationPolicyTest extends TestCase
{
    public function testProjectSettingsApprovalRequiredForNonDirectRoleWhenChanged(): void
    {
        $required = AdminMutationPolicy::shouldRequireProjectSettingsApproval(
            false,
            'Project A',
            'active',
            'Project B',
            'active'
        );

        $this->assertTrue($required);
    }

    public function testProjectSettingsApprovalNotRequiredWhenUnchanged(): void
    {
        $required = AdminMutationPolicy::shouldRequireProjectSettingsApproval(
            false,
            'Project A',
            'active',
            'Project A',
            'active'
        );

        $this->assertFalse($required);
    }

    public function testClientSettingsApprovalDetectsConfigChange(): void
    {
        $current = [
            'name' => 'Client A',
            'status' => 'active',
            'redirect_uris' => ['https://example.com/callback'],
            'scopes' => ['openid', 'profile'],
            'access_token_type' => 'jwt',
            'access_token_lifetime' => 3600,
            'refresh_token_lifetime' => 2592000,
            'oidc_enabled' => 1,
        ];
        $requested = $current;
        $requested['scopes'] = ['openid', 'email'];

        $required = AdminMutationPolicy::shouldRequireClientSettingsApproval(false, $current, $requested);

        $this->assertTrue($required);
    }

    public function testClientSettingsApprovalIgnoresScopeOrder(): void
    {
        $current = [
            'name' => 'Client A',
            'status' => 'active',
            'redirect_uris' => ['https://example.com/callback'],
            'scopes' => ['openid', 'profile'],
            'access_token_type' => 'jwt',
            'access_token_lifetime' => 3600,
            'refresh_token_lifetime' => 2592000,
            'oidc_enabled' => 1,
        ];
        $requested = $current;
        $requested['scopes'] = ['profile', 'openid'];

        $required = AdminMutationPolicy::shouldRequireClientSettingsApproval(false, $current, $requested);

        $this->assertFalse($required);
    }

    public function testAssignmentMutationsRequireApprovalWhenNotDirect(): void
    {
        $this->assertTrue(AdminMutationPolicy::shouldRequireAssignmentApproval(false));
        $this->assertFalse(AdminMutationPolicy::shouldRequireAssignmentApproval(true));
    }
}

