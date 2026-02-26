<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthRefreshScopeEnforcementSourceTest extends TestCase
{
    public function testRefreshTokenFlowRejectsScopesNoLongerAllowedForClient(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Service/OAuthService.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('c.scopes AS client_scopes', $source);
        $this->assertStringContainsString('OAuthScopePolicy::firstDisallowed($refreshScopes, $clientScopes);', $source);
        $this->assertStringContainsString('if ($disallowedScope !== null) {', $source);
    }
}
