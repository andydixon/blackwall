<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthAuthorizeScopeEnforcementSourceTest extends TestCase
{
    public function testAuthorizeFlowRejectsDisallowedClientScopes(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('OAuthScopePolicy::firstDisallowed($requestedScopes, $client->scopes);', $source);
        $this->assertStringContainsString("'error_code' => 'invalid_scope'", $source);
        $this->assertStringContainsString("'Requested scope is not allowed for this client'", $source);
    }
}
