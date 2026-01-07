<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminClientRedirectUriPolicyEnforcementSourceTest extends TestCase
{
    public function testClientMutationsUseRedirectUriSecurityPolicy(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('OAuthRedirectUriPolicy::allAllowed($redirectUris)', $source);
        $this->assertStringContainsString('invalid_redirect_uri', $source);
        $this->assertStringContainsString("case 'update_client_settings':", $source);
    }
}
