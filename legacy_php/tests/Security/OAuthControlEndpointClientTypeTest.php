<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthControlEndpointClientTypeTest extends TestCase
{
    public function testRevokeAndIntrospectEnforceConfidentialClients(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('if (!$client->isConfidential())', $source);
        $this->assertStringContainsString("json_encode(['error' => 'unauthorized_client'])", $source);
        $this->assertStringContainsString("json_encode(['active' => false])", $source);
    }
}
