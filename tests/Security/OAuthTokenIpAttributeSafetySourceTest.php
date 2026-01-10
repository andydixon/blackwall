<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthTokenIpAttributeSafetySourceTest extends TestCase
{
    public function testTokenEndpointUsesSafeDefaultWhenIpAttributeMissing(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString(
            "getAttribute('ip_address', '0.0.0.0')",
            $source
        );
    }
}
