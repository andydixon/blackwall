<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class IpAddressMiddlewareProxySpoofingSourceTest extends TestCase
{
    public function testProxyIpExtractionValidatesAndUsesRightMostUntrustedHop(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Middleware/IpAddressMiddleware.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('for ($i = count($ips) - 1; $i >= 0; $i--)', $source);
        $this->assertStringContainsString('!$this->isTrustedProxy($ips[$i], $trustedProxies)', $source);
        $this->assertStringContainsString('filter_var($candidate, FILTER_VALIDATE_IP)', $source);
        $this->assertStringContainsString("return \$this->validatedIpOrNull(\$remoteAddr) ?? '0.0.0.0';", $source);
    }
}
