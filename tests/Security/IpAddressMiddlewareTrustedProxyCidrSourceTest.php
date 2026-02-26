<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class IpAddressMiddlewareTrustedProxyCidrSourceTest extends TestCase
{
    public function testTrustedProxyEvaluationSupportsCidrRanges(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Middleware/IpAddressMiddleware.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('if ($this->isTrustedProxy($remoteAddr, $trustedProxies)) {', $source);
        $this->assertStringContainsString('if (str_contains($entry, \'/\')) {', $source);
        $this->assertStringContainsString('private function ipInCidr(string $ip, string $cidr): bool', $source);
        $this->assertStringContainsString('inet_pton($ip)', $source);
    }
}
