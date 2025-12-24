<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class MetricsEndpointAuthPolicyTest extends TestCase
{
    public function testMetricsEndpointDefaultsToAuthenticatedMode(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/MetricsController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("Config::getBool('METRICS_ALLOW_UNAUTHENTICATED', false)", $source);
        $this->assertStringContainsString('Metrics authentication is not configured', $source);
        $this->assertStringContainsString("->withStatus(503)", $source);
    }
}
