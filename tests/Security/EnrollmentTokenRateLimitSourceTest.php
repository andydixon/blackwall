<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class EnrollmentTokenRateLimitSourceTest extends TestCase
{
    public function testBootstrapAndEnrollmentTokenEndpointsAreRateLimited(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/BootstrapController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString("'bootstrap.token.verify'", $source);
        $this->assertStringContainsString("'enrollment.token.verify'", $source);
        $this->assertStringContainsString('too_many_requests', $source);
    }
}
