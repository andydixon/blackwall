<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OrganizationSignupRateLimitSourceTest extends TestCase
{
    public function testOrganizationSignupHasRateLimitGuard(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/BootstrapController.php');
        $this->assertIsString($source);
        $this->assertStringContainsString("'organization.signup'", $source);
        $this->assertStringContainsString('rate_limited', $source);
    }
}
