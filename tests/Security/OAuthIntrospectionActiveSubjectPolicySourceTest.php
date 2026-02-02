<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthIntrospectionActiveSubjectPolicySourceTest extends TestCase
{
    public function testIntrospectionRequiresActiveUserProjectAndClient(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Service/OAuthService.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("AND u.status = \\'active\\'", $source);
        $this->assertStringContainsString("AND p.status = \\'active\\'", $source);
        $this->assertStringContainsString("AND c.status = \\'active\\'", $source);
    }
}
