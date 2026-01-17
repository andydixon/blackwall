<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthTokenSubjectStatusPolicySourceTest extends TestCase
{
    public function testAuthorizationCodeExchangeRequiresActiveClientAndSubjects(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Service/OAuthService.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("c.status = ? AND ac.used_at IS NULL", $source);
        $this->assertStringContainsString("SELECT uuid, display_label FROM users WHERE id = ? AND status = 'active'", $source);
        $this->assertStringContainsString("SELECT uuid FROM projects WHERE id = ? AND status = 'active'", $source);
        $this->assertStringContainsString("SELECT client_id FROM oauth_clients WHERE id = ? AND status = 'active'", $source);
        $this->assertStringContainsString('): ?array {', $source);
    }
}
