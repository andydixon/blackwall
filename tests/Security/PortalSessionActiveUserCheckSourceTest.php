<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class PortalSessionActiveUserCheckSourceTest extends TestCase
{
    public function testPortalSessionAuthCheckRequiresActiveUserStatus(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("SELECT 1 FROM users WHERE id = ? AND status = 'active' LIMIT 1", $source);
        $this->assertStringContainsString('return (bool) $stmt->fetchColumn();', $source);
    }
}
