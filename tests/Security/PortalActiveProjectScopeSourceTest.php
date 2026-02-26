<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class PortalActiveProjectScopeSourceTest extends TestCase
{
    public function testPortalDashboardListsOnlyActiveProjectsForUserAssignments(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('AND p.status = ?', $source);
        $this->assertStringContainsString('$stmt->execute([$userId, \'active\']);', $source);
    }
}
