<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminAuditExportRateLimitSourceTest extends TestCase
{
    public function testAuditExportEndpointHasDedicatedRateLimitGuard(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("'admin.audit_export'", $source);
        $this->assertStringContainsString('ADMIN_AUDIT_EXPORT_RATE_LIMIT_ATTEMPTS', $source);
        $this->assertStringContainsString('Rate limit exceeded for audit export endpoint', $source);
        $this->assertStringContainsString("'error' => 'too_many_requests'", $source);
    }
}
