<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class ApprovalDecisionLockingSourceTest extends TestCase
{
    public function testRejectAndCancelUsePerApprovalExecutionLocking(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("public function approvalReject(Request \$request, Response \$response, array \$args): Response", $source);
        $this->assertStringContainsString("public function approvalCancel(Request \$request, Response \$response, array \$args): Response", $source);
        $this->assertStringContainsString("if (!\$this->acquireApprovalExecutionLock(\$approvalId)) {", $source);
        $this->assertStringContainsString("\$this->releaseApprovalExecutionLock(\$approvalId);", $source);
    }
}
