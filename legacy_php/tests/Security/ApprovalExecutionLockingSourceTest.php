<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class ApprovalExecutionLockingSourceTest extends TestCase
{
    public function testApprovalApproveUsesPerApprovalLockAndRechecksPendingState(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('if (!$this->acquireApprovalExecutionLock($approvalId)) {', $source);
        $this->assertStringContainsString('$approval = $this->approvalService->getById($approvalId);', $source);
        $this->assertStringContainsString('SELECT GET_LOCK(?, 2)', $source);
        $this->assertStringContainsString('SELECT RELEASE_LOCK(?)', $source);
    }
}
