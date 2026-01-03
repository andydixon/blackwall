<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class ApprovalCreateAssignmentTenantBoundarySourceTest extends TestCase
{
    public function testCreateAssignmentApprovalRevalidatesUserOrganizationAgainstProject(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $casePos = strpos($source, "case 'create_assignment':");
        $nextCasePos = strpos($source, "case 'update_assignment':");

        $this->assertNotFalse($casePos);
        $this->assertNotFalse($nextCasePos);
        $segment = substr($source, $casePos, $nextCasePos - $casePos);

        $orgCheckPos = strpos($segment, '$targetUser->organizationId !== $project->organizationId');
        $createPos = strpos($segment, '$this->roleRepo->create($userId, $project->id, $privilegeLevel);');

        $this->assertNotFalse($orgCheckPos);
        $this->assertNotFalse($createPos);
        $this->assertLessThan($createPos, $orgCheckPos);
    }
}
