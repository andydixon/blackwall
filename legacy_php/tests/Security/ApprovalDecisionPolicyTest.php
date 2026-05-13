<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\ApprovalDecisionPolicy;
use PHPUnit\Framework\TestCase;

class ApprovalDecisionPolicyTest extends TestCase
{
    public function testDeniesWhenCapabilityMissing(): void
    {
        $approval = ['requested_by_user_id' => 12, 'project_id' => 3];
        $scope = ['is_super_admin' => true, 'project_ids' => [3, 4]];

        $reason = ApprovalDecisionPolicy::denialReason(false, $approval, $scope, 10);

        $this->assertSame('missing_capability', $reason);
    }

    public function testDeniesWhenApprovalIsOutOfScope(): void
    {
        $approval = ['requested_by_user_id' => 12, 'project_id' => 9];
        $scope = ['is_super_admin' => false, 'project_ids' => [3, 4]];

        $reason = ApprovalDecisionPolicy::denialReason(true, $approval, $scope, 10);

        $this->assertSame('out_of_scope', $reason);
    }

    public function testDeniesSelfDecisionWhenVisible(): void
    {
        $approval = ['requested_by_user_id' => 10, 'project_id' => 3];
        $scope = ['is_super_admin' => false, 'project_ids' => [3, 4]];

        $reason = ApprovalDecisionPolicy::denialReason(true, $approval, $scope, 10);

        $this->assertSame('self_decision', $reason);
    }

    public function testAllowsInScopeNonSelfDecision(): void
    {
        $approval = ['requested_by_user_id' => 12, 'project_id' => 3];
        $scope = ['is_super_admin' => false, 'project_ids' => [3, 4]];

        $reason = ApprovalDecisionPolicy::denialReason(true, $approval, $scope, 10);

        $this->assertNull($reason);
    }

    public function testAllowsSuperAdminVisibilityButStillDeniesSelfDecision(): void
    {
        $approval = ['requested_by_user_id' => 10, 'project_id' => 999];
        $scope = ['is_super_admin' => true, 'project_ids' => []];

        $reason = ApprovalDecisionPolicy::denialReason(true, $approval, $scope, 10);

        $this->assertSame('self_decision', $reason);
    }
}
