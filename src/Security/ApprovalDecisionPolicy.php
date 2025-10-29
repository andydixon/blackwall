<?php

declare(strict_types=1);

namespace BlackWall\Security;

class ApprovalDecisionPolicy
{
    public static function denialReason(
        bool $canDecideApprovals,
        array $approval,
        array $scope,
        int $actorUserId
    ): ?string {
        if (!$canDecideApprovals) {
            return 'missing_capability';
        }

        if (!self::isVisibleToActor($approval, $scope, $actorUserId)) {
            return 'out_of_scope';
        }

        if ((int) ($approval['requested_by_user_id'] ?? 0) === $actorUserId) {
            return 'self_decision';
        }

        return null;
    }

    private static function isVisibleToActor(array $approval, array $scope, int $actorUserId): bool
    {
        if ((bool) ($scope['is_super_admin'] ?? false)) {
            return true;
        }

        if ((int) ($approval['requested_by_user_id'] ?? 0) === $actorUserId) {
            return true;
        }

        $projectId = (int) ($approval['project_id'] ?? 0);
        if ($projectId < 1) {
            return false;
        }

        $projectIds = $scope['project_ids'] ?? [];
        return is_array($projectIds) && in_array($projectId, $projectIds, true);
    }
}
