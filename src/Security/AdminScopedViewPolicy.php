<?php

declare(strict_types=1);

namespace BlackWall\Security;

class AdminScopedViewPolicy
{
    public static function canAccessProjectId(array $scope, int $projectId): bool
    {
        if ((bool) ($scope['is_super_admin'] ?? false)) {
            return true;
        }

        $projectIds = $scope['project_ids'] ?? [];
        return is_array($projectIds) && in_array($projectId, $projectIds, true);
    }

    public static function canAccessProjectUuid(array $scope, string $projectUuid): bool
    {
        if ((bool) ($scope['is_super_admin'] ?? false)) {
            return true;
        }

        $set = $scope['project_uuid_set'] ?? [];
        return is_array($set) && isset($set[$projectUuid]);
    }

    public static function canAccessUserByProjects(array $scope, array $userProjectIds): bool
    {
        if ((bool) ($scope['is_super_admin'] ?? false)) {
            return true;
        }

        $projectIds = $scope['project_ids'] ?? [];
        if (!is_array($projectIds) || empty($projectIds)) {
            return false;
        }

        foreach ($userProjectIds as $projectId) {
            if (in_array((int) $projectId, $projectIds, true)) {
                return true;
            }
        }

        return false;
    }
}
