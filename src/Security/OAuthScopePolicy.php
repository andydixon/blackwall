<?php

declare(strict_types=1);

namespace BlackWall\Security;

final class OAuthScopePolicy
{
    /**
     * @param array<int, mixed> $requested
     * @param array<int, mixed> $allowed
     */
    public static function firstDisallowed(array $requested, array $allowed): ?string
    {
        $allowedSet = [];
        foreach ($allowed as $scope) {
            $scope = trim((string) $scope);
            if ($scope === '') {
                continue;
            }
            $allowedSet[$scope] = true;
        }

        foreach ($requested as $scope) {
            $scope = trim((string) $scope);
            if ($scope === '') {
                continue;
            }
            if (!isset($allowedSet[$scope])) {
                return $scope;
            }
        }

        return null;
    }
}
