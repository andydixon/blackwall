<?php

declare(strict_types=1);

namespace BlackWall\Security;

class UserInfoScopePolicy
{
    public static function hasOpenIdScope(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (is_string($scope) && hash_equals('openid', $scope)) {
                return true;
            }
        }

        return false;
    }
}
