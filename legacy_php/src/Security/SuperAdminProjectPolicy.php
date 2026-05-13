<?php

declare(strict_types=1);

namespace BlackWall\Security;

class SuperAdminProjectPolicy
{
    public static function isSuperProject(string $projectUuid, string $configuredSuperProjectUuid): bool
    {
        $configured = trim($configuredSuperProjectUuid);
        if ($configured === '') {
            return false;
        }

        return hash_equals($configured, $projectUuid);
    }
}
