<?php

declare(strict_types=1);

namespace BlackWall\Domain;

class PrivilegeLabelResolver
{
    public static function resolve(int $level, ?string $overrideName = null): string
    {
        $name = trim((string) ($overrideName ?? ''));
        if ($name !== '') {
            return $name;
        }

        return match ($level) {
            1 => 'Admin',
            2 => 'User',
            3 => 'Restricted User',
            default => "Custom Rules ({$level})",
        };
    }
}
