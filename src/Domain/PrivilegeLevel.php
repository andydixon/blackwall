<?php

declare(strict_types=1);

namespace BlackWall\Domain;

class PrivilegeLevel
{
    public function __construct(
        public readonly int $id,
        public readonly int $projectId,
        public readonly int $level,
        public readonly string $name,
        public readonly ?string $description
    ) {
    }
}
