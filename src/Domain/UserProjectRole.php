<?php

declare(strict_types=1);

namespace BlackWall\Domain;

class UserProjectRole
{
    public function __construct(
        public readonly int $id,
        public readonly int $userId,
        public readonly int $projectId,
        public readonly int $privilegeLevel,
        public readonly \DateTimeImmutable $createdAt
    ) {
    }
}
