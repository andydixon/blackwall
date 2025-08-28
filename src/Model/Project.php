<?php

declare(strict_types=1);

namespace BlackWall\Model;

class Project
{
    public function __construct(
        public readonly int $id,
        public readonly string $uuid,
        public readonly string $name,
        public readonly ?int $ownerUserId,
        public readonly string $status,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }
}
