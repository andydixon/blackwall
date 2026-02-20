<?php

declare(strict_types=1);

namespace BlackWall\Model;

class User
{
    public function __construct(
        public readonly int $id,
        public readonly int $organizationId,
        public readonly string $uuid,
        public readonly ?string $displayLabel,
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
