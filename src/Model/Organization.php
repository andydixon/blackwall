<?php

declare(strict_types=1);

namespace BlackWall\Model;

class Organization
{
    public function __construct(
        public readonly int $id,
        public readonly string $uuid,
        public readonly string $name,
        public readonly string $slug,
        public readonly ?string $logoUrl,
        public readonly string $status,
        public readonly ?int $adminUserId,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }
}

