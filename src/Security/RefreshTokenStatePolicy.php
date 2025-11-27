<?php

declare(strict_types=1);

namespace BlackWall\Security;

class RefreshTokenStatePolicy
{
    public const STATE_VALID = 'valid';
    public const STATE_EXPIRED = 'expired';
    public const STATE_REUSED = 'reused';
    public const STATE_INVALID = 'invalid';

    public static function classify(?string $revokedAt, ?string $expiresAt, ?\DateTimeImmutable $now = null): string
    {
        if ($expiresAt === null || trim($expiresAt) === '') {
            return self::STATE_INVALID;
        }

        try {
            $expiry = new \DateTimeImmutable($expiresAt);
        } catch (\Throwable $e) {
            return self::STATE_INVALID;
        }

        $reference = $now ?? new \DateTimeImmutable();
        if ($expiry < $reference) {
            return self::STATE_EXPIRED;
        }

        if ($revokedAt !== null && trim($revokedAt) !== '') {
            return self::STATE_REUSED;
        }

        return self::STATE_VALID;
    }
}
