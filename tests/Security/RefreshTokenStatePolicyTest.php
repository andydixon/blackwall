<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\RefreshTokenStatePolicy;
use PHPUnit\Framework\TestCase;

class RefreshTokenStatePolicyTest extends TestCase
{
    public function testClassifyValidRefreshToken(): void
    {
        $state = RefreshTokenStatePolicy::classify(
            null,
            '2026-03-01 10:00:00',
            new \DateTimeImmutable('2026-03-01 09:59:59')
        );

        $this->assertSame(RefreshTokenStatePolicy::STATE_VALID, $state);
    }

    public function testClassifyExpiredRefreshToken(): void
    {
        $state = RefreshTokenStatePolicy::classify(
            null,
            '2026-03-01 09:59:59',
            new \DateTimeImmutable('2026-03-01 10:00:00')
        );

        $this->assertSame(RefreshTokenStatePolicy::STATE_EXPIRED, $state);
    }

    public function testClassifyReusedRefreshToken(): void
    {
        $state = RefreshTokenStatePolicy::classify(
            '2026-03-01 09:00:00',
            '2026-03-01 11:00:00',
            new \DateTimeImmutable('2026-03-01 10:00:00')
        );

        $this->assertSame(RefreshTokenStatePolicy::STATE_REUSED, $state);
    }

    public function testClassifyInvalidRefreshTokenWhenExpiryMissingOrMalformed(): void
    {
        $this->assertSame(
            RefreshTokenStatePolicy::STATE_INVALID,
            RefreshTokenStatePolicy::classify(null, null)
        );
        $this->assertSame(
            RefreshTokenStatePolicy::STATE_INVALID,
            RefreshTokenStatePolicy::classify(null, 'not-a-date')
        );
    }
}
