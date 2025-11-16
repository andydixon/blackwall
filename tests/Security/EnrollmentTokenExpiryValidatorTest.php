<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\EnrollmentTokenExpiryValidator;
use PHPUnit\Framework\TestCase;

class EnrollmentTokenExpiryValidatorTest extends TestCase
{
    public function testRejectsExpiredToken(): void
    {
        $now = new \DateTimeImmutable('2026-02-25T10:00:00+00:00');
        $this->assertFalse(EnrollmentTokenExpiryValidator::isValid('2026-02-25 09:59:59', $now));
    }

    public function testAcceptsFutureExpiry(): void
    {
        $now = new \DateTimeImmutable('2026-02-25T10:00:00+00:00');
        $this->assertTrue(EnrollmentTokenExpiryValidator::isValid('2026-02-25 10:00:01', $now));
    }

    public function testRejectsMissingOrMalformedExpiry(): void
    {
        $this->assertFalse(EnrollmentTokenExpiryValidator::isValid(null));
        $this->assertFalse(EnrollmentTokenExpiryValidator::isValid('not-a-date'));
    }
}
