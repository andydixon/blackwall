<?php

declare(strict_types=1);

namespace BlackWall\Security;

class EnrollmentTokenExpiryValidator
{
    public static function isValid(?string $expiryValue, ?\DateTimeImmutable $now = null): bool
    {
        if ($expiryValue === null || trim($expiryValue) === '') {
            return false;
        }

        try {
            $expiry = new \DateTimeImmutable($expiryValue);
        } catch (\Throwable $e) {
            return false;
        }

        $reference = $now ?? new \DateTimeImmutable();
        return $expiry >= $reference;
    }
}
