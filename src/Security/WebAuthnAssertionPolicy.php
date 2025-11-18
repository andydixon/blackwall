<?php

declare(strict_types=1);

namespace BlackWall\Security;

class WebAuthnAssertionPolicy
{
    public static function hasValidRpIdHash(string $authenticatorDataBinary, string $rpId): bool
    {
        if (strlen($authenticatorDataBinary) < 32) {
            return false;
        }

        $expected = hash('sha256', $rpId, true);
        $received = substr($authenticatorDataBinary, 0, 32);

        return hash_equals($expected, $received);
    }

    public static function hasValidSignCounter(int $storedSignCounter, int $assertedSignCounter): bool
    {
        if ($storedSignCounter < 0 || $assertedSignCounter < 0) {
            return false;
        }

        // Authenticators that do not implement counters often report 0 always.
        if ($storedSignCounter === 0 && $assertedSignCounter === 0) {
            return true;
        }

        // For non-zero counters, require monotonic increase to detect cloned authenticators.
        return $assertedSignCounter > $storedSignCounter;
    }
}
