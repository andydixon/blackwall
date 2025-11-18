<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\WebAuthnAssertionPolicy;
use PHPUnit\Framework\TestCase;

class WebAuthnAssertionPolicyTest extends TestCase
{
    public function testRejectsAssertionWhenRpIdHashDoesNotMatch(): void
    {
        $rpId = 'example.test';
        $invalidHash = hash('sha256', 'other.example', true);
        $authData = $invalidHash . str_repeat("\x00", 5);

        $this->assertFalse(WebAuthnAssertionPolicy::hasValidRpIdHash($authData, $rpId));
    }

    public function testAcceptsAssertionWhenRpIdHashMatches(): void
    {
        $rpId = 'example.test';
        $validHash = hash('sha256', $rpId, true);
        $authData = $validHash . str_repeat("\x00", 5);

        $this->assertTrue(WebAuthnAssertionPolicy::hasValidRpIdHash($authData, $rpId));
    }

    public function testRejectsSignCounterRegression(): void
    {
        $this->assertFalse(WebAuthnAssertionPolicy::hasValidSignCounter(8, 8));
        $this->assertFalse(WebAuthnAssertionPolicy::hasValidSignCounter(8, 7));
        $this->assertFalse(WebAuthnAssertionPolicy::hasValidSignCounter(8, 0));
    }

    public function testAllowsSignCounterIncreaseAndNoCounterDevices(): void
    {
        $this->assertTrue(WebAuthnAssertionPolicy::hasValidSignCounter(8, 9));
        $this->assertTrue(WebAuthnAssertionPolicy::hasValidSignCounter(0, 0));
        $this->assertTrue(WebAuthnAssertionPolicy::hasValidSignCounter(0, 1));
    }
}
