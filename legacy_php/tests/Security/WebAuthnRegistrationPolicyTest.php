<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\WebAuthnRegistrationPolicy;
use PHPUnit\Framework\TestCase;

class WebAuthnRegistrationPolicyTest extends TestCase
{
    public function testAcceptsValidRegistrationClientData(): void
    {
        $challengeBytes = random_bytes(32);
        $expectedChallenge = base64_encode($challengeBytes);
        $clientData = [
            'type' => 'webauthn.create',
            'origin' => 'https://example.test',
            'challenge' => rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '='),
        ];
        $clientDataEncoded = base64_encode((string) json_encode($clientData));

        $this->assertTrue(WebAuthnRegistrationPolicy::validateClientData($clientDataEncoded, $expectedChallenge, 'example.test'));
    }

    public function testRejectsRegistrationWhenTypeOriginOrChallengeMismatch(): void
    {
        $challengeBytes = random_bytes(32);
        $expectedChallenge = base64_encode($challengeBytes);

        $wrongType = base64_encode((string) json_encode([
            'type' => 'webauthn.get',
            'origin' => 'https://example.test',
            'challenge' => rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '='),
        ]));
        $this->assertFalse(WebAuthnRegistrationPolicy::validateClientData($wrongType, $expectedChallenge, 'example.test'));

        $wrongOrigin = base64_encode((string) json_encode([
            'type' => 'webauthn.create',
            'origin' => 'https://attacker.test',
            'challenge' => rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '='),
        ]));
        $this->assertFalse(WebAuthnRegistrationPolicy::validateClientData($wrongOrigin, $expectedChallenge, 'example.test'));

        $wrongChallenge = base64_encode((string) json_encode([
            'type' => 'webauthn.create',
            'origin' => 'https://example.test',
            'challenge' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
        ]));
        $this->assertFalse(WebAuthnRegistrationPolicy::validateClientData($wrongChallenge, $expectedChallenge, 'example.test'));
    }
}
