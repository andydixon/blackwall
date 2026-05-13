<?php

declare(strict_types=1);

namespace BlackWall\Security;

class WebAuthnRegistrationPolicy
{
    public static function validateClientData(
        string $clientDataJsonEncoded,
        string $expectedChallengeBase64,
        string $rpId
    ): bool {
        $clientDataJson = self::decodeFlexibleBase64($clientDataJsonEncoded);
        if ($clientDataJson === false || $clientDataJson === '') {
            return false;
        }

        $clientData = json_decode($clientDataJson, true);
        if (!is_array($clientData)) {
            return false;
        }

        if (($clientData['type'] ?? '') !== 'webauthn.create') {
            return false;
        }

        $origin = (string) ($clientData['origin'] ?? '');
        $expectedOrigin = 'https://' . $rpId;
        if (!hash_equals($expectedOrigin, $origin)) {
            return false;
        }

        $receivedChallenge = self::decodeFlexibleBase64((string) ($clientData['challenge'] ?? ''));
        $expectedChallenge = base64_decode($expectedChallengeBase64, true);
        if ($receivedChallenge === false || $expectedChallenge === false) {
            return false;
        }

        return hash_equals($expectedChallenge, $receivedChallenge);
    }

    private static function decodeFlexibleBase64(string $value): string|false
    {
        if ($value === '') {
            return false;
        }

        $urlDecoded = Base64Url::decode($value);
        if ($urlDecoded !== false) {
            return $urlDecoded;
        }

        return base64_decode($value, true);
    }
}
