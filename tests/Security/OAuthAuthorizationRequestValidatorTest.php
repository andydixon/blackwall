<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\OAuthAuthorizationRequestValidator;
use PHPUnit\Framework\TestCase;

class OAuthAuthorizationRequestValidatorTest extends TestCase
{
    public function testRejectsMissingState(): void
    {
        $validator = new OAuthAuthorizationRequestValidator();
        $result = $validator->validate([
            'client_id' => 'client-a',
            'redirect_uri' => 'https://app.example/callback',
            'response_type' => 'code',
            'code_challenge' => 'abc',
            'code_challenge_method' => 'S256',
        ], false, null);

        $this->assertFalse($result['ok']);
        $this->assertSame('invalid_request', $result['error']);
        $this->assertSame('Missing parameter: state', $result['description']);
    }

    public function testRejectsOpenIdRequestWithoutNonce(): void
    {
        $validator = new OAuthAuthorizationRequestValidator();
        $result = $validator->validate([
            'client_id' => 'client-a',
            'redirect_uri' => 'https://app.example/callback',
            'response_type' => 'code',
            'code_challenge' => 'abc',
            'code_challenge_method' => 'S256',
            'state' => 'state-123',
        ], true, null);

        $this->assertFalse($result['ok']);
        $this->assertSame('Missing parameter: nonce', $result['description']);
    }

    public function testRejectsNonceReplayForOpenIdRequest(): void
    {
        $validator = new OAuthAuthorizationRequestValidator();
        $result = $validator->validate([
            'client_id' => 'client-a',
            'redirect_uri' => 'https://app.example/callback',
            'response_type' => 'code',
            'code_challenge' => 'abc',
            'code_challenge_method' => 'S256',
            'state' => 'state-123',
            'nonce' => 'nonce-12345',
        ], true, fn(string $nonce): bool => true);

        $this->assertFalse($result['ok']);
        $this->assertSame('Nonce replay detected', $result['description']);
    }

    public function testAcceptsValidAuthorizationRequest(): void
    {
        $validator = new OAuthAuthorizationRequestValidator();
        $result = $validator->validate([
            'client_id' => 'client-a',
            'redirect_uri' => 'https://app.example/callback',
            'response_type' => 'code',
            'code_challenge' => 'abc',
            'code_challenge_method' => 'S256',
            'state' => 'state-123',
            'nonce' => 'nonce-12345',
        ], true, fn(string $nonce): bool => false);

        $this->assertTrue($result['ok']);
        $this->assertNull($result['error']);
        $this->assertNull($result['description']);
    }
}
