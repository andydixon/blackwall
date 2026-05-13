<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Model\OAuthClient;
use BlackWall\Security\OAuthClientAuthenticator;
use BlackWall\Security\TokenHasher;
use PHPUnit\Framework\TestCase;

class OAuthClientAuthenticatorTest extends TestCase
{
    public function testConfidentialClientRequiresSecret(): void
    {
        $hasher = new TokenHasher();
        $client = $this->makeClient('confidential-client', $hasher->hash('expected-secret'));
        $authenticator = new OAuthClientAuthenticator($hasher);

        $result = $authenticator->authenticate('', ['client_id' => 'confidential-client'], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('invalid_client', $result['error']);
    }

    public function testConfidentialClientAcceptsValidBasicCredentials(): void
    {
        $hasher = new TokenHasher();
        $client = $this->makeClient('confidential-client', $hasher->hash('expected-secret'));
        $authenticator = new OAuthClientAuthenticator($hasher);
        $header = 'Basic ' . base64_encode('confidential-client:expected-secret');

        $result = $authenticator->authenticate($header, [], fn(string $id) => $client);

        $this->assertTrue($result['ok']);
        $this->assertInstanceOf(OAuthClient::class, $result['client']);
        $this->assertSame('client_secret_basic', $result['auth_method']);
    }

    public function testConfidentialClientRejectsWrongSecret(): void
    {
        $hasher = new TokenHasher();
        $client = $this->makeClient('confidential-client', $hasher->hash('expected-secret'));
        $authenticator = new OAuthClientAuthenticator($hasher);
        $header = 'Basic ' . base64_encode('confidential-client:wrong-secret');

        $result = $authenticator->authenticate($header, [], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('invalid_client', $result['error']);
    }

    public function testPublicClientCanAuthenticateWithoutSecret(): void
    {
        $client = $this->makeClient('public-client', null);
        $authenticator = new OAuthClientAuthenticator(new TokenHasher());

        $result = $authenticator->authenticate('', ['client_id' => 'public-client'], fn(string $id) => $client);

        $this->assertTrue($result['ok']);
        $this->assertInstanceOf(OAuthClient::class, $result['client']);
        $this->assertSame('none', $result['auth_method']);
    }

    public function testMismatchedBasicAndBodyClientIdIsRejected(): void
    {
        $hasher = new TokenHasher();
        $client = $this->makeClient('confidential-client', $hasher->hash('expected-secret'));
        $authenticator = new OAuthClientAuthenticator($hasher);
        $header = 'Basic ' . base64_encode('confidential-client:expected-secret');

        $result = $authenticator->authenticate($header, ['client_id' => 'different-client'], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('invalid_client', $result['error']);
    }

    public function testConfidentialClientAcceptsClientSecretPost(): void
    {
        $hasher = new TokenHasher();
        $client = $this->makeClient('confidential-client', $hasher->hash('expected-secret'));
        $authenticator = new OAuthClientAuthenticator($hasher);

        $result = $authenticator->authenticate('', [
            'client_id' => 'confidential-client',
            'client_secret' => 'expected-secret',
        ], fn(string $id) => $client);

        $this->assertTrue($result['ok']);
        $this->assertSame('client_secret_post', $result['auth_method']);
    }

    public function testPublicClientRejectsBasicAuthentication(): void
    {
        $client = $this->makeClient('public-client', null);
        $authenticator = new OAuthClientAuthenticator(new TokenHasher());
        $header = 'Basic ' . base64_encode('public-client:');

        $result = $authenticator->authenticate($header, [], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('unauthorized_client', $result['error']);
    }

    public function testPublicClientRejectsClientSecretPost(): void
    {
        $client = $this->makeClient('public-client', null);
        $authenticator = new OAuthClientAuthenticator(new TokenHasher());

        $result = $authenticator->authenticate('', [
            'client_id' => 'public-client',
            'client_secret' => 'should-not-be-here',
        ], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('unauthorized_client', $result['error']);
    }

    public function testConfidentialClientRejectsMixedBasicAndBodySecretAuthentication(): void
    {
        $hasher = new TokenHasher();
        $client = $this->makeClient('confidential-client', $hasher->hash('expected-secret'));
        $authenticator = new OAuthClientAuthenticator($hasher);
        $header = 'Basic ' . base64_encode('confidential-client:expected-secret');

        $result = $authenticator->authenticate($header, [
            'client_id' => 'confidential-client',
            'client_secret' => 'expected-secret',
        ], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('invalid_client', $result['error']);
    }

    public function testPublicClientRejectsMixedBasicAndBodySecretAuthentication(): void
    {
        $client = $this->makeClient('public-client', null);
        $authenticator = new OAuthClientAuthenticator(new TokenHasher());
        $header = 'Basic ' . base64_encode('public-client:');

        $result = $authenticator->authenticate($header, [
            'client_id' => 'public-client',
            'client_secret' => 'unexpected',
        ], fn(string $id) => $client);

        $this->assertFalse($result['ok']);
        $this->assertSame('invalid_client', $result['error']);
    }

    private function makeClient(string $clientId, ?string $clientSecretHash): OAuthClient
    {
        return new OAuthClient(
            id: 1,
            clientId: $clientId,
            clientSecretHash: $clientSecretHash,
            projectId: 100,
            name: 'Test Client',
            redirectUris: ['https://example.test/callback'],
            grants: ['authorization_code', 'refresh_token'],
            scopes: ['openid'],
            pkceRequired: true,
            accessTokenType: 'jwt',
            accessTokenLifetime: 3600,
            refreshTokenLifetime: 2592000,
            oidcEnabled: true,
            status: 'active',
            createdAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            updatedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00')
        );
    }
}
