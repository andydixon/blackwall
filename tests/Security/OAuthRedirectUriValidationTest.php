<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Model\OAuthClient;
use PHPUnit\Framework\TestCase;

class OAuthRedirectUriValidationTest extends TestCase
{
    public function testRedirectUriRequiresExactStringMatch(): void
    {
        $client = $this->makeClient(['https://example.test/callback']);

        $this->assertTrue($client->hasRedirectUri('https://example.test/callback'));
        $this->assertFalse($client->hasRedirectUri('https://example.test/callback/'));
        $this->assertFalse($client->hasRedirectUri('https://example.test/callback?x=1'));
    }

    private function makeClient(array $redirectUris): OAuthClient
    {
        return new OAuthClient(
            id: 1,
            clientId: 'client-a',
            clientSecretHash: null,
            projectId: 1,
            name: 'Client',
            redirectUris: $redirectUris,
            grants: ['authorization_code'],
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
