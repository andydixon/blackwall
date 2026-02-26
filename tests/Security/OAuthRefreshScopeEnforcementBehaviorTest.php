<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\TokenHasher;
use BlackWall\Service\OAuthService;
use PDO;
use PDOStatement;
use PHPUnit\Framework\TestCase;

class OAuthRefreshScopeEnforcementBehaviorTest extends TestCase
{
    public function testRefreshExchangeRejectsTokenWhenClientScopesWereTightened(): void
    {
        $refreshToken = 'refresh-token-abc';
        $refreshTokenHash = (new TokenHasher())->hash($refreshToken);

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->with([$refreshTokenHash, 'client-public']);
        $stmt->expects($this->once())
            ->method('fetch')
            ->willReturn([
                'id' => 10,
                'client_id' => 7,
                'user_id' => 22,
                'project_id' => 33,
                'token_hash' => $refreshTokenHash,
                'scopes' => json_encode(['openid', 'offline_access']),
                'client_scopes' => json_encode(['openid']),
                'client_status' => 'active',
                'revoked_at' => null,
                'expires_at' => '2099-01-01 00:00:00',
            ]);

        $db = $this->createMock(PDO::class);
        $db->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);
        $db->expects($this->never())->method('beginTransaction');

        $service = (new \ReflectionClass(OAuthService::class))->newInstanceWithoutConstructor();
        $this->setPrivateProperty($service, 'db', $db);
        $this->setPrivateProperty($service, 'hasher', new TokenHasher());

        $result = $service->exchangeRefreshToken($refreshToken, 'client-public');
        $this->assertNull($result);
    }

    private function setPrivateProperty(object $target, string $name, mixed $value): void
    {
        $property = new \ReflectionProperty($target, $name);
        $property->setAccessible(true);
        $property->setValue($target, $value);
    }
}
