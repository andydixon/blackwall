<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Controller\OAuthController;
use BlackWall\Model\OAuthClient;
use BlackWall\Model\Project;
use BlackWall\Repository\OAuthClientRepository;
use BlackWall\Repository\ProjectRepository;
use BlackWall\Security\OAuthAuthorizationRequestValidator;
use BlackWall\Security\OidcNonceReplayGuard;
use BlackWall\Security\RateLimiter;
use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

class OAuthAuthorizeScopeEnforcementBehaviorTest extends TestCase
{
    public function testAuthorizeRejectsScopeNotAllowedForClient(): void
    {
        $controller = $this->makeControllerForScopeTest();

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://provider.example/oauth/authorize')
            ->withQueryParams([
                'client_id' => 'client-public',
                'redirect_uri' => 'https://rp.example/callback',
                'response_type' => 'code',
                'code_challenge' => str_repeat('a', 43),
                'code_challenge_method' => 'S256',
                'state' => 'state-123',
                'scope' => 'profile offline_access',
            ])
            ->withAttribute('audit_logger', new class {
                public function logFail(string $eventType, array $context = []): void
                {
                }

                public function logInfo(string $eventType, array $context = []): void
                {
                }

                public function logSuccess(string $eventType, array $context = []): void
                {
                }
            });

        $response = (new ResponseFactory())->createResponse();
        $result = $controller->authorize($request, $response);

        $this->assertSame(302, $result->getStatusCode());
        $location = $result->getHeaderLine('Location');
        $this->assertStringContainsString('https://rp.example/callback?', $location);
        $this->assertStringContainsString('error=invalid_scope', $location);
        $this->assertStringContainsString('state=state-123', $location);
    }

    private function makeControllerForScopeTest(): OAuthController
    {
        $reflection = new \ReflectionClass(OAuthController::class);
        /** @var OAuthController $controller */
        $controller = $reflection->newInstanceWithoutConstructor();

        $client = new OAuthClient(
            id: 7,
            clientId: 'client-public',
            clientSecretHash: null,
            projectId: 5,
            name: 'Scope Test Client',
            redirectUris: ['https://rp.example/callback'],
            grants: ['authorization_code', 'refresh_token'],
            scopes: ['profile'],
            pkceRequired: true,
            accessTokenType: 'jwt',
            accessTokenLifetime: 3600,
            refreshTokenLifetime: 2592000,
            oidcEnabled: true,
            status: 'active',
            createdAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            updatedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00')
        );

        $project = new Project(
            id: 5,
            organizationId: 2,
            uuid: 'project-uuid-1',
            name: 'Project One',
            ownerUserId: null,
            status: 'active',
            createdAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            updatedAt: new \DateTimeImmutable('2026-01-01T00:00:00+00:00')
        );

        $clientRepo = new class ($client) extends OAuthClientRepository {
            public function __construct(private readonly OAuthClient $client)
            {
            }

            public function findByClientId(string $clientId): ?OAuthClient
            {
                return $clientId === $this->client->clientId ? $this->client : null;
            }
        };

        $projectRepo = new class ($project) extends ProjectRepository {
            public function __construct(private readonly Project $project)
            {
            }

            public function findById(int $id): ?Project
            {
                return $id === $this->project->id ? $this->project : null;
            }
        };

        $rateLimiter = new class extends RateLimiter {
            public function __construct()
            {
            }

            public function check(string $identifier, string $action, int $maxAttempts, int $windowSeconds): bool
            {
                return true;
            }
        };

        $nonceGuard = (new \ReflectionClass(OidcNonceReplayGuard::class))->newInstanceWithoutConstructor();

        $this->setPrivateProperty($controller, 'clientRepo', $clientRepo);
        $this->setPrivateProperty($controller, 'projectRepo', $projectRepo);
        $this->setPrivateProperty($controller, 'rateLimiter', $rateLimiter);
        $this->setPrivateProperty($controller, 'authRequestValidator', new OAuthAuthorizationRequestValidator());
        $this->setPrivateProperty($controller, 'nonceReplayGuard', $nonceGuard);

        return $controller;
    }

    private function setPrivateProperty(object $target, string $name, mixed $value): void
    {
        $property = new \ReflectionProperty($target, $name);
        $property->setAccessible(true);
        $property->setValue($target, $value);
    }
}
