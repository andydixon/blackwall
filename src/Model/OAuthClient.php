<?php

declare(strict_types=1);

namespace BlackWall\Model;

class OAuthClient
{
    public function __construct(
        public readonly int $id,
        public readonly string $clientId,
        public readonly ?string $clientSecretHash,
        public readonly int $projectId,
        public readonly string $name,
        public readonly array $redirectUris,
        public readonly array $grants,
        public readonly array $scopes,
        public readonly bool $pkceRequired,
        public readonly string $accessTokenType,
        public readonly int $accessTokenLifetime,
        public readonly int $refreshTokenLifetime,
        public readonly bool $oidcEnabled,
        public readonly string $status,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    public function isConfidential(): bool
    {
        return $this->clientSecretHash !== null;
    }

    public function hasRedirectUri(string $uri): bool
    {
        // Normalize URIs to avoid trivial mismatches (e.g., trailing slash)
        $normalize = function (string $u): string {
            return rtrim($u, '/');
        };
        $needle = $normalize($uri);
        foreach ($this->redirectUris as $allowed) {
            if ($needle === $normalize($allowed)) {
                return true;
            }
        }
        return false;
    }

    public function supportsGrant(string $grant): bool
    {
        return in_array($grant, $this->grants, true);
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
