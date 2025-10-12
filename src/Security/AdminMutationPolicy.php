<?php

declare(strict_types=1);

namespace BlackWall\Security;

class AdminMutationPolicy
{
    public static function shouldRequireProjectSettingsApproval(
        bool $canApplyDirectly,
        string $currentName,
        string $currentStatus,
        string $newName,
        string $newStatus
    ): bool {
        if ($canApplyDirectly) {
            return false;
        }

        return trim($currentName) !== trim($newName) || $currentStatus !== $newStatus;
    }

    public static function shouldRequireClientSettingsApproval(
        bool $canApplyDirectly,
        array $current,
        array $requested
    ): bool {
        if ($canApplyDirectly) {
            return false;
        }

        return self::normalizeClientSettings($current) !== self::normalizeClientSettings($requested);
    }

    public static function shouldRequireAssignmentApproval(bool $canApplyDirectly): bool
    {
        return !$canApplyDirectly;
    }

    private static function normalizeClientSettings(array $settings): array
    {
        $redirectUris = array_values(array_filter(array_map(
            static fn($v) => trim((string) $v),
            $settings['redirect_uris'] ?? []
        )));
        sort($redirectUris);

        $scopes = array_values(array_filter(array_map(
            static fn($v) => trim((string) $v),
            $settings['scopes'] ?? []
        )));
        sort($scopes);

        return [
            'name' => trim((string) ($settings['name'] ?? '')),
            'status' => (string) ($settings['status'] ?? ''),
            'redirect_uris' => $redirectUris,
            'scopes' => $scopes,
            'access_token_type' => (string) ($settings['access_token_type'] ?? ''),
            'access_token_lifetime' => (int) ($settings['access_token_lifetime'] ?? 0),
            'refresh_token_lifetime' => (int) ($settings['refresh_token_lifetime'] ?? 0),
            'oidc_enabled' => (int) (($settings['oidc_enabled'] ?? 0) ? 1 : 0),
        ];
    }
}

