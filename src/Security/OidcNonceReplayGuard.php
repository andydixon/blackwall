<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Database;
use PDO;

class OidcNonceReplayGuard
{
    private PDO $db;
    private TokenHasher $hasher;
    private int $ttlSeconds;

    public function __construct(?PDO $db = null, ?TokenHasher $hasher = null, ?int $ttlSeconds = null)
    {
        $this->db = $db ?? Database::getInstance();
        $this->hasher = $hasher ?? new TokenHasher();
        $this->ttlSeconds = $ttlSeconds ?? max(60, \BlackWall\Config::getInt('OIDC_NONCE_REPLAY_TTL_SECONDS', 900));
    }

    public function isReplayAndRemember(string $clientId, string $nonce): bool
    {
        $key = $this->nonceKey($clientId, $nonce);
        $existing = $this->loadExpiry($key);
        $now = new \DateTimeImmutable();

        if ($existing !== null) {
            try {
                $expiresAt = new \DateTimeImmutable($existing);
                if ($expiresAt >= $now) {
                    return true;
                }
            } catch (\Throwable $e) {
                return true;
            }
        }

        $newExpiry = $now->modify("+{$this->ttlSeconds} seconds")->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            "INSERT INTO system_config (config_key, config_value)
             VALUES (?, ?)
             ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)"
        );
        $stmt->execute([$key, $newExpiry]);

        return false;
    }

    private function nonceKey(string $clientId, string $nonce): string
    {
        return 'oidc_nonce_' . $this->hasher->hash($clientId . '|' . $nonce);
    }

    private function loadExpiry(string $key): ?string
    {
        $stmt = $this->db->prepare('SELECT config_value FROM system_config WHERE config_key = ?');
        $stmt->execute([$key]);
        $row = $stmt->fetch();
        if (!$row || !isset($row['config_value'])) {
            return null;
        }

        return (string) $row['config_value'];
    }
}
