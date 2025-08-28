<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Database;
use PDO;

class RateLimiter
{
    private PDO $db;
    private bool $enabled;

    public function __construct()
    {
        $this->db = Database::getInstance();
        $this->enabled = \BlackWall\Config::getBool('RATE_LIMIT_ENABLED', true);
    }

    public function check(string $identifier, string $action, int $maxAttempts, int $windowSeconds): bool
    {
        if (!$this->enabled) {
            return true;
        }

        $this->cleanup();

        $stmt = $this->db->prepare(
            'SELECT attempts, blocked_until FROM rate_limits 
            WHERE identifier = ? AND action = ? AND window_start >= ?'
        );
        
        $windowStart = (new \DateTimeImmutable())->modify("-{$windowSeconds} seconds");
        $stmt->execute([$identifier, $action, $windowStart->format('Y-m-d H:i:s')]);
        $row = $stmt->fetch();

        if ($row && $row['blocked_until']) {
            $blockedUntil = new \DateTimeImmutable($row['blocked_until']);
            if ($blockedUntil > new \DateTimeImmutable()) {
                return false;
            }
        }

        if ($row && (int) $row['attempts'] >= $maxAttempts) {
            $this->block($identifier, $action, $windowSeconds * 2);
            return false;
        }

        $this->increment($identifier, $action, $windowSeconds);
        return true;
    }

    private function increment(string $identifier, string $action, int $windowSeconds): void
    {
        $windowStart = (new \DateTimeImmutable())->modify("-{$windowSeconds} seconds");
        
        $stmt = $this->db->prepare(
            'INSERT INTO rate_limits (identifier, action, attempts, window_start) 
            VALUES (?, ?, 1, NOW())
            ON DUPLICATE KEY UPDATE attempts = attempts + 1'
        );
        
        $stmt->execute([$identifier, $action]);
    }

    private function block(string $identifier, string $action, int $blockSeconds): void
    {
        $blockedUntil = (new \DateTimeImmutable())->modify("+{$blockSeconds} seconds");
        
        $stmt = $this->db->prepare(
            'UPDATE rate_limits SET blocked_until = ? WHERE identifier = ? AND action = ?'
        );
        
        $stmt->execute([$blockedUntil->format('Y-m-d H:i:s'), $identifier, $action]);
    }

    private function cleanup(): void
    {
        if (rand(1, 100) > 5) {
            return;
        }

        $stmt = $this->db->prepare(
            'DELETE FROM rate_limits WHERE window_start < ? AND (blocked_until IS NULL OR blocked_until < ?)'
        );
        
        $cutoff = (new \DateTimeImmutable())->modify('-1 hour');
        $stmt->execute([$cutoff->format('Y-m-d H:i:s'), $cutoff->format('Y-m-d H:i:s')]);
    }

    public function reset(string $identifier, string $action): void
    {
        $stmt = $this->db->prepare('DELETE FROM rate_limits WHERE identifier = ? AND action = ?');
        $stmt->execute([$identifier, $action]);
    }
}
