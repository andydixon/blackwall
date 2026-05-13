<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthAuthorizationCodeConsumptionTest extends TestCase
{
    public function testAuthorizationCodeConsumptionIsAtomicInSource(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Service/OAuthService.php');
        $this->assertIsString($source);

        $this->assertStringContainsString(
            'UPDATE oauth_auth_codes SET used_at = NOW() WHERE id = ? AND used_at IS NULL',
            $source
        );
        $this->assertStringContainsString('if ($updateStmt->rowCount() !== 1)', $source);
    }
}
