<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class SessionDestroyCookieClearSourceTest extends TestCase
{
    public function testDestroyClearsSessionCookie(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Security/SessionManager.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("if (ini_get('session.use_cookies')) {", $source);
        $this->assertStringContainsString('session_get_cookie_params()', $source);
        $this->assertStringContainsString('setcookie(', $source);
        $this->assertStringContainsString("'expires' => time() - 42000", $source);
    }
}
