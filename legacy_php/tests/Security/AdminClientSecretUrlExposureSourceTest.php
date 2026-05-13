<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminClientSecretUrlExposureSourceTest extends TestCase
{
    public function testClientSecretIsNotTransportedInRedirectQueryString(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("SessionManager::set('oauth_client_secret_flash_' . \$clientId, \$clientSecret);", $source);
        $this->assertStringContainsString("SessionManager::get(\$secretFlashKey);", $source);
        $this->assertStringContainsString("SessionManager::remove(\$secretFlashKey);", $source);
        $this->assertStringNotContainsString("?secret=", $source);
    }
}
