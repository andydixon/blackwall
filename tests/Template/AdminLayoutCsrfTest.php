<?php

declare(strict_types=1);

namespace Tests\Template;

use PHPUnit\Framework\TestCase;

class AdminLayoutCsrfTest extends TestCase
{
    public function testAdminLogoutFormIncludesCsrfToken(): void
    {
        $template = file_get_contents(dirname(__DIR__, 2) . '/templates/_layout.php');
        $this->assertIsString($template);

        $this->assertStringContainsString('action="/admin/logout"', $template);
        $this->assertStringContainsString('name="csrf_token"', $template);
        $this->assertStringContainsString('CSRFProtection::getToken()', $template);
    }
}
