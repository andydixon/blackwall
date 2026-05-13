<?php

declare(strict_types=1);

namespace Tests\Template;

use PHPUnit\Framework\TestCase;

class AdminLayoutCsrfHelperTest extends TestCase
{
    public function testAdminLayoutUsesValidCsrfHelper(): void
    {
        $template = file_get_contents(dirname(__DIR__, 2) . '/templates/_layout.php');
        $this->assertIsString($template);
        $this->assertStringNotContainsString('CSRFProtection::token()', $template);
        $this->assertStringContainsString('CSRFProtection::getToken()', $template);
    }
}
