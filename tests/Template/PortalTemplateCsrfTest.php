<?php

declare(strict_types=1);

namespace Tests\Template;

use PHPUnit\Framework\TestCase;

class PortalTemplateCsrfTest extends TestCase
{
    public function testDashboardIncludesCsrfForPortalMutations(): void
    {
        $template = file_get_contents(dirname(__DIR__, 2) . '/templates/portal/dashboard.php');
        $this->assertIsString($template);

        $this->assertStringContainsString('action="/portal/logout"', $template);
        $this->assertStringContainsString('name="csrf_token"', $template);
        $this->assertStringContainsString('/portal/keys/', $template);
        $this->assertStringContainsString('body: JSON.stringify({ csrf_token: csrfToken })', $template);
        $this->assertStringContainsString('csrf_token: csrfToken', $template);
    }
}
