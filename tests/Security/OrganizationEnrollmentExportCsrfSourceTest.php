<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OrganizationEnrollmentExportCsrfSourceTest extends TestCase
{
    public function testEnrollmentUrlExportRequiresPostRouteAndCsrfToken(): void
    {
        $routes = file_get_contents(dirname(__DIR__, 2) . '/config/routes.php');
        $controller = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');

        $this->assertIsString($routes);
        $this->assertIsString($controller);

        $this->assertStringContainsString("\$group->post('/organisations/{organizationUuid}/enrollment-urls/export'", $routes);
        $this->assertStringContainsString("if (!CSRFProtection::validateToken(\$body['csrf_token'] ?? '')) {", $controller);
        $this->assertStringContainsString("/admin/organisations/' . \$organization->uuid . '?error=csrf", $controller);
    }
}
