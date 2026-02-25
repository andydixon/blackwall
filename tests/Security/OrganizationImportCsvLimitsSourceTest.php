<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OrganizationImportCsvLimitsSourceTest extends TestCase
{
    public function testOrganizationUserImportEnforcesCsvSizeAndRowLimits(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("Config::getInt('ADMIN_ORGANIZATION_IMPORT_MAX_BYTES', 1048576)", $source);
        $this->assertStringContainsString("?error=csv_too_large", $source);
        $this->assertStringContainsString("Config::getInt('ADMIN_ORGANIZATION_IMPORT_MAX_ROWS', 2000)", $source);
        $this->assertStringContainsString("?error=csv_too_many_rows", $source);
    }
}
