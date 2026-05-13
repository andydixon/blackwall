<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminCsvExportFormulaInjectionSourceTest extends TestCase
{
    public function testAdminCsvExportsSanitizeFormulaLikeCells(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('private function sanitizeCsvCell(string $value): string', $source);
        $this->assertStringContainsString("preg_match('/^[=\\+\\-@]/', \$value) === 1", $source);
        $this->assertStringContainsString("\$this->sanitizeCsvCell((string) (\$row['message'] ?? ''))", $source);
        $this->assertStringContainsString("\$this->sanitizeCsvCell((string) (\$row['display_label'] ?? ''))", $source);
        $this->assertStringContainsString("\$this->sanitizeCsvCell((string) (\$user->displayLabel ?? ''))", $source);
    }
}
