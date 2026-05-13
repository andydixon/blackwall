<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class EnrollmentTokenInputValidationSourceTest extends TestCase
{
    public function testBootstrapControllerValidatesTokenFormatAndUsesPreparedDelete(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/BootstrapController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("preg_match('/^[a-f0-9]{64}$/', \$token)", $source);
        $this->assertStringContainsString("DELETE FROM system_config WHERE config_key IN (?, ?)", $source);
    }
}
