<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class SourceHardeningRegressionTest extends TestCase
{
    public function testSessionManagerRegeneratesAndInvalidatesOldSessionId(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Security/SessionManager.php');
        $this->assertIsString($source);
        $this->assertStringContainsString('session_regenerate_id(true);', $source);
        $this->assertStringNotContainsString('session_regenerate_id(false);', $source);
    }
}
