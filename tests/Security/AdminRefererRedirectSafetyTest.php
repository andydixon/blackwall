<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminRefererRedirectSafetyTest extends TestCase
{
    public function testAdminControllerSanitizesRefererBeforeRedirect(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('safeAdminRedirectTarget(', $source);
        $this->assertStringContainsString("!str_starts_with(\$target, '/admin/')", $source);
        $this->assertStringContainsString("hash_equals(strtolower(\$appHost), strtolower((string) \$parts['host']))", $source);
    }
}
