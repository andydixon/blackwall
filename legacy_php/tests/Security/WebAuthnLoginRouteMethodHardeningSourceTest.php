<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginRouteMethodHardeningSourceTest extends TestCase
{
    public function testLoginChallengeAndVerifyRoutesArePostOnly(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/config/routes.php');
        $this->assertIsString($source);

        $this->assertStringNotContainsString("get('/portal/login/challenge'", $source);
        $this->assertStringNotContainsString("get('/portal/login/verify'", $source);
        $this->assertStringNotContainsString("get('/login/challenge'", $source);
        $this->assertStringContainsString("post('/portal/login/challenge'", $source);
        $this->assertStringContainsString("post('/portal/login/verify'", $source);
        $this->assertStringContainsString("post('/login/challenge'", $source);
        $this->assertStringContainsString("post('/login/verify'", $source);
    }
}
