<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class WebAuthnLoginUserVerificationPolicySourceTest extends TestCase
{
    public function testLoginFlowsRequireUserVerificationClientAndServerSide(): void
    {
        $admin = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $portal = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/PortalController.php');
        $oauthTemplate = file_get_contents(dirname(__DIR__, 2) . '/templates/oauth/login.php');
        $service = file_get_contents(dirname(__DIR__, 2) . '/src/Service/WebAuthnService.php');

        $this->assertIsString($admin);
        $this->assertIsString($portal);
        $this->assertIsString($oauthTemplate);
        $this->assertIsString($service);

        $this->assertStringContainsString("'userVerification' => 'required'", $admin);
        $this->assertStringContainsString("'userVerification' => 'required'", $portal);
        $this->assertStringContainsString("userVerification: 'required'", $oauthTemplate);
        $this->assertStringContainsString('hasUserVerificationFlag($authDataBinary)', $service);
    }
}
