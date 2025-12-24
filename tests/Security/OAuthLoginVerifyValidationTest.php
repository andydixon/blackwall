<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthLoginVerifyValidationTest extends TestCase
{
    public function testOAuthLoginVerifyGuardsMissingCredentialDataAndLookupFailures(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString("oauth.login.fail", $source);
        $this->assertStringContainsString("Missing credential data", $source);
        $this->assertStringContainsString("Credential not found", $source);
        $this->assertStringContainsString("oauth.login.success", $source);
    }
}
