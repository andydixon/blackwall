<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class CryptbinUnwrapKeyVerificationSourceTest extends TestCase
{
    public function testUnwrapRequiresKeyVerifierMatchBeforeWebauthnAssertion(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/CryptbinController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('$keyB64 = (string) ($body[\'key_b64url\'] ?? \'\')', $source);
        $this->assertStringContainsString("cryptbin.unwrap.fail', ['target_type' => 'cryptbin', 'target_id' => \$id, 'failure_reason' => 'Invalid key']", $source);
        $this->assertStringContainsString("return \$this->json(\$response, ['error' => 'Forbidden'], 403);", $source);
    }
}
