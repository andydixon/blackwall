<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class CryptbinCredentialBindingSourceTest extends TestCase
{
    public function testCryptbinOperationsEnforceBoundWebauthnCredentialForNewItems(): void
    {
        $controller = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/CryptbinController.php');
        $clientJs = file_get_contents(dirname(__DIR__, 2) . '/public_html/assets/js/cryptbin.js');
        $this->assertIsString($controller);
        $this->assertIsString($clientJs);

        $this->assertStringContainsString("'webauthn_credential_id' => \$authResult['credential_db_id']", $controller);
        $this->assertStringContainsString("'webauthn_credential_public_id' => \$authResult['credential_id']", $controller);
        $this->assertStringContainsString('if (!$this->verifyBoundCredential($meta, $authResult)) {', $controller);
        $this->assertStringContainsString('private function verifyBoundCredential(array $metadata, array $authResult): bool', $controller);
        $this->assertStringContainsString('webauthn_credential_id: wrapped.webauthn_credential_id', $clientJs);
        $this->assertStringContainsString('webauthn_credential_public_id: wrapped.webauthn_credential_public_id', $clientJs);
    }
}
