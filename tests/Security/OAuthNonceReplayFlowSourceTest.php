<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthNonceReplayFlowSourceTest extends TestCase
{
    public function testAuthorizeValidatesNonceWithoutConsumingAndAuthorizePostConsumesIt(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString(
            "\$validation = \$this->authRequestValidator->validate(\n            \$params,\n            \$isOidcRequest,\n            null\n        );",
            $source
        );
        $this->assertStringContainsString("if (in_array('openid', \$requestedScopes, true)) {", $source);
        $this->assertStringContainsString(
            "\$this->nonceReplayGuard->isReplayAndRemember(\$client->clientId, \$nonce)",
            $source
        );
    }
}
