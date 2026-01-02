<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class OAuthAuthorizePostMembershipEnforcementSourceTest extends TestCase
{
    public function testAuthorizePostRevalidatesClientProjectAndMembershipBeforeIssuingCode(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/OAuthController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('Malformed authorization request', $source);
        $this->assertStringContainsString('Invalid or inactive OAuth client', $source);
        $this->assertStringContainsString('Client project invalid', $source);
        $this->assertStringContainsString('User not assigned to project at consent submission', $source);

        $roleCheckPos = strpos($source, 'findByUserAndProject((int) $userId, $project->id)');
        $codeIssuePos = strpos($source, 'createAuthorizationCode([');
        $this->assertNotFalse($roleCheckPos);
        $this->assertNotFalse($codeIssuePos);
        $this->assertLessThan($codeIssuePos, $roleCheckPos);
    }
}
