<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\OAuthRedirectUriPolicy;
use PHPUnit\Framework\TestCase;

class OAuthRedirectUriPolicyTest extends TestCase
{
    public function testAllowsHttpsAndLocalhostHttpRedirectUris(): void
    {
        $this->assertTrue(OAuthRedirectUriPolicy::isAllowed('https://app.example/callback'));
        $this->assertTrue(OAuthRedirectUriPolicy::isAllowed('http://localhost/callback'));
        $this->assertTrue(OAuthRedirectUriPolicy::isAllowed('http://127.0.0.1:8080/callback'));
        $this->assertTrue(OAuthRedirectUriPolicy::isAllowed('http://[::1]/callback'));
    }

    public function testRejectsInsecureOrMalformedRedirectUris(): void
    {
        $this->assertFalse(OAuthRedirectUriPolicy::isAllowed('http://app.example/callback'));
        $this->assertFalse(OAuthRedirectUriPolicy::isAllowed('javascript:alert(1)'));
        $this->assertFalse(OAuthRedirectUriPolicy::isAllowed('https://user:pass@app.example/callback'));
        $this->assertFalse(OAuthRedirectUriPolicy::isAllowed('https://app.example/callback#frag'));
        $this->assertFalse(OAuthRedirectUriPolicy::isAllowed('https://*.example/callback'));
    }

    public function testAllAllowedRequiresNonEmptyAndAllValid(): void
    {
        $this->assertFalse(OAuthRedirectUriPolicy::allAllowed([]));
        $this->assertTrue(OAuthRedirectUriPolicy::allAllowed([
            'https://app.example/callback',
            'http://localhost/callback',
        ]));
        $this->assertFalse(OAuthRedirectUriPolicy::allAllowed([
            'https://app.example/callback',
            'http://evil.example/callback',
        ]));
    }
}
