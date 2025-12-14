<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\PKCEValidator;
use PHPUnit\Framework\TestCase;

class PKCEValidatorTest extends TestCase
{
    public function testAcceptsValidS256Challenge(): void
    {
        $validator = new PKCEValidator();
        $verifier = str_repeat('a', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $this->assertTrue($validator->validateChallenge($verifier, $challenge, 'S256'));
    }

    public function testRejectsPlainMethod(): void
    {
        $validator = new PKCEValidator();
        $verifier = str_repeat('a', 43);

        $this->assertFalse($validator->validateChallenge($verifier, $verifier, 'plain'));
        $this->assertSame('', $validator->generateChallenge($verifier, 'plain'));
    }
}
