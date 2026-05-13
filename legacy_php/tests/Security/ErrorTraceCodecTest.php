<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\ErrorTraceCodec;
use PHPUnit\Framework\TestCase;

class ErrorTraceCodecTest extends TestCase
{
    private string $testKeyB64 = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';

    protected function setUp(): void
    {
        putenv('ERROR_TRACE_KEY=' . $this->testKeyB64);
    }

    public function testEncodeDecodeRoundTripWithCompression(): void
    {
        $trace = "RuntimeException: Example\n#0 /srv/app/src/Foo.php(10): call()\n#1 {main}";

        $encoded = ErrorTraceCodec::encode($trace);
        $decoded = ErrorTraceCodec::decode($encoded);

        $this->assertSame($trace, $decoded);
    }

    public function testDecodeSupportsLegacyV1Payload(): void
    {
        $plaintext = "Legacy stack trace\nline two";
        $key = base64_decode($this->testKeyB64, true);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        $this->assertNotFalse($ciphertext);

        $payload = base64_encode((string) json_encode([
            'v' => 1,
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ct' => base64_encode((string) $ciphertext),
        ]));

        $decoded = ErrorTraceCodec::decode($payload);
        $this->assertSame($plaintext, $decoded);
    }
}
