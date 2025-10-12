<?php

declare(strict_types=1);

namespace Tests\Security;

use BlackWall\Security\AuditExportSigner;
use PHPUnit\Framework\TestCase;

class AuditExportSignerTest extends TestCase
{
    public function testSha256IsStable(): void
    {
        $payload = "a,b,c\n1,2,3\n";
        $hash = AuditExportSigner::sha256($payload);

        $this->assertSame(hash('sha256', $payload), $hash);
    }
}

