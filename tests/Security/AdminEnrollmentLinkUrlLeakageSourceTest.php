<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AdminEnrollmentLinkUrlLeakageSourceTest extends TestCase
{
    public function testEnrollmentLinksAreFlashedInSessionNotRedirectQueryStrings(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringNotContainsString('?enrollment_link=', $source);
        $this->assertStringContainsString('$this->setEnrollmentLinkFlash($organization->uuid, $enrollmentLink);', $source);
        $this->assertStringContainsString('$this->setEnrollmentLinkFlash($user->uuid, $enrollmentLink);', $source);
        $this->assertStringContainsString("'enrollmentLink' => \$this->consumeEnrollmentLinkFlash(\$organization->uuid)", $source);
        $this->assertStringContainsString('$enrollmentLink = $this->consumeEnrollmentLinkFlash($user->uuid);', $source);
    }
}
