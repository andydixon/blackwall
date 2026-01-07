<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

class AssignmentPrivilegeLevelValidationSourceTest extends TestCase
{
    public function testAssignmentMutationsRequireProjectPrivilegeLevelExistence(): void
    {
        $source = file_get_contents(dirname(__DIR__, 2) . '/src/Controller/AdminController.php');
        $this->assertIsString($source);

        $this->assertStringContainsString('findByProjectAndLevel($project->id, $privilegeLevel) === null', $source);
        $this->assertStringContainsString('findByProjectAndLevel($assignment->projectId, $privilegeLevel) === null', $source);
        $this->assertStringContainsString('findByProjectAndLevel($project->id, $privilegeLevel) === null', $source);
        $this->assertStringContainsString('findByProjectAndLevel($assignment->projectId, $requestedLevel) === null', $source);
    }
}
