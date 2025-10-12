<?php

declare(strict_types=1);

namespace Tests\Template;

use PHPUnit\Framework\TestCase;

class AssignmentsTemplateCsrfTest extends TestCase
{
    public function testAssignmentsTemplateIncludesCsrfTokenInCreateAndDeleteForms(): void
    {
        $template = file_get_contents(__DIR__ . '/../../templates/admin/projects/assignments.php');
        $this->assertNotFalse($template);

        $occurrences = substr_count((string) $template, 'name="csrf_token"');
        $this->assertGreaterThanOrEqual(
            2,
            $occurrences,
            'Expected CSRF token fields in assignment create and delete forms.'
        );
    }
}

