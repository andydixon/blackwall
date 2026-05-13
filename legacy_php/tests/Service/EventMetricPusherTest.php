<?php

declare(strict_types=1);

namespace Tests\Service;

use BlackWall\Service\EventMetricPusher;
use PHPUnit\Framework\TestCase;

class EventMetricPusherTest extends TestCase
{
    public function testBuildPrometheusLineIncludesEventNameAndValueOne(): void
    {
        $line = EventMetricPusher::buildPrometheusLine('blackwall_event', [
            'event_name' => 'admin.login.success',
            'outcome' => 'success',
        ]);

        $this->assertSame(
            "blackwall_event{event_name=\"admin.login.success\",outcome=\"success\"} 1\n",
            $line
        );
    }

    public function testBuildPrometheusLineEscapesLabelValues(): void
    {
        $line = EventMetricPusher::buildPrometheusLine('blackwall_event', [
            'event_name' => "line\\name\"quoted\nnext",
            'bad-label' => 'ignored',
        ]);

        $this->assertStringContainsString('event_name="', $line);
        $this->assertStringContainsString('line\\\\name', $line);
        $this->assertStringContainsString('\\"quoted', $line);
        $this->assertStringContainsString('\\nnext', $line);
        $this->assertStringNotContainsString('bad-label', $line);
    }
}
