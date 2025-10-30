<?php

declare(strict_types=1);

namespace BlackWall\Service;

use BlackWall\Config;

class EventMetricPusher
{
    public function pushEvent(string $eventType, string $outcome): void
    {
        if (!Config::getBool('EVENT_METRICS_PUSH_ENABLED', false)) {
            return;
        }

        $url = trim((string) Config::get('EVENT_METRICS_PUSH_URL', ''));
        if ($url === '') {
            return;
        }

        $metricName = trim((string) Config::get('EVENT_METRICS_PUSH_METRIC_NAME', 'blackwall_event'));
        $metricName = self::sanitiseMetricName($metricName);
        if ($metricName === '') {
            $metricName = 'blackwall_event';
        }

        $labels = self::parseStaticLabels((string) Config::get('EVENT_METRICS_PUSH_STATIC_LABELS', ''));
        $labels['event_name'] = $eventType;
        if (Config::getBool('EVENT_METRICS_PUSH_INCLUDE_OUTCOME', true)) {
            $labels['outcome'] = $outcome;
        }

        $payload = self::buildPrometheusLine($metricName, $labels);
        $timeoutMs = max(50, Config::getInt('EVENT_METRICS_PUSH_TIMEOUT_MS', 250));

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: text/plain; version=0.0.4\r\n",
                'content' => $payload,
                'timeout' => $timeoutMs / 1000,
                'ignore_errors' => true,
            ],
        ]);

        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            error_log('EventMetricPusher: failed to push event metric to vmagent');
        }
    }

    public static function buildPrometheusLine(string $metricName, array $labels): string
    {
        $pairs = [];
        foreach ($labels as $key => $value) {
            $labelName = self::sanitiseLabelName((string) $key);
            if ($labelName === '') {
                continue;
            }
            $pairs[] = $labelName . '="' . self::escapeLabelValue((string) $value) . '"';
        }

        $labelSet = !empty($pairs) ? '{' . implode(',', $pairs) . '}' : '';
        return $metricName . $labelSet . " 1\n";
    }

    private static function parseStaticLabels(string $raw): array
    {
        $labels = [];
        foreach (array_filter(array_map('trim', explode(',', $raw))) as $entry) {
            $parts = explode('=', $entry, 2);
            if (count($parts) !== 2) {
                continue;
            }
            $key = self::sanitiseLabelName(trim($parts[0]));
            $value = trim($parts[1]);
            if ($key === '') {
                continue;
            }
            $labels[$key] = $value;
        }
        return $labels;
    }

    private static function sanitiseMetricName(string $name): string
    {
        $name = preg_replace('/[^a-zA-Z0-9_:]/', '_', $name) ?? '';
        if ($name === '' || !preg_match('/^[a-zA-Z_:]/', $name)) {
            return '';
        }
        return $name;
    }

    private static function sanitiseLabelName(string $name): string
    {
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $name)) {
            return '';
        }
        return $name;
    }

    private static function escapeLabelValue(string $value): string
    {
        return str_replace(
            ["\\", "\"", "\n", "\r"],
            ["\\\\", "\\\"", "\\n", "\\r"],
            $value
        );
    }
}
