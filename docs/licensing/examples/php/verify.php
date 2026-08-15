<?php

declare(strict_types=1);

// Usage: php verify.php <licence-file> <hostname> <project-uuid>
// Requires PHP 8.1+ with cURL. The fixed URL preserves the issuer trust anchor.

const VERIFY_URL = 'https://blackwall.cx/licences/v1/verify';
const EXPECTED_ISSUER = 'https://blackwall.cx';
const MAX_LICENCE_BYTES = 16384;
const MAX_RESPONSE_BYTES = 65536;

if ($argc !== 4) {
    fwrite(STDERR, "usage: php verify.php <licence-file> <hostname> <project-uuid>\n");
    exit(2);
}

[$script, $licencePath, $hostname, $projectUuid] = $argv;
$licence = trim((string) file_get_contents($licencePath));
if ($licence === '' || strlen($licence) > MAX_LICENCE_BYTES) {
    fail('licence file is empty or too large');
}

$requestBody = json_encode([
    'licence' => $licence,
    'expected_hostname' => normaliseHostname($hostname),
    'project_uuid' => strtolower($projectUuid),
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

$responseBody = '';
$curl = curl_init(VERIFY_URL);
curl_setopt_array($curl, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $requestBody,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
    CURLOPT_RETURNTRANSFER => false,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
    CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$responseBody): int {
        if (strlen($responseBody) + strlen($chunk) > MAX_RESPONSE_BYTES) {
            return 0;
        }
        $responseBody .= $chunk;
        return strlen($chunk);
    },
]);

if (!curl_exec($curl)) {
    fail('verification request failed: ' . curl_error($curl));
}
$status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
curl_close($curl);
if ($status !== 200) {
    fail("verification service returned HTTP {$status}");
}

try {
    $result = json_decode($responseBody, true, 32, JSON_THROW_ON_ERROR);
} catch (JsonException $exception) {
    fail('verification service returned invalid JSON');
}
if (!is_array($result) || ($result['valid'] ?? null) !== true || ($result['code'] ?? null) !== 'valid') {
    fail('licence rejected: ' . (string) ($result['code'] ?? 'invalid_response'));
}

$claims = $result['claims'] ?? null;
$checkedAt = strtotime((string) ($result['checked_at'] ?? ''));
if (!is_array($claims) || $checkedAt === false || abs(time() - $checkedAt) > 300) {
    fail('verification response is incomplete or stale');
}
if (($claims['v'] ?? null) !== 1
    || ($claims['iss'] ?? null) !== EXPECTED_ISSUER
    || ($claims['aud'] ?? null) !== 'blackwall-licence'
    || ($claims['project_uuid'] ?? null) !== strtolower($projectUuid)
    || !in_array(normaliseHostname($hostname), $claims['hostnames'] ?? [], true)
    || !is_int($claims['nbf'] ?? null)
    || !is_int($claims['exp'] ?? null)
    || time() + 120 < $claims['nbf']
    || time() - 120 > $claims['exp']) {
    fail('verified response did not match the local policy');
}

fwrite(STDOUT, "valid licence " . $claims['licence_id'] . "\n");

function normaliseHostname(string $raw): string
{
    $host = strtolower(rtrim(trim($raw), '.'));
    if ($host === '' || strlen($host) > 253 || preg_match('/[^a-z0-9.:-]/D', $host) === 1) {
        fail('invalid hostname');
    }
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return $host;
    }
    if (str_contains($host, ':')) {
        fail('ports are not allowed in hostnames');
    }
    foreach (explode('.', $host) as $label) {
        if ($label === '' || strlen($label) > 63 || $label[0] === '-' || str_ends_with($label, '-')) {
            fail('invalid DNS hostname');
        }
    }
    return $host;
}

function fail(string $message): never
{
    fwrite(STDERR, "invalid: {$message}\n");
    exit(1);
}
