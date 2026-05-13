<?php

declare(strict_types=1);

namespace BlackWall\Middleware;

use BlackWall\Config;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class IpAddressMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $ipAddress = $this->extractIpAddress($request);
        $request = $request->withAttribute('ip_address', $ipAddress);

        return $handler->handle($request);
    }

    private function extractIpAddress(ServerRequestInterface $request): string
    {
        $serverParams = $request->getServerParams();
        $remoteAddr = (string) ($serverParams['REMOTE_ADDR'] ?? '');

        if (Config::getBool('TRUST_PROXY', false)) {
            $trustedProxies = explode(',', Config::get('TRUSTED_PROXIES', ''));
            $trustedProxies = array_map('trim', $trustedProxies);

            if ($this->isTrustedProxy($remoteAddr, $trustedProxies)) {
                $forwardedFor = $request->getHeaderLine('X-Forwarded-For');
                if (!empty($forwardedFor)) {
                    $ips = array_values(array_filter(array_map(
                        fn(string $ip): ?string => $this->validatedIpOrNull($ip),
                        explode(',', $forwardedFor)
                    )));

                    if (!empty($ips)) {
                        // XFF can include attacker-controlled left-most values; walk from the
                        // right and pick the first hop that is not a trusted proxy.
                        for ($i = count($ips) - 1; $i >= 0; $i--) {
                            if (!$this->isTrustedProxy($ips[$i], $trustedProxies)) {
                                return $ips[$i];
                            }
                        }

                        return $ips[count($ips) - 1];
                    }
                }

                $realIp = $request->getHeaderLine('X-Real-IP');
                $validatedRealIp = $this->validatedIpOrNull($realIp);
                if ($validatedRealIp !== null) {
                    return $validatedRealIp;
                }
            }
        }

        return $this->validatedIpOrNull($remoteAddr) ?? '0.0.0.0';
    }

    private function validatedIpOrNull(string $candidate): ?string
    {
        $candidate = trim($candidate);
        if ($candidate === '') {
            return null;
        }

        return filter_var($candidate, FILTER_VALIDATE_IP) !== false ? $candidate : null;
    }

    private function isTrustedProxy(string $ip, array $trustedEntries): bool
    {
        $validatedIp = $this->validatedIpOrNull($ip);
        if ($validatedIp === null) {
            return false;
        }

        foreach ($trustedEntries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }

            if (str_contains($entry, '/')) {
                if ($this->ipInCidr($validatedIp, $entry)) {
                    return true;
                }
                continue;
            }

            if ($validatedIp === $entry) {
                return true;
            }
        }

        return false;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $prefixLength] = array_pad(explode('/', $cidr, 2), 2, null);
        $subnet = $this->validatedIpOrNull((string) $subnet);
        if ($subnet === null || $prefixLength === null || !ctype_digit($prefixLength)) {
            return false;
        }

        $ipPacked = inet_pton($ip);
        $subnetPacked = inet_pton($subnet);
        if ($ipPacked === false || $subnetPacked === false) {
            return false;
        }
        if (strlen($ipPacked) !== strlen($subnetPacked)) {
            return false;
        }

        $maxBits = strlen($ipPacked) * 8;
        $prefix = (int) $prefixLength;
        if ($prefix < 0 || $prefix > $maxBits) {
            return false;
        }

        $bytes = intdiv($prefix, 8);
        $bits = $prefix % 8;

        if ($bytes > 0 && substr($ipPacked, 0, $bytes) !== substr($subnetPacked, 0, $bytes)) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $mask = ((0xFF00 >> $bits) & 0xFF);
        return (ord($ipPacked[$bytes]) & $mask) === (ord($subnetPacked[$bytes]) & $mask);
    }
}
