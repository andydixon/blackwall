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

            if (in_array($remoteAddr, $trustedProxies, true)) {
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
                            if (!in_array($ips[$i], $trustedProxies, true)) {
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
}
