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

        if (Config::getBool('TRUST_PROXY', false)) {
            $trustedProxies = explode(',', Config::get('TRUSTED_PROXIES', ''));
            $trustedProxies = array_map('trim', $trustedProxies);

            $remoteAddr = $serverParams['REMOTE_ADDR'] ?? '';

            if (in_array($remoteAddr, $trustedProxies, true)) {
                $forwardedFor = $request->getHeaderLine('X-Forwarded-For');
                if (!empty($forwardedFor)) {
                    $ips = explode(',', $forwardedFor);
                    return trim($ips[0]);
                }

                $realIp = $request->getHeaderLine('X-Real-IP');
                if (!empty($realIp)) {
                    return $realIp;
                }
            }
        }

        return $serverParams['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
