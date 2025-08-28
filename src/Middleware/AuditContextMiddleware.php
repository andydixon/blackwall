<?php

declare(strict_types=1);

namespace BlackWall\Middleware;

use BlackWall\Service\AuditLogger;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuditContextMiddleware implements MiddlewareInterface
{
    private AuditLogger $auditLogger;

    public function __construct(AuditLogger $auditLogger)
    {
        $this->auditLogger = $auditLogger;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $correlationId = $request->getAttribute('correlation_id');
        $ipAddress = $request->getAttribute('ip_address');
        $userAgent = $request->getHeaderLine('User-Agent');

        $this->auditLogger->setRequestContext($correlationId, $ipAddress, $userAgent);

        $request = $request->withAttribute('audit_logger', $this->auditLogger);

        return $handler->handle($request);
    }
}
