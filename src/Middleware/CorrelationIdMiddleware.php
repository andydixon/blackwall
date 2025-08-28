<?php

declare(strict_types=1);

namespace BlackWall\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Ramsey\Uuid\Uuid;

class CorrelationIdMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $correlationId = $request->getHeaderLine('X-Correlation-Id');
        
        if (empty($correlationId) || !$this->isValidUuid($correlationId)) {
            $correlationId = Uuid::uuid4()->toString();
        }

        $request = $request->withAttribute('correlation_id', $correlationId);

        $response = $handler->handle($request);

        return $response->withHeader('X-Correlation-Id', $correlationId);
    }

    private function isValidUuid(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid) === 1;
    }
}
