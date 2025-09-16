<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Config;
use BlackWall\Service\MetricsService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class MetricsController
{
    private MetricsService $metrics;

    public function __construct()
    {
        $this->metrics = new MetricsService();
    }

    public function index(Request $request, Response $response): Response
    {
        $expectedToken = trim(Config::get('METRICS_TOKEN', ''));
        if ($expectedToken !== '') {
            $authHeader = $request->getHeaderLine('Authorization');
            $providedToken = '';
            if (str_starts_with($authHeader, 'Bearer ')) {
                $providedToken = substr($authHeader, 7);
            }

            if (!hash_equals($expectedToken, $providedToken)) {
                $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
                return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
            }
        }

        $payload = $this->metrics->collect();
        $response->getBody()->write(json_encode($payload, JSON_PRETTY_PRINT));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
