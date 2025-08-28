<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BlackWall\Config;
use BlackWall\Service\AuditLogger;
use BlackWall\Middleware\CorrelationIdMiddleware;
use BlackWall\Middleware\IpAddressMiddleware;
use BlackWall\Middleware\AuditContextMiddleware;
use Slim\Factory\AppFactory;
use Slim\Views\PhpRenderer;

// Load environment configuration
Config::load(__DIR__ . '/..');

// Validate required configuration
Config::required([
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'DB_PASS',
    'APP_URL',
    'WEBAUTHN_RP_ID',
    'WEBAUTHN_RP_NAME',
]);

// Create Slim app
$app = AppFactory::create();

// Add error middleware
$app->addErrorMiddleware(
    Config::getBool('APP_DEBUG', false),
    true,
    true
);

// Add global middleware
$app->add(new CorrelationIdMiddleware());
$app->add(new IpAddressMiddleware());
$app->add(new AuditContextMiddleware(new AuditLogger()));

// Template renderer
$templates = new PhpRenderer(__DIR__ . '/../templates');

// Health check
$app->get('/health', function ($request, $response) {
    $response->getBody()->write(json_encode(['status' => 'ok']));
    return $response->withHeader('Content-Type', 'application/json');
});

// Load routes
require __DIR__ . '/../config/routes.php';

return $app;
