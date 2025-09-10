<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BlackWall\Config;
use BlackWall\Service\AuditLogger;
use BlackWall\Middleware\CorrelationIdMiddleware;
use BlackWall\Middleware\IpAddressMiddleware;
use BlackWall\Middleware\AuditContextMiddleware;
use Slim\Factory\AppFactory;
use Slim\Exception\HttpException;
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
    'CRYPTBIN_KEK_BASE64',
]);

// Create Slim app
$app = AppFactory::create();

// Template renderer
$templates = new PhpRenderer(__DIR__ . '/../templates');

// Add error middleware
$errorMiddleware = $app->addErrorMiddleware(
    Config::getBool('APP_DEBUG', false),
    true,
    true
);

$errorMiddleware->setDefaultErrorHandler(
    function (
        $request,
        \Throwable $exception,
        bool $displayErrorDetails,
        bool $logErrors,
        bool $logErrorDetails
    ) use ($app, $templates) {
        $statusCode = 500;
        if ($exception instanceof HttpException) {
            $statusCode = method_exists($exception, 'getStatusCode')
                ? (int) $exception->getStatusCode()
                : (int) $exception->getCode();
        }
        if ($statusCode < 400 || $statusCode > 599) {
            $statusCode = 500;
        }

        $headline = match ($statusCode) {
            404 => 'Page Not Found',
            403 => 'Access Forbidden',
            401 => 'Unauthorized',
            default => 'Application Error',
        };

        $detail = match ($statusCode) {
            404 => 'The page you requested does not exist or has moved.',
            403 => 'You do not have permission to access this resource.',
            401 => 'Authentication is required to access this resource.',
            default => 'An unexpected error occurred while processing your request.',
        };

        $tracePayload = null;
        if ($displayErrorDetails) {
            $tracePayload = base64_encode((string) $exception);
        }

        $response = $app->getResponseFactory()->createResponse($statusCode);
        return $templates->render($response, 'error.php', [
            'title' => "Error {$statusCode}",
            'statusCode' => $statusCode,
            'headline' => $headline,
            'detail' => $detail,
            'tracePayload' => $tracePayload,
        ]);
    }
);

// Add body parsing middleware for JSON requests
$app->addBodyParsingMiddleware();

// Add global middleware (last added runs first)
$app->add(new AuditContextMiddleware(new AuditLogger()));
$app->add(new IpAddressMiddleware());
$app->add(new CorrelationIdMiddleware());

// Health check
$app->get('/health', function ($request, $response) {
    $response->getBody()->write(json_encode(['status' => 'ok']));
    return $response->withHeader('Content-Type', 'application/json');
});

// Load routes
require __DIR__ . '/../config/routes.php';

return $app;
