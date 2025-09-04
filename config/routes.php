<?php

declare(strict_types=1);

use BlackWall\Controller\AdminController;
use BlackWall\Controller\OAuthController;
use BlackWall\Controller\BootstrapController;
use BlackWall\Controller\PortalController;
use Slim\Routing\RouteCollectorProxy;

// Bootstrap route (only if not complete)
$app->get('/bootstrap', [BootstrapController::class, 'showBootstrapForm']);
$app->post('/bootstrap/enroll', [BootstrapController::class, 'enrollWebAuthn']);

// Portal routes
$app->get('/portal/login', [PortalController::class, 'loginForm']);
$app->post('/portal/login', [PortalController::class, 'loginChallenge']);
$app->get('/portal/login/challenge', [PortalController::class, 'loginChallenge']);
$app->post('/portal/login/challenge', [PortalController::class, 'loginChallenge']);
$app->get('/portal/login/verify', [PortalController::class, 'loginVerify']);
$app->post('/portal/login/verify', [PortalController::class, 'loginVerify']);
$app->get('/portal', [PortalController::class, 'dashboard']);
$app->post('/portal/keys/add/init', [PortalController::class, 'addKeyInit']);
$app->post('/portal/keys/add/complete', [PortalController::class, 'addKeyComplete']);
$app->post('/portal/keys/{id}/delete', [PortalController::class, 'deleteKey']);
$app->post('/portal/logout', [PortalController::class, 'logout']);

// Home page
$app->get('/', function ($request, $response) {
    $renderer = new \Slim\Views\PhpRenderer(__DIR__ . '/../templates');
    return $renderer->render($response, 'home.php');
});

// OAuth 2.1 / OIDC Discovery
$app->get('/.well-known/openid-configuration', [OAuthController::class, 'discovery']);
$app->get('/oauth/jwks', [OAuthController::class, 'jwks']);

// OAuth endpoints
$app->get('/oauth/authorize', [OAuthController::class, 'authorize']);
$app->post('/oauth/authorize', [OAuthController::class, 'authorizePost']);
$app->post('/oauth/login/challenge', [OAuthController::class, 'loginChallenge']);
$app->post('/oauth/login/verify', [OAuthController::class, 'loginVerify']);
$app->post('/oauth/token', [OAuthController::class, 'token']);
$app->post('/oauth/revoke', [OAuthController::class, 'revoke']);
$app->post('/oauth/introspect', [OAuthController::class, 'introspect']);
$app->get('/oauth/userinfo', [OAuthController::class, 'userinfo']);

// Admin routes
$app->group('/admin', function (RouteCollectorProxy $group) {
    // Auth
    $group->get('/login', [AdminController::class, 'loginForm']);
    $group->get('/login/challenge', [AdminController::class, 'loginChallenge']);
    $group->post('/login/challenge', [AdminController::class, 'loginChallenge']);
    $group->post('/login/verify', [AdminController::class, 'loginVerify']);
    $group->post('/logout', [AdminController::class, 'logout']);

    // Dashboard
    $group->get('', [AdminController::class, 'dashboard']);
    $group->get('/dashboard', [AdminController::class, 'dashboard']);

    // Users
    $group->get('/users', [AdminController::class, 'usersList']);
    $group->get('/users/create', [AdminController::class, 'userCreate']);
    $group->post('/users/create', [AdminController::class, 'userStore']);
    $group->get('/users/{id}', [AdminController::class, 'userDetail']);
    $group->post('/users/{id}/update', [AdminController::class, 'userUpdate']);

    // Projects
    $group->get('/projects', [AdminController::class, 'projectsList']);
    $group->get('/projects/create', [AdminController::class, 'projectCreate']);
    $group->post('/projects/create', [AdminController::class, 'projectStore']);
    $group->get('/projects/{id}', [AdminController::class, 'projectDetail']);
    $group->post('/projects/{id}/update', [AdminController::class, 'projectUpdate']);

    // Privilege levels
    $group->get('/projects/{id}/privileges', [AdminController::class, 'privilegeLevels']);
    $group->post('/projects/{id}/privileges/create', [AdminController::class, 'privilegeLevelCreate']);
    $group->post('/privileges/{id}/update', [AdminController::class, 'privilegeLevelUpdate']);
    $group->post('/privileges/{id}/delete', [AdminController::class, 'privilegeLevelDelete']);

    // User assignments
    $group->get('/projects/{id}/assignments', [AdminController::class, 'projectAssignments']);
    $group->post('/projects/{id}/assignments/create', [AdminController::class, 'assignmentCreate']);
    $group->post('/assignments/{id}/update', [AdminController::class, 'assignmentUpdate']);
    $group->post('/assignments/{id}/delete', [AdminController::class, 'assignmentDelete']);

    // OAuth clients
    $group->get('/projects/{id}/clients', [AdminController::class, 'clientsList']);
    $group->get('/projects/{projectId}/clients/create', [AdminController::class, 'clientCreate']);
    $group->post('/projects/{projectId}/clients/create', [AdminController::class, 'clientStore']);
    $group->get('/clients/{id}', [AdminController::class, 'clientDetail']);
    $group->post('/clients/{id}/update', [AdminController::class, 'clientUpdate']);

    // Audit logs
    $group->get('/audit', [AdminController::class, 'auditLog']);
    $group->get('/audit/export', [AdminController::class, 'auditExport']);
});
