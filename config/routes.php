<?php

declare(strict_types=1);

use BlackWall\Controller\AdminController;
use BlackWall\Controller\OAuthController;
use BlackWall\Controller\BootstrapController;
use BlackWall\Controller\PortalController;
use BlackWall\Controller\CryptbinController;
use BlackWall\Controller\MetricsController;
use Slim\Routing\RouteCollectorProxy;

// Bootstrap route (only if not complete)
$app->get('/bootstrap', [BootstrapController::class, 'showBootstrapForm']);
$app->post('/bootstrap/enroll', [BootstrapController::class, 'enrollWebAuthn']);

// User enrollment routes
$app->get('/enroll', [BootstrapController::class, 'showEnrollmentForm']);
$app->post('/enroll/complete', [BootstrapController::class, 'enrollKey']);
$app->get('/organisations/signup', [BootstrapController::class, 'organizationSignupForm']);
$app->post('/organisations/signup', [BootstrapController::class, 'organizationSignup']);

// Portal routes
$app->get('/portal/login', [PortalController::class, 'loginForm']);
$app->post('/portal/login', [PortalController::class, 'loginChallenge']);
$app->post('/portal/login/challenge', [PortalController::class, 'loginChallenge']);
$app->post('/portal/login/verify', [PortalController::class, 'loginVerify']);
$app->get('/portal', [PortalController::class, 'dashboard']);
$app->post('/portal/keys/add/init', [PortalController::class, 'addKeyInit']);
$app->post('/portal/keys/add/complete', [PortalController::class, 'addKeyComplete']);
$app->post('/portal/keys/{credentialPublicId}/delete', [PortalController::class, 'deleteKey']);
$app->post('/portal/logout', [PortalController::class, 'logout']);

// Cryptbin routes
$app->get('/cryptbin', [CryptbinController::class, 'createForm']);
$app->post('/cryptbin/create', [CryptbinController::class, 'create']);
$app->get('/cryptbin/{id}', [CryptbinController::class, 'view']);
$app->get('/cryptbin/{id}/share', [CryptbinController::class, 'share']);
$app->get('/cryptbin/{id}/meta', [CryptbinController::class, 'metadata']);
$app->get('/cryptbin/{id}/ciphertext', [CryptbinController::class, 'ciphertext']);
$app->post('/cryptbin/{id}/webauthn/challenge', [CryptbinController::class, 'webauthnChallenge']);
$app->post('/cryptbin/{id}/wrap', [CryptbinController::class, 'wrap']);
$app->post('/cryptbin/{id}/unwrap', [CryptbinController::class, 'unwrap']);
$app->post('/cryptbin/{id}/update', [CryptbinController::class, 'update']);
$app->post('/cryptbin/{id}/delete', [CryptbinController::class, 'delete']);

// Home page
$app->get('/', function ($request, $response) {
    $renderer = new \Slim\Views\PhpRenderer(__DIR__ . '/../templates');
    return $renderer->render($response, 'home.php');
});
$app->get('/metrics', [MetricsController::class, 'index']);

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
    $group->post('/login/challenge', [AdminController::class, 'loginChallenge']);
    $group->post('/login/verify', [AdminController::class, 'loginVerify']);
    $group->post('/logout', [AdminController::class, 'logout']);

    // Dashboard
    $group->get('', [AdminController::class, 'dashboard']);
    $group->get('/dashboard', [AdminController::class, 'dashboard']);
    $group->get('/maintenance', [AdminController::class, 'maintenance']);
    $group->get('/docs', [AdminController::class, 'docsHome']);
    $group->get('/docs/', [AdminController::class, 'docsHome']);
    $group->get('/docs/{page}', [AdminController::class, 'docsPage']);
    $group->get('/docs/{page}/', [AdminController::class, 'docsPage']);
    $group->get('/scope', [AdminController::class, 'scopeDebug']);
    $group->get('/error-trace', [AdminController::class, 'errorTraceDecodeForm']);
    $group->post('/error-trace', [AdminController::class, 'errorTraceDecode']);
    $group->get('/roles', [AdminController::class, 'adminRoles']);
    $group->post('/roles', [AdminController::class, 'adminRoleUpsert']);
    $group->post('/roles/{userId}/revoke', [AdminController::class, 'adminRoleRevoke']);
    $group->get('/organisations', [AdminController::class, 'organizationsList']);
    $group->post('/organisations/create', [AdminController::class, 'organizationStore']);
    $group->get('/organisations/{organizationUuid}', [AdminController::class, 'organizationDetail']);
    $group->post('/organisations/{organizationUuid}/update', [AdminController::class, 'organizationUpdate']);
    $group->post('/organisations/{organizationUuid}/switch-admin', [AdminController::class, 'organizationSwitchAdmin']);
    $group->post('/organisations/{organizationUuid}/users/import', [AdminController::class, 'organizationImportUsers']);
    $group->get('/organisations/{organizationUuid}/enrollment-urls/export', [AdminController::class, 'organizationExportEnrollmentUrls']);
    $group->post('/switch/restore', [AdminController::class, 'switchRestore']);
    $group->get('/approvals', [AdminController::class, 'approvalsList']);
    $group->post('/approvals/{id}/approve', [AdminController::class, 'approvalApprove']);
    $group->post('/approvals/{id}/reject', [AdminController::class, 'approvalReject']);
    $group->post('/approvals/{id}/cancel', [AdminController::class, 'approvalCancel']);

    // Users
    $group->get('/users', [AdminController::class, 'usersList']);
    $group->get('/users/create', [AdminController::class, 'userCreate']);
    $group->post('/users/create', [AdminController::class, 'userStore']);
    $group->get('/users/{userUuid}', [AdminController::class, 'userDetail']);
    $group->post('/users/{userUuid}/update', [AdminController::class, 'userUpdate']);
    $group->post('/users/{userUuid}/enrollment-link', [AdminController::class, 'generateEnrollmentLink']);
    $group->post('/users/{userUuid}/credentials/{credentialPublicId}/delete', [AdminController::class, 'deleteCredential']);

    // Projects
    $group->get('/projects', [AdminController::class, 'projectsList']);
    $group->get('/projects/create', [AdminController::class, 'projectCreate']);
    $group->post('/projects/create', [AdminController::class, 'projectStore']);
    $group->get('/projects/{projectUuid}', [AdminController::class, 'projectDetail']);
    $group->post('/projects/{projectUuid}/update', [AdminController::class, 'projectUpdate']);

    // Privilege levels
    $group->get('/projects/{projectUuid}/privileges', [AdminController::class, 'privilegeLevels']);
    $group->post('/projects/{projectUuid}/privileges/create', [AdminController::class, 'privilegeLevelCreate']);
    $group->post('/privileges/{id}/update', [AdminController::class, 'privilegeLevelUpdate']);
    $group->post('/privileges/{id}/delete', [AdminController::class, 'privilegeLevelDelete']);

    // User assignments
    $group->get('/projects/{projectUuid}/assignments', [AdminController::class, 'projectAssignments']);
    $group->post('/projects/{projectUuid}/assignments/create', [AdminController::class, 'assignmentCreate']);
    $group->post('/assignments/{id}/update', [AdminController::class, 'assignmentUpdate']);
    $group->post('/assignments/{id}/delete', [AdminController::class, 'assignmentDelete']);

    // OAuth clients
    $group->get('/projects/{projectUuid}/clients', [AdminController::class, 'clientsList']);
    $group->get('/projects/{projectUuid}/clients/create', [AdminController::class, 'clientCreate']);
    $group->post('/projects/{projectUuid}/clients/create', [AdminController::class, 'clientStore']);
    $group->get('/clients/{clientPublicId}', [AdminController::class, 'clientDetail']);
    $group->post('/clients/{clientPublicId}/update', [AdminController::class, 'clientUpdate']);

    // Audit logs
    $group->get('/audit', [AdminController::class, 'auditLog']);
    $group->get('/audit/export', [AdminController::class, 'auditExport']);
});
