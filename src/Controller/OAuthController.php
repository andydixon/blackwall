<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Config;
use BlackWall\Repository\OAuthClientRepository;
use BlackWall\Repository\ProjectRepository;
use BlackWall\Repository\UserProjectRoleRepository;
use BlackWall\Repository\PrivilegeLevelRepository;
use BlackWall\Service\OAuthService;
use BlackWall\Service\AuditLogger;
use BlackWall\Security\SessionManager;
use BlackWall\Security\CSRFProtection;
use BlackWall\Security\JWTManager;
use BlackWall\Security\RateLimiter;
use BlackWall\Security\TokenHasher;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;

class OAuthController
{
    private OAuthClientRepository $clientRepo;
    private ProjectRepository $projectRepo;
    private UserProjectRoleRepository $roleRepo;
    private PrivilegeLevelRepository $privilegeRepo;
    private OAuthService $oauthService;
    private JWTManager $jwtManager;
    private RateLimiter $rateLimiter;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->clientRepo = new OAuthClientRepository();
        $this->projectRepo = new ProjectRepository();
        $this->roleRepo = new UserProjectRoleRepository();
        $this->privilegeRepo = new PrivilegeLevelRepository();
        $this->oauthService = new OAuthService();
        $this->jwtManager = new JWTManager();
        $this->rateLimiter = new RateLimiter();
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
    }

    public function discovery(Request $request, Response $response): Response
    {
        $issuer = Config::get('APP_URL');

        $config = [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer . '/oauth/authorize',
            'token_endpoint' => $issuer . '/oauth/token',
            'userinfo_endpoint' => $issuer . '/oauth/userinfo',
            'jwks_uri' => $issuer . '/oauth/jwks',
            'revocation_endpoint' => $issuer . '/oauth/revoke',
            'introspection_endpoint' => $issuer . '/oauth/introspect',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic', 'none'],
            'code_challenge_methods_supported' => ['S256'],
        ];

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $audit->logInfo('oidc.discovery');

        $response->getBody()->write(json_encode($config, JSON_PRETTY_PRINT));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function jwks(Request $request, Response $response): Response
    {
        $jwks = $this->jwtManager->getJWKS();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $audit->logInfo('jwks.fetch');

        $response->getBody()->write(json_encode($jwks, JSON_PRETTY_PRINT));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function authorize(Request $request, Response $response): Response
    {
        SessionManager::start();
        
        $params = $request->getQueryParams();
        
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        // Validate required parameters
        $requiredParams = ['client_id', 'redirect_uri', 'response_type', 'code_challenge', 'project_id'];
        foreach ($requiredParams as $param) {
            if (empty($params[$param])) {
                $audit->logFail('oauth.authorize.fail', [
                    'message' => "Missing required parameter: {$param}",
                    'error_code' => 'invalid_request',
                ]);
                return $this->errorResponse($response, 'invalid_request', "Missing parameter: {$param}");
            }
        }

        if ($params['response_type'] !== 'code') {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Unsupported response_type',
                'error_code' => 'unsupported_response_type',
            ]);
            return $this->errorResponse($response, 'unsupported_response_type');
        }

        // Find client
        $client = $this->clientRepo->findByClientId($params['client_id']);
        if (!$client || !$client->isActive()) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Invalid client_id',
                'error_code' => 'invalid_client',
                'oauth_client_public_id' => $params['client_id'],
            ]);
            return $this->errorResponse($response, 'invalid_client');
        }

        // Validate redirect URI
        if (!$client->hasRedirectUri($params['redirect_uri'])) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Invalid redirect_uri',
                'error_code' => 'invalid_redirect_uri',
                'oauth_client_id' => $client->id,
                'oauth_client_public_id' => $client->clientId,
                'redirect_uri' => $params['redirect_uri'],
            ]);
            return $this->errorResponse($response, 'invalid_request', 'Invalid redirect_uri');
        }

        // Validate project
        $project = $this->projectRepo->findByUuid($params['project_id']);
        if (!$project || !$project->isActive()) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Invalid project_id',
                'error_code' => 'invalid_project',
                'project_uuid' => $params['project_id'],
                'oauth_client_id' => $client->id,
            ]);
            return $this->redirectError($response, $params['redirect_uri'], 'invalid_request', 'Invalid project_id', $params['state'] ?? null);
        }

        // Verify client belongs to project
        if ($client->projectId !== $project->id) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Client does not belong to project',
                'error_code' => 'unauthorized_client',
                'project_id' => $project->id,
                'project_uuid' => $project->uuid,
                'oauth_client_id' => $client->id,
            ]);
            return $this->redirectError($response, $params['redirect_uri'], 'unauthorized_client', null, $params['state'] ?? null);
        }

        // Validate PKCE
        if (empty($params['code_challenge']) || empty($params['code_challenge_method'])) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Missing PKCE parameters',
                'error_code' => 'invalid_request',
                'oauth_client_id' => $client->id,
            ]);
            return $this->redirectError($response, $params['redirect_uri'], 'invalid_request', 'PKCE required', $params['state'] ?? null);
        }

        if ($params['code_challenge_method'] !== 'S256') {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Unsupported code_challenge_method',
                'error_code' => 'invalid_request',
                'oauth_client_id' => $client->id,
                'pkce_method' => $params['code_challenge_method'],
            ]);
            return $this->redirectError($response, $params['redirect_uri'], 'invalid_request', 'Only S256 supported', $params['state'] ?? null);
        }

        // Parse scopes
        $requestedScopes = isset($params['scope']) ? explode(' ', $params['scope']) : [];
        
        // Check if user is logged in
        $userId = SessionManager::get('user_id');
        if (!$userId) {
            // Store auth request and redirect to login
            SessionManager::set('oauth_auth_request', $params);
            return $response
                ->withHeader('Location', '/admin/login?return_to=/oauth/authorize')
                ->withStatus(302);
        }

        // Check if user has access to project
        $role = $this->roleRepo->findByUserAndProject($userId, $project->id);
        if (!$role) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'User not assigned to project',
                'error_code' => 'access_denied',
                'actor_user_id' => $userId,
                'project_id' => $project->id,
                'project_uuid' => $project->uuid,
            ]);
            return $this->redirectError($response, $params['redirect_uri'], 'access_denied', 'User not authorized for this project', $params['state'] ?? null);
        }

        $privilegeLevel = $this->privilegeRepo->findByProjectAndLevel($project->id, $role->privilegeLevel);

        $audit->logInfo('oauth.authorize.begin', [
            'actor_user_id' => $userId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'oauth_client_id' => $client->id,
            'oauth_client_public_id' => $client->clientId,
            'requested_scopes' => $requestedScopes,
            'redirect_uri' => $params['redirect_uri'],
        ]);

        // Show consent screen
        return $this->renderer->render($response, 'oauth/consent.php', [
            'client' => $client,
            'project' => $project,
            'scopes' => $requestedScopes,
            'privilegeLevel' => $privilegeLevel,
            'csrfToken' => CSRFProtection::generateToken(),
            'params' => $params,
        ]);
    }

    public function authorizePost(Request $request, Response $response): Response
    {
        SessionManager::start();
        
        $body = $request->getParsedBody();
        
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        // Validate CSRF
        if (!isset($body['csrf_token']) || !CSRFProtection::validateToken($body['csrf_token'])) {
            $audit->logFail('security.csrf.fail', ['message' => 'CSRF validation failed']);
            return $this->errorResponse($response, 'invalid_request', 'CSRF validation failed');
        }

        $params = SessionManager::get('oauth_auth_request');
        if (!$params) {
            return $this->errorResponse($response, 'invalid_request', 'No authorization request found');
        }

        $userId = SessionManager::get('user_id');
        if (!$userId) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $client = $this->clientRepo->findByClientId($params['client_id']);
        $project = $this->projectRepo->findByUuid($params['project_id']);

        if (isset($body['deny'])) {
            $audit->logInfo('oauth.authorize.deny', [
                'actor_user_id' => $userId,
                'project_id' => $project->id,
                'project_uuid' => $project->uuid,
                'oauth_client_id' => $client->id,
            ]);

            SessionManager::remove('oauth_auth_request');
            return $this->redirectError($response, $params['redirect_uri'], 'access_denied', null, $params['state'] ?? null);
        }

        // User approved - generate authorization code
        $requestedScopes = isset($params['scope']) ? explode(' ', $params['scope']) : [];
        
        $code = $this->oauthService->createAuthorizationCode([
            'client_id' => $client->id,
            'user_id' => $userId,
            'project_id' => $project->id,
            'redirect_uri' => $params['redirect_uri'],
            'scopes' => $requestedScopes,
            'code_challenge' => $params['code_challenge'],
            'code_challenge_method' => $params['code_challenge_method'],
            'nonce' => $params['nonce'] ?? null,
        ]);

        $role = $this->roleRepo->findByUserAndProject($userId, $project->id);
        $privilegeLevel = $this->privilegeRepo->findByProjectAndLevel($project->id, $role->privilegeLevel);

        $audit->logSuccess('oauth.authorize.approve', [
            'actor_user_id' => $userId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'oauth_client_id' => $client->id,
            'oauth_client_public_id' => $client->clientId,
            'requested_scopes' => $requestedScopes,
            'privilege_level' => $role->privilegeLevel,
            'privilege_name' => $privilegeLevel ? $privilegeLevel->name : 'Unknown',
        ]);

        SessionManager::remove('oauth_auth_request');

        $redirectUrl = $params['redirect_uri'] . '?code=' . urlencode($code);
        if (isset($params['state'])) {
            $redirectUrl .= '&state=' . urlencode($params['state']);
        }

        return $response->withHeader('Location', $redirectUrl)->withStatus(302);
    }

    public function token(Request $request, Response $response): Response
    {
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = $request->getAttribute('ip_address');

        if (!$this->rateLimiter->check($ipAddress, 'oauth.token', 60, 60)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for token endpoint',
                'action' => 'oauth.token',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        $body = $request->getParsedBody();

        if (empty($body['grant_type'])) {
            $audit->logFail('oauth.token.fail', ['error_code' => 'invalid_request']);
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        if ($body['grant_type'] === 'authorization_code') {
            return $this->handleAuthorizationCodeGrant($request, $response, $body, $audit);
        }

        $audit->logFail('oauth.token.fail', ['error_code' => 'unsupported_grant_type']);
        $response->getBody()->write(json_encode(['error' => 'unsupported_grant_type']));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    private function handleAuthorizationCodeGrant(Request $request, Response $response, array $body, AuditLogger $audit): Response
    {
        if (empty($body['code']) || empty($body['client_id']) || empty($body['redirect_uri']) || empty($body['code_verifier'])) {
            $audit->logFail('oauth.token.fail', ['error_code' => 'invalid_request']);
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $tokenData = $this->oauthService->exchangeAuthorizationCode(
            $body['code'],
            $body['client_id'],
            $body['redirect_uri'],
            $body['code_verifier']
        );

        if (!$tokenData) {
            $audit->logFail('oauth.token.fail', [
                'error_code' => 'invalid_grant',
                'oauth_client_public_id' => $body['client_id'],
            ]);
            $response->getBody()->write(json_encode(['error' => 'invalid_grant']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $audit->logSuccess('oauth.token.issue', [
            'oauth_client_public_id' => $body['client_id'],
            'grant_type' => 'authorization_code',
        ]);

        $response->getBody()->write(json_encode($tokenData));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function revoke(Request $request, Response $response): Response
    {
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        if (empty($body['token'])) {
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $revoked = $this->oauthService->revokeToken($body['token']);

        $audit->logSuccess('oauth.token.revoke', [
            'oauth_client_public_id' => $body['client_id'] ?? null,
        ]);

        return $response->withStatus(200);
    }

    public function introspect(Request $request, Response $response): Response
    {
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        if (empty($body['token'])) {
            $response->getBody()->write(json_encode(['active' => false]));
            return $response->withHeader('Content-Type', 'application/json');
        }

        $introspection = $this->oauthService->introspectToken($body['token']);

        $audit->logInfo('oauth.token.introspect', [
            'oauth_client_public_id' => $body['client_id'] ?? null,
        ]);

        $response->getBody()->write(json_encode($introspection));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function userinfo(Request $request, Response $response): Response
    {
        // TODO: Implement bearer token extraction and validation
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        $audit->logInfo('oidc.userinfo');

        $response->getBody()->write(json_encode(['sub' => 'user-uuid']));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function errorResponse(Response $response, string $error, ?string $description = null): Response
    {
        $data = ['error' => $error];
        if ($description) {
            $data['error_description'] = $description;
        }

        $response->getBody()->write(json_encode($data));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    private function redirectError(Response $response, string $redirectUri, string $error, ?string $description = null, ?string $state = null): Response
    {
        $url = $redirectUri . '?error=' . urlencode($error);
        if ($description) {
            $url .= '&error_description=' . urlencode($description);
        }
        if ($state) {
            $url .= '&state=' . urlencode($state);
        }

        return $response->withHeader('Location', $url)->withStatus(302);
    }
}
