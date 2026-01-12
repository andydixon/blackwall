<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Config;
use BlackWall\Domain\PrivilegeLabelResolver;
use BlackWall\Repository\OAuthClientRepository;
use BlackWall\Repository\ProjectRepository;
use BlackWall\Repository\OrganizationRepository;
use BlackWall\Repository\UserProjectRoleRepository;
use BlackWall\Repository\PrivilegeLevelRepository;
use BlackWall\Service\OAuthService;
use BlackWall\Service\AuditLogger;
use BlackWall\Security\SessionManager;
use BlackWall\Security\CSRFProtection;
use BlackWall\Security\JWTManager;
use BlackWall\Security\OAuthClientAuthenticator;
use BlackWall\Security\OAuthAuthorizationRequestValidator;
use BlackWall\Security\OidcNonceReplayGuard;
use BlackWall\Security\RateLimiter;
use BlackWall\Security\TokenHasher;
use BlackWall\Security\UserInfoScopePolicy;
use BlackWall\Database;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;

class OAuthController
{
    private const LOGIN_CHALLENGE_TTL_SECONDS = 120;

    private OAuthClientRepository $clientRepo;
    private ProjectRepository $projectRepo;
    private UserProjectRoleRepository $roleRepo;
    private OrganizationRepository $organizationRepo;
    private PrivilegeLevelRepository $privilegeRepo;
    private OAuthService $oauthService;
    private JWTManager $jwtManager;
    private RateLimiter $rateLimiter;
    private OAuthClientAuthenticator $clientAuthenticator;
    private OAuthAuthorizationRequestValidator $authRequestValidator;
    private OidcNonceReplayGuard $nonceReplayGuard;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->clientRepo = new OAuthClientRepository();
        $this->projectRepo = new ProjectRepository();
        $this->organizationRepo = new OrganizationRepository();
        $this->roleRepo = new UserProjectRoleRepository();
        $this->privilegeRepo = new PrivilegeLevelRepository();
        $this->oauthService = new OAuthService();
        $this->jwtManager = new JWTManager();
        $this->rateLimiter = new RateLimiter();
        $this->clientAuthenticator = new OAuthClientAuthenticator(new TokenHasher());
        $this->authRequestValidator = new OAuthAuthorizationRequestValidator();
        $this->nonceReplayGuard = new OidcNonceReplayGuard();
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
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        if (!$this->rateLimiter->check('ip:' . $ipAddress, 'oauth.authorize', 120, 60)) {
            /** @var AuditLogger $audit */
            $audit = $request->getAttribute('audit_logger');
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for authorize endpoint',
                'action' => 'oauth.authorize',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }
        
        $params = $request->getQueryParams();
        
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        if (empty($params['client_id']) || empty($params['redirect_uri'])) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Missing client_id or redirect_uri',
                'error_code' => 'invalid_request',
            ]);
            return $this->errorResponse($response, 'invalid_request', 'Missing client_id or redirect_uri');
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

        // Get project from client
        $project = $this->projectRepo->findById($client->projectId);
        if (!$project || !$project->isActive()) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'Client project not found or inactive',
                'error_code' => 'invalid_project',
                'project_id' => $client->projectId,
                'oauth_client_id' => $client->id,
            ]);
            return $this->redirectError($response, $params['redirect_uri'], 'invalid_request', 'Client project invalid', $params['state'] ?? null);
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

        // Parse scopes
        $requestedScopes = isset($params['scope']) ? explode(' ', $params['scope']) : [];
        $isOidcRequest = in_array('openid', $requestedScopes, true);

        $validation = $this->authRequestValidator->validate(
            $params,
            $isOidcRequest,
            $isOidcRequest
                ? fn(string $nonce): bool => $this->nonceReplayGuard->isReplayAndRemember($client->clientId, $nonce)
                : null
        );
        if (!$validation['ok']) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => (string) ($validation['description'] ?? $validation['error'] ?? 'Invalid authorization request'),
                'error_code' => (string) ($validation['error'] ?? 'invalid_request'),
                'oauth_client_id' => $client->id,
                'oauth_client_public_id' => $client->clientId,
            ]);
            return $this->redirectError(
                $response,
                $params['redirect_uri'],
                (string) ($validation['error'] ?? 'invalid_request'),
                $validation['description'],
                $params['state'] ?? null
            );
        }
        
        // Check if user is logged in
        $userId = SessionManager::get('user_id');
        // Always store the authorization request for later use
        SessionManager::set('oauth_auth_request', $params);
        if (!$userId) {
            // Show OAuth login page
            return $this->renderer->render($response, 'oauth/login.php', [
                'clientName' => $client->name,
                'returnUrl' => $params['redirect_uri'],
                'organization' => $this->organizationRepo->findById($project->organizationId),
                'csrfToken' => CSRFProtection::generateToken(),
            ]);
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
        $privilegeLabel = PrivilegeLabelResolver::resolve($role->privilegeLevel, $privilegeLevel?->name);

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
            'privilegeLabel' => $privilegeLabel,
            'privilegeLevelNumber' => $role->privilegeLevel,
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
        if (!is_array($params)) {
            return $this->errorResponse($response, 'invalid_request', 'No authorization request found');
        }
        $clientPublicId = (string) ($params['client_id'] ?? '');
        $redirectUri = (string) ($params['redirect_uri'] ?? '');
        if ($clientPublicId === '' || $redirectUri === '') {
            SessionManager::remove('oauth_auth_request');
            return $this->errorResponse($response, 'invalid_request', 'Malformed authorization request');
        }

        $userId = SessionManager::get('user_id');
        if (!$userId) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $client = $this->clientRepo->findByClientId($clientPublicId);
        if ($client === null || !$client->isActive() || !$client->hasRedirectUri($redirectUri)) {
            SessionManager::remove('oauth_auth_request');
            return $this->errorResponse($response, 'invalid_client', 'Invalid or inactive OAuth client');
        }
        $project = $this->projectRepo->findById($client->projectId);
        if ($project === null || !$project->isActive() || $client->projectId !== $project->id) {
            SessionManager::remove('oauth_auth_request');
            return $this->redirectError($response, $redirectUri, 'invalid_request', 'Client project invalid', $params['state'] ?? null);
        }

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
        $role = $this->roleRepo->findByUserAndProject((int) $userId, $project->id);
        if ($role === null) {
            $audit->logFail('oauth.authorize.fail', [
                'message' => 'User not assigned to project at consent submission',
                'error_code' => 'access_denied',
                'actor_user_id' => (int) $userId,
                'project_id' => $project->id,
                'project_uuid' => $project->uuid,
                'oauth_client_id' => $client->id,
                'oauth_client_public_id' => $client->clientId,
            ]);
            SessionManager::remove('oauth_auth_request');
            return $this->redirectError($response, $redirectUri, 'access_denied', 'User not authorized for this project', $params['state'] ?? null);
        }
        
        $code = $this->oauthService->createAuthorizationCode([
            'client_id' => $client->id,
            'user_id' => $userId,
            'project_id' => $project->id,
            'redirect_uri' => $redirectUri,
            'scopes' => $requestedScopes,
            'code_challenge' => $params['code_challenge'],
            'code_challenge_method' => $params['code_challenge_method'],
            'nonce' => $params['nonce'] ?? null,
        ]);

        $privilegeLevel = $this->privilegeRepo->findByProjectAndLevel($project->id, $role->privilegeLevel);

        $audit->logSuccess('oauth.authorize.approve', [
            'actor_user_id' => $userId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'oauth_client_id' => $client->id,
            'oauth_client_public_id' => $client->clientId,
            'requested_scopes' => $requestedScopes,
            'privilege_level' => $role->privilegeLevel,
            'privilege_name' => PrivilegeLabelResolver::resolve(
                $role->privilegeLevel,
                $privilegeLevel?->name
            ),
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
        $response = $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');

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

        $auth = $this->authenticateClient($request, (array) $body);
        if (!$auth['ok']) {
            $error = (string) ($auth['error'] ?? 'invalid_client');
            $status = $error === 'unauthorized_client' ? 400 : 401;
            $audit->logFail('oauth.token.fail', ['error_code' => $error]);
            $response->getBody()->write(json_encode(['error' => $error]));
            return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
        }
        $client = $auth['client'];

        if (!$client->supportsGrant((string) $body['grant_type'])) {
            $audit->logFail('oauth.token.fail', ['error_code' => 'unauthorized_client']);
            $response->getBody()->write(json_encode(['error' => 'unauthorized_client']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        if ($body['grant_type'] === 'authorization_code') {
            return $this->handleAuthorizationCodeGrant($request, $response, (array) $body, $audit, $client);
        }
        if ($body['grant_type'] === 'refresh_token') {
            return $this->handleRefreshTokenGrant($response, (array) $body, $audit, $client);
        }

        $audit->logFail('oauth.token.fail', ['error_code' => 'unsupported_grant_type']);
        $response->getBody()->write(json_encode(['error' => 'unsupported_grant_type']));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    private function handleAuthorizationCodeGrant(
        Request $request,
        Response $response,
        array $body,
        AuditLogger $audit,
        \BlackWall\Model\OAuthClient $client
    ): Response
    {
        if (empty($body['code']) || empty($body['redirect_uri']) || empty($body['code_verifier'])) {
            $audit->logFail('oauth.token.fail', ['error_code' => 'invalid_request']);
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $tokenData = $this->oauthService->exchangeAuthorizationCode(
            (string) $body['code'],
            $client->clientId,
            (string) $body['redirect_uri'],
            (string) $body['code_verifier']
        );

        if (!$tokenData) {
            $audit->logFail('oauth.token.fail', [
                'error_code' => 'invalid_grant',
                'oauth_client_public_id' => $client->clientId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'invalid_grant']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $audit->logSuccess('oauth.token.issue', [
            'oauth_client_public_id' => $client->clientId,
            'grant_type' => 'authorization_code',
        ]);

        $response->getBody()->write(json_encode($tokenData));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function handleRefreshTokenGrant(
        Response $response,
        array $body,
        AuditLogger $audit,
        \BlackWall\Model\OAuthClient $client
    ): Response {
        if (empty($body['refresh_token'])) {
            $audit->logFail('oauth.token.fail', ['error_code' => 'invalid_request']);
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $tokenData = $this->oauthService->exchangeRefreshToken(
            (string) $body['refresh_token'],
            $client->clientId
        );
        if (!$tokenData) {
            $audit->logFail('oauth.token.fail', [
                'error_code' => 'invalid_grant',
                'oauth_client_public_id' => $client->clientId,
                'grant_type' => 'refresh_token',
            ]);
            $response->getBody()->write(json_encode(['error' => 'invalid_grant']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $audit->logSuccess('oauth.token.issue', [
            'oauth_client_public_id' => $client->clientId,
            'grant_type' => 'refresh_token',
        ]);

        $response->getBody()->write(json_encode($tokenData));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function revoke(Request $request, Response $response): Response
    {
        $response = $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        if (!$this->rateLimiter->check('ip:' . $ipAddress, 'oauth.revoke', 60, 60)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for revoke endpoint',
                'action' => 'oauth.revoke',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        if (empty($body['token'])) {
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $auth = $this->authenticateClient($request, (array) $body);
        if (!$auth['ok']) {
            $error = (string) ($auth['error'] ?? 'invalid_client');
            $status = $error === 'unauthorized_client' ? 400 : 401;
            $response->getBody()->write(json_encode(['error' => $error]));
            return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
        }
        $client = $auth['client'];
        if (!$client->isConfidential()) {
            $response->getBody()->write(json_encode(['error' => 'unauthorized_client']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        $this->oauthService->revokeToken((string) $body['token'], $client->id);

        $audit->logSuccess('oauth.token.revoke', [
            'oauth_client_public_id' => $client->clientId,
        ]);

        return $response->withStatus(200);
    }

    public function introspect(Request $request, Response $response): Response
    {
        $response = $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        if (!$this->rateLimiter->check('ip:' . $ipAddress, 'oauth.introspect', 60, 60)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for introspect endpoint',
                'action' => 'oauth.introspect',
            ]);
            $response->getBody()->write(json_encode(['active' => false]));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        $auth = $this->authenticateClient($request, (array) $body);
        if (!$auth['ok']) {
            $response->getBody()->write(json_encode(['active' => false]));
            $status = (string) ($auth['error'] ?? 'invalid_client') === 'unauthorized_client' ? 400 : 401;
            return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
        }
        $client = $auth['client'];
        if (!$client->isConfidential()) {
            $response->getBody()->write(json_encode(['active' => false]));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        if (empty($body['token'])) {
            $response->getBody()->write(json_encode(['active' => false]));
            return $response->withHeader('Content-Type', 'application/json');
        }

        $introspection = $this->oauthService->introspectToken((string) $body['token'], $client->id);

        $audit->logInfo('oauth.token.introspect', [
            'oauth_client_public_id' => $client->clientId,
        ]);

        $response->getBody()->write(json_encode($introspection));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function authenticateClient(Request $request, array $body): array
    {
        return $this->clientAuthenticator->authenticate(
            $request->getHeaderLine('Authorization'),
            $body,
            fn(string $clientId) => $this->clientRepo->findByClientId($clientId)
        );
    }

    public function userinfo(Request $request, Response $response): Response
    {
        $response = $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        if (!$this->rateLimiter->check('ip:' . $ipAddress, 'oauth.userinfo', 120, 60)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for userinfo endpoint',
                'action' => 'oauth.userinfo',
            ]);
            $response->getBody()->write(json_encode([
                'error' => 'too_many_requests',
                'error_description' => 'Rate limit exceeded',
            ]));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        // Extract bearer token from Authorization header
        $authHeader = $request->getHeaderLine('Authorization');
        if (empty($authHeader) || !preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'Missing or invalid authorization header']);
            $response->getBody()->write(json_encode([
                'error' => 'invalid_token',
                'error_description' => 'Bearer token required'
            ]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $accessToken = $matches[1];

        // Try to parse as JWT first
        $jwtToken = $this->jwtManager->parse($accessToken);
        if ($jwtToken && $this->jwtManager->validate($jwtToken)) {
            // JWT token - extract claims
            $claims = $jwtToken->claims();
            $userUuid = $claims->get('sub');
            $scopeString = $claims->get('scope', '');
            $scopes = !empty($scopeString) ? explode(' ', $scopeString) : [];
            if (!UserInfoScopePolicy::hasOpenIdScope($scopes)) {
                $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'Missing openid scope']);
                $response->getBody()->write(json_encode([
                    'error' => 'insufficient_scope',
                    'error_description' => 'openid scope required',
                ]));
                return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
            }

            $audClaim = $claims->get('aud', null);
            $audience = null;
            if (is_string($audClaim) && $audClaim !== '') {
                $audience = $audClaim;
            } elseif (is_array($audClaim) && !empty($audClaim) && is_string($audClaim[0])) {
                $audience = $audClaim[0];
            }
            if ($audience === null) {
                $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'Missing audience claim']);
                $response->getBody()->write(json_encode([
                    'error' => 'invalid_token',
                    'error_description' => 'Token audience is missing'
                ]));
                return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
            }
            $clientStmt = Database::getInstance()->prepare(
                'SELECT id FROM oauth_clients WHERE client_id = ? AND status = ?'
            );
            $clientStmt->execute([$audience, 'active']);
            if (!$clientStmt->fetchColumn()) {
                $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'Audience client is invalid or inactive']);
                $response->getBody()->write(json_encode([
                    'error' => 'invalid_token',
                    'error_description' => 'Token audience is invalid'
                ]));
                return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
            }
            
            // Get user details from database
            $db = Database::getInstance();
            $stmt = $db->prepare('SELECT id, uuid, display_label FROM users WHERE uuid = ? AND status = ?');
            $stmt->execute([$userUuid, 'active']);
            $user = $stmt->fetch();

            $projectUuid = (string) $claims->get('project_id', '');
            $projectStmt = $db->prepare('SELECT id FROM projects WHERE uuid = ? AND status = ?');
            $projectStmt->execute([$projectUuid, 'active']);
            $project = $projectStmt->fetch();
            
            if (!$user || !$project) {
                $audit->logFail('oidc.userinfo.fail', [
                    'failure_reason' => 'User or project inactive for JWT token',
                    'user_uuid' => $userUuid,
                    'project_uuid' => $projectUuid,
                ]);
                $response->getBody()->write(json_encode([
                    'error' => 'invalid_token',
                    'error_description' => 'Token subject is inactive'
                ]));
                return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
            }
            
            // Build userinfo response from JWT claims
            $userinfo = ['sub' => $userUuid];
            
            if (in_array('profile', $scopes)) {
                $userinfo['name'] = $user['display_label'];
                $userinfo['preferred_username'] = $user['display_label'];
            }
            
            if (in_array('email', $scopes) && !empty($user['display_label'])) {
                if (filter_var($user['display_label'], FILTER_VALIDATE_EMAIL)) {
                    $userinfo['email'] = $user['display_label'];
                    $userinfo['email_verified'] = true;
                }
            }
            
            $audit->logSuccess('oidc.userinfo.success', [
                'actor_user_id' => $user['id'],
                'actor_user_uuid' => $userUuid,
                'project_uuid' => $claims->get('project_id'),
            ]);
            
            $response->getBody()->write(json_encode($userinfo));
            return $response->withHeader('Content-Type', 'application/json');
        }

        // Not a JWT or invalid JWT - try opaque token lookup
        $db = Database::getInstance();
        $stmt = $db->prepare(
            'SELECT t.*, u.uuid as user_uuid, u.display_label, p.uuid as project_uuid, p.name as project_name, c.status as client_status
             FROM oauth_access_tokens t
             JOIN users u ON t.user_id = u.id
             JOIN projects p ON t.project_id = p.id
             JOIN oauth_clients c ON c.id = t.client_id
             WHERE t.token_hash = ? AND t.revoked_at IS NULL AND t.expires_at > NOW() AND c.status = ? AND u.status = ? AND p.status = ?'
        );
        $stmt->execute([hash('sha256', $accessToken), 'active', 'active', 'active']);
        $token = $stmt->fetch();

        if (!$token) {
            $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'Invalid or expired token']);
            $response->getBody()->write(json_encode([
                'error' => 'invalid_token',
                'error_description' => 'Token is invalid or expired'
            ]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        // Build userinfo response
        $userinfo = [
            'sub' => $token['user_uuid'],
        ];

        // Add optional claims based on scopes
        $scopeList = json_decode((string) ($token['scopes'] ?? '[]'), true);
        if (!is_array($scopeList)) {
            $scopeList = [];
        }
        $scopes = array_values(array_filter(array_map('strval', $scopeList)));
        if (!UserInfoScopePolicy::hasOpenIdScope($scopes)) {
            $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'Missing openid scope']);
            $response->getBody()->write(json_encode([
                'error' => 'insufficient_scope',
                'error_description' => 'openid scope required',
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }
        
        if (in_array('profile', $scopes)) {
            $userinfo['name'] = $token['display_label'];
            $userinfo['preferred_username'] = $token['display_label'];
        }

        if (in_array('email', $scopes) && !empty($token['display_label'])) {
            // If display_label looks like an email, include it
            if (filter_var($token['display_label'], FILTER_VALIDATE_EMAIL)) {
                $userinfo['email'] = $token['display_label'];
                $userinfo['email_verified'] = true;
            }
        }

        $audit->logSuccess('oidc.userinfo.success', [
            'actor_user_id' => $token['user_id'],
            'actor_user_uuid' => $token['user_uuid'],
            'project_id' => $token['project_id'],
            'project_uuid' => $token['project_uuid'],
        ]);

        $response->getBody()->write(json_encode($userinfo));
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

    public function loginChallenge(Request $request, Response $response): Response
    {
        SessionManager::start();
        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            $response->getBody()->write(json_encode(['error' => 'Invalid CSRF token']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        if (!$this->rateLimiter->check('ip:' . $ipAddress, 'webauthn.login.oauth.challenge', 60, 300)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for OAuth login challenge',
                'action' => 'webauthn.login.oauth.challenge',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        $challenge = base64_encode(random_bytes(32));
        SessionManager::set('oauth_webauthn_challenge', [
            'value' => $challenge,
            'expires_at' => time() + self::LOGIN_CHALLENGE_TTL_SECONDS,
        ]);
        
        $response->getBody()->write(json_encode(['challenge' => $challenge]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function loginVerify(Request $request, Response $response): Response
    {
        SessionManager::start();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        /** @var AuditLogger $audit */
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        if (!$this->rateLimiter->check('ip:' . $ipAddress, 'webauthn.login.oauth.verify', 20, 300)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for OAuth login verify',
                'action' => 'webauthn.login.oauth.verify',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        $body = $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'oauth.login_verify']);
            $response->getBody()->write(json_encode(['error' => 'Invalid CSRF token']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }
        $credentialId = (string) ($body['id'] ?? '');
        $clientDataJSON = (string) ($body['response']['clientDataJSON'] ?? '');
        $authenticatorData = (string) ($body['response']['authenticatorData'] ?? '');
        $signature = (string) ($body['response']['signature'] ?? '');
        if ($credentialId === '' || $clientDataJSON === '' || $authenticatorData === '' || $signature === '') {
            $audit->logFail('oauth.login.fail', ['failure_reason' => 'Missing credential data']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        
        $webauthn = new \BlackWall\Service\WebAuthnService();
        $challengeState = SessionManager::get('oauth_webauthn_challenge');
        $expectedChallenge = is_array($challengeState)
            ? (string) ($challengeState['value'] ?? '')
            : (string) $challengeState;
        $expiresAt = is_array($challengeState)
            ? (int) ($challengeState['expires_at'] ?? 0)
            : 0;
        if ($expectedChallenge === '' || ($expiresAt > 0 && $expiresAt < time())) {
            SessionManager::remove('oauth_webauthn_challenge');
            $response->getBody()->write(json_encode(['error' => 'Session expired']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        
        // Consume challenge before verification to enforce single-use semantics.
        SessionManager::remove('oauth_webauthn_challenge');

        $verified = $webauthn->verifyAssertion(
            $credentialId,
            $clientDataJSON,
            $authenticatorData,
            $signature,
            $expectedChallenge
        );
        
        if (!$verified) {
            $audit->logFail('oauth.login.fail', ['failure_reason' => 'Assertion verification failed']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        
        // Preserve auth request across session ID regeneration
        $authRequest = SessionManager::get('oauth_auth_request');

        $credential = $webauthn->getCredentialById($credentialId);
        if (!$credential || !isset($credential['user_id'])) {
            $audit->logFail('oauth.login.fail', ['failure_reason' => 'Credential not found']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        $userId = (int) $credential['user_id'];
        SessionManager::set('user_id', $userId);
        SessionManager::regenerateId();

        // Restore auth request if it existed
        if ($authRequest) {
            SessionManager::set('oauth_auth_request', $authRequest);
        }

        $returnUrl = '/oauth/authorize?' . http_build_query($authRequest);
        
        $audit->logSuccess('oauth.login.success', [
            'actor_user_id' => $userId,
            'webauthn_credential_public_id' => $credentialId,
        ]);

        $response->getBody()->write(json_encode(['success' => true, 'redirect' => $returnUrl]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
