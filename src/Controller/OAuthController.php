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
use BlackWall\Security\RateLimiter;
use BlackWall\Security\TokenHasher;
use BlackWall\Database;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;

class OAuthController
{
    private OAuthClientRepository $clientRepo;
    private ProjectRepository $projectRepo;
    private UserProjectRoleRepository $roleRepo;
    private OrganizationRepository $organizationRepo;
    private PrivilegeLevelRepository $privilegeRepo;
    private OAuthService $oauthService;
    private JWTManager $jwtManager;
    private RateLimiter $rateLimiter;
    private OAuthClientAuthenticator $clientAuthenticator;
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
        $requiredParams = ['client_id', 'redirect_uri', 'response_type', 'code_challenge'];
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
        // Always store the authorization request for later use
        SessionManager::set('oauth_auth_request', $params);
        if (!$userId) {
            // Show OAuth login page
            return $this->renderer->render($response, 'oauth/login.php', [
                'clientName' => $client->name,
                'returnUrl' => $params['redirect_uri'],
                'organization' => $this->organizationRepo->findById($project->organizationId),
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
        if (!$params) {
            return $this->errorResponse($response, 'invalid_request', 'No authorization request found');
        }

        $userId = SessionManager::get('user_id');
        if (!$userId) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $client = $this->clientRepo->findByClientId($params['client_id']);
        $project = $this->projectRepo->findById($client->projectId);

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

        $auth = $this->authenticateClient($request, (array) $body);
        if (!$auth['ok']) {
            $audit->logFail('oauth.token.fail', ['error_code' => 'invalid_client']);
            $response->getBody()->write(json_encode(['error' => 'invalid_client']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
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

    public function revoke(Request $request, Response $response): Response
    {
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        if (empty($body['token'])) {
            $response->getBody()->write(json_encode(['error' => 'invalid_request']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $auth = $this->authenticateClient($request, (array) $body);
        if (!$auth['ok']) {
            $response->getBody()->write(json_encode(['error' => 'invalid_client']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
        $client = $auth['client'];
        $this->oauthService->revokeToken((string) $body['token'], $client->id);

        $audit->logSuccess('oauth.token.revoke', [
            'oauth_client_public_id' => $client->clientId,
        ]);

        return $response->withStatus(200);
    }

    public function introspect(Request $request, Response $response): Response
    {
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        $auth = $this->authenticateClient($request, (array) $body);
        if (!$auth['ok']) {
            $response->getBody()->write(json_encode(['active' => false]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
        $client = $auth['client'];

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
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

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
        error_log("JWT parse result: " . ($jwtToken ? "success" : "null"));
        if ($jwtToken) {
            $isValid = $this->jwtManager->validate($jwtToken);
            error_log("JWT validation result: " . ($isValid ? "valid" : "invalid"));
        }
        if ($jwtToken && $this->jwtManager->validate($jwtToken)) {
            // JWT token - extract claims
            $claims = $jwtToken->claims();
            $userUuid = $claims->get('sub');
            $scopeString = $claims->get('scope', '');
            $scopes = !empty($scopeString) ? explode(' ', $scopeString) : [];
            
            // Get user details from database
            $db = Database::getInstance();
            $stmt = $db->prepare('SELECT id, uuid, display_label FROM users WHERE uuid = ?');
            $stmt->execute([$userUuid]);
            $user = $stmt->fetch();
            
            if (!$user) {
                $audit->logFail('oidc.userinfo.fail', ['failure_reason' => 'User not found for JWT token', 'user_uuid' => $userUuid]);
                $response->getBody()->write(json_encode([
                    'error' => 'invalid_token',
                    'error_description' => 'Token user not found'
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
            'SELECT t.*, u.uuid as user_uuid, u.display_label, p.uuid as project_uuid, p.name as project_name
             FROM oauth_access_tokens t
             JOIN users u ON t.user_id = u.id
             JOIN projects p ON t.project_id = p.id
             WHERE t.token_hash = ? AND t.revoked_at IS NULL AND t.expires_at > NOW()'
        );
        $stmt->execute([hash('sha256', $accessToken)]);
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
        $scopes = explode(' ', $token['scopes']);
        
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
        $challenge = base64_encode(random_bytes(32));
        SessionManager::set('oauth_webauthn_challenge', $challenge);
        
        $response->getBody()->write(json_encode(['challenge' => $challenge]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function loginVerify(Request $request, Response $response): Response
    {
        SessionManager::start();
        $body = $request->getParsedBody();
        
        $webauthn = new \BlackWall\Service\WebAuthnService();
        $expectedChallenge = SessionManager::get('oauth_webauthn_challenge');
        
        if (!$expectedChallenge) {
            $response->getBody()->write(json_encode(['error' => 'Session expired']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        
        $verified = $webauthn->verifyAssertion(
            $body['id'],
            $body['response']['clientDataJSON'],
            $body['response']['authenticatorData'],
            $body['response']['signature'],
            $expectedChallenge
        );
        
        if (!$verified) {
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        
        SessionManager::remove('oauth_webauthn_challenge');
        
        // Preserve auth request across session ID regeneration
        $authRequest = SessionManager::get('oauth_auth_request');

        $credential = $webauthn->getCredentialById($body['id']);
        $userId = (int) $credential['user_id'];
        SessionManager::set('user_id', $userId);
        SessionManager::regenerateId();

        // Restore auth request if it existed
        if ($authRequest) {
            SessionManager::set('oauth_auth_request', $authRequest);
        }

        $returnUrl = '/oauth/authorize?' . http_build_query($authRequest);
        
        $response->getBody()->write(json_encode(['success' => true, 'redirect' => $returnUrl]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
