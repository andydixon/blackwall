<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Database;
use BlackWall\Domain\PrivilegeLabelResolver;
use BlackWall\Config;
use BlackWall\Service\WebAuthnService;
use BlackWall\Service\AuditLogger;
use BlackWall\Security\RateLimiter;
use BlackWall\Security\SessionManager;
use BlackWall\Security\CSRFProtection;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;

class PortalController
{
    private const LOGIN_CHALLENGE_TTL_SECONDS = 120;

    private WebAuthnService $webauthn;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->webauthn = new WebAuthnService();
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
    }

    private function renderWithLayout(Response $response, string $template, array $data = []): Response
    {
        $contentRenderer = new PhpRenderer(__DIR__ . '/../../templates');
        $contentResponse = $contentRenderer->render(new \Slim\Psr7\Response(), $template, $data);
        $content = (string) $contentResponse->getBody();
        
        $data['content'] = $content;
        return $this->renderer->render($response, '_layout.php', $data);
    }

    private function checkAuth(): bool
    {
        SessionManager::start();
        $userId = (int) SessionManager::get('user_id');
        if ($userId < 1) {
            return false;
        }

        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$userId]);
        return (bool) $stmt->fetchColumn();
    }

    public function loginForm(Request $request, Response $response): Response
    {
        return $this->renderer->render($response, 'portal/login.php', [
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function loginChallenge(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            $response->getBody()->write(json_encode(['error' => 'Invalid CSRF token']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $rateLimiter = new RateLimiter();
        if (!$rateLimiter->check('ip:' . $ipAddress, 'webauthn.login.portal.challenge', 60, 300)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for portal login challenge',
                'action' => 'webauthn.login.portal.challenge',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }

        $challenge = random_bytes(32);
        
        SessionManager::start();
        SessionManager::set('portal_webauthn_challenge', [
            'value' => base64_encode($challenge),
            'expires_at' => time() + self::LOGIN_CHALLENGE_TTL_SECONDS,
        ]);

        $options = [
            'challenge' => base64_encode($challenge),
            'timeout' => 60000,
            'rpId' => \BlackWall\Config::get('WEBAUTHN_RP_ID'),
            'userVerification' => 'required',
        ];

        $response->getBody()->write(json_encode($options));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function loginVerify(Request $request, Response $response): Response
    {
        SessionManager::start();
        
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'portal.login_verify']);
            $response->getBody()->write(json_encode(['error' => 'Invalid CSRF token']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $rateLimiter = new RateLimiter();
        if (!$rateLimiter->check('ip:' . $ipAddress, 'webauthn.login.portal.verify', 20, 300)) {
            $audit->logFail('security.ratelimit.hit', [
                'message' => 'Rate limit exceeded for portal login verify',
                'action' => 'webauthn.login.portal.verify',
            ]);
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }
        
        $credentialId = $body['id'] ?? null;
        $rawId = $body['rawId'] ?? null;
        $authenticatorData = $body['response']['authenticatorData'] ?? null;
        $clientDataJSON = $body['response']['clientDataJSON'] ?? null;
        $signature = $body['response']['signature'] ?? null;

        if (!$credentialId || !$rawId || !$authenticatorData || !$clientDataJSON || !$signature) {
            $audit->logFail('portal.login.fail', ['failure_reason' => 'Missing credential data']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $credential = $this->webauthn->getCredentialById($credentialId);
        if (!$credential) {
            $audit->logFail('portal.login.fail', [
                'failure_reason' => 'Credential not found',
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $challengeState = SessionManager::get('portal_webauthn_challenge');
        $expectedChallenge = is_array($challengeState)
            ? (string) ($challengeState['value'] ?? '')
            : (string) $challengeState;
        $expiresAt = is_array($challengeState)
            ? (int) ($challengeState['expires_at'] ?? 0)
            : 0;
        if ($expectedChallenge === '' || ($expiresAt > 0 && $expiresAt < time())) {
            SessionManager::remove('portal_webauthn_challenge');
            $audit->logFail('portal.login.fail', [
                'failure_reason' => 'Challenge missing or expired',
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Session expired']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Consume challenge before verification to enforce single-use semantics.
        SessionManager::remove('portal_webauthn_challenge');

        $verified = $this->webauthn->verifyAssertion(
            $credentialId,
            $clientDataJSON,
            $authenticatorData,
            $signature,
            $expectedChallenge
        );

        if (!$verified) {
            $audit->logFail('portal.login.fail', [
                'failure_reason' => 'Signature verification failed',
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $userId = (int) $credential['user_id'];
        $db = Database::getInstance();
        $statusStmt = $db->prepare("SELECT status FROM users WHERE id = ? LIMIT 1");
        $statusStmt->execute([$userId]);
        $userStatus = (string) ($statusStmt->fetchColumn() ?: '');
        if ($userStatus !== 'active') {
            $audit->logFail('portal.login.fail', [
                'failure_reason' => 'User account inactive',
                'actor_user_id' => $userId,
                'webauthn_credential_id' => $credential['id'],
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        SessionManager::set('user_id', $userId);
        SessionManager::set('login_credential_id', $credential['id']);
        SessionManager::regenerateId();

        $audit->logSuccess('portal.login.success', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credential['id'],
            'webauthn_credential_public_id' => $credentialId,
        ]);

        // Check for OAuth return URL
        $returnTo = SessionManager::get('oauth_return_to') ?: '/portal';
        SessionManager::remove('oauth_return_to');

        $response->getBody()->write(json_encode(['success' => true, 'redirect' => $returnTo]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function dashboard(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/portal/login')->withStatus(302);
        }

        $userId = SessionManager::get('user_id');
        $loginCredentialId = SessionManager::get('login_credential_id');
        $db = Database::getInstance();

        // Get user info
        $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        // Get user's projects with privilege levels
        $stmt = $db->prepare(
            'SELECT p.*, upr.privilege_level, upr.id as assignment_id, ppl.name AS privilege_name
             FROM projects p
             JOIN user_project_roles upr ON p.id = upr.project_id
             LEFT JOIN project_privilege_levels ppl
                ON ppl.project_id = upr.project_id
               AND ppl.level = upr.privilege_level
             WHERE upr.user_id = ?
             ORDER BY p.name'
        );
        $stmt->execute([$userId]);
        $projects = $stmt->fetchAll();
        foreach ($projects as &$project) {
            $project['privilege_label'] = PrivilegeLabelResolver::resolve(
                (int) $project['privilege_level'],
                $project['privilege_name'] ?? null
            );
        }
        unset($project);

        // Get user's WebAuthn credentials
        $stmt = $db->prepare(
            'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC'
        );
        $stmt->execute([$userId]);
        $credentials = $stmt->fetchAll();

        return $this->renderWithLayout($response, 'portal/dashboard.php', [
            'title' => 'Portal',
            'user' => $user,
            'projects' => $projects,
            'credentials' => $credentials,
            'loginCredentialId' => $loginCredentialId,
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function addKeyInit(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            $response->getBody()->write(json_encode(['error' => 'Invalid CSRF token']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $userId = SessionManager::get('user_id');
        $db = Database::getInstance();

        $stmt = $db->prepare('SELECT uuid, display_label FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $options = $this->webauthn->generateRegistrationOptions($user['uuid'], $user['display_label'] ?? 'User');

        SessionManager::set('portal_registration_challenge', $options['challenge']);

        $response->getBody()->write(json_encode($options));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function addKeyComplete(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');
        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'portal.add_key_complete']);
            $response->getBody()->write(json_encode(['error' => 'Invalid CSRF token']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $credentialId = $body['id'] ?? null;
        $attestationObject = $body['response']['attestationObject'] ?? null;
        $clientDataJSON = $body['response']['clientDataJSON'] ?? null;
        $label = $body['label'] ?? 'Unnamed Key';

        if (!$credentialId || !$attestationObject || !$clientDataJSON) {
            $response->getBody()->write(json_encode(['error' => 'Invalid credential data']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $expectedChallenge = (string) SessionManager::get('portal_registration_challenge', '');
        SessionManager::remove('portal_registration_challenge');
        if ($expectedChallenge === '' || !$this->webauthn->verifyRegistrationResponse((string) $clientDataJSON, $expectedChallenge)) {
            $audit->logFail('webauthn.registration.fail', [
                'failure_reason' => 'Registration challenge or origin validation failed',
                'actor_user_id' => $userId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Invalid registration response']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $publicKey = $this->webauthn->extractPublicKeyFromAttestation($attestationObject);
        if (!$publicKey) {
            $response->getBody()->write(json_encode(['error' => 'Failed to extract public key']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $credentialData = [
            'credential_id' => $credentialId,
            'public_key' => $publicKey,
            'sign_counter' => 0,
            'attestation_type' => 'none',
        ];

        $credentialDbId = $this->webauthn->storeCredential($userId, $credentialData, $label);

        $audit->logSuccess('portal.key.add', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credentialDbId,
        ]);

        $response->getBody()->write(json_encode(['success' => true]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function deleteKey(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/portal/login')->withStatus(302);
        }

        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            return $response->withHeader('Location', '/portal?error=csrf')->withStatus(302);
        }

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');
        $loginCredentialId = SessionManager::get('login_credential_id');
        $credentialPublicId = (string) ($args['credentialPublicId'] ?? '');
        if ($credentialPublicId === '') {
            return $response->withHeader('Location', '/portal?error=invalid_key')->withStatus(302);
        }

        // Prevent deleting the credential used to log in
        // Verify the credential belongs to this user and fetch DB id for FK-safe checks.
        $db = Database::getInstance();
        $stmt = $db->prepare('SELECT id, user_id FROM webauthn_credentials WHERE credential_id = ?');
        $stmt->execute([$credentialPublicId]);
        $credential = $stmt->fetch();

        if (!$credential || (int) $credential['user_id'] !== (int) $userId) {
            return $response->withHeader('Location', '/portal?error=unauthorized')->withStatus(302);
        }

        $credentialId = (int) $credential['id'];

        $minKeys = max(1, Config::getInt('MIN_WEBAUTHN_KEYS', 1));
        $countStmt = $db->prepare('SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?');
        $countStmt->execute([$userId]);
        $currentKeyCount = (int) $countStmt->fetchColumn();
        if ($currentKeyCount <= $minKeys) {
            return $response->withHeader('Location', '/portal?error=min_keys')->withStatus(302);
        }

        if ($credentialId === (int) $loginCredentialId) {
            return $response->withHeader('Location', '/portal?error=cannot_delete_current_key')->withStatus(302);
        }

        $audit->logSuccess('portal.key.delete', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credentialId,
            'webauthn_credential_public_id' => $credentialPublicId,
        ]);

        $this->webauthn->deleteCredential($credentialId);

        return $response->withHeader('Location', '/portal?success=key_deleted')->withStatus(302);
    }

    public function logout(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        if (!CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            return $response->withHeader('Location', '/portal?error=csrf')->withStatus(302);
        }

        SessionManager::destroy();
        return $response->withHeader('Location', '/portal/login')->withStatus(302);
    }
}
