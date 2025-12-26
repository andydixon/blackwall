<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Database;
use BlackWall\Config;
use BlackWall\Repository\OrganizationRepository;
use BlackWall\Repository\UserRepository;
use BlackWall\Security\EnrollmentTokenExpiryValidator;
use BlackWall\Security\RateLimiter;
use BlackWall\Security\SessionManager;
use BlackWall\Service\WebAuthnService;
use BlackWall\Service\AuditLogger;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;
use Ramsey\Uuid\Uuid;

class BootstrapController
{
    private WebAuthnService $webauthn;
    private OrganizationRepository $organizationRepo;
    private UserRepository $userRepo;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->webauthn = new WebAuthnService();
        $this->organizationRepo = new OrganizationRepository();
        $this->userRepo = new UserRepository();
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
    }

    public function organizationSignupForm(Request $request, Response $response): Response
    {
        return $this->renderer->render($response, 'organizations/signup.php', [
            'csrfToken' => \BlackWall\Security\CSRFProtection::generateToken(),
        ]);
    }

    public function organizationSignup(Request $request, Response $response): Response
    {
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $limiter = new RateLimiter();
        if (!$limiter->check('ip:' . $ipAddress, 'organization.signup', 5, 3600)) {
            return $response->withHeader('Location', '/organisations/signup?error=rate_limited')->withStatus(302);
        }

        $body = $request->getParsedBody();
        if (!\BlackWall\Security\CSRFProtection::validateToken((string) ($body['csrf_token'] ?? ''))) {
            return $response->withHeader('Location', '/organisations/signup?error=csrf')->withStatus(302);
        }

        $name = trim((string) ($body['name'] ?? ''));
        $slug = trim((string) ($body['slug'] ?? ''));
        $adminLabel = trim((string) ($body['admin_display_label'] ?? ''));
        if ($name === '' || $slug === '' || $adminLabel === '') {
            return $response->withHeader('Location', '/organisations/signup?error=invalid')->withStatus(302);
        }
        if (!preg_match('/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/', $slug)) {
            return $response->withHeader('Location', '/organisations/signup?error=slug')->withStatus(302);
        }

        try {
            $organization = $this->organizationRepo->create(Uuid::uuid4()->toString(), $name, $slug, null, null);
        } catch (\Throwable $e) {
            return $response->withHeader('Location', '/organisations/signup?error=duplicate')->withStatus(302);
        }

        $adminUser = $this->userRepo->create($organization->id, Uuid::uuid4()->toString(), $adminLabel, 'active');
        $this->organizationRepo->setAdminUser($organization->id, $adminUser->id);

        $db = Database::getInstance();
        $token = bin2hex(random_bytes(32));
        $expiry = (new \DateTimeImmutable('+24 hours'))->format('Y-m-d H:i:s');
        $stmt = $db->prepare(
            "INSERT INTO system_config (config_key, config_value)
             VALUES (?, ?)
             ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)"
        );
        $stmt->execute(['enrollment_token_' . $token, (string) $adminUser->id]);
        $stmt->execute(['enrollment_expiry_' . $token, $expiry]);
        $enrollmentLink = rtrim((string) Config::get('APP_URL'), '/') . '/enroll?token=' . urlencode($token);

        return $this->renderer->render($response, 'organizations/signup.php', [
            'csrfToken' => \BlackWall\Security\CSRFProtection::generateToken(),
            'success' => true,
            'enrollmentLink' => $enrollmentLink,
            'organizationName' => $organization->name,
        ]);
    }

    public function showBootstrapForm(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $limiter = new RateLimiter();
        if (!$limiter->check('ip:' . $ipAddress, 'bootstrap.token.verify', 20, 900)) {
            $response->getBody()->write('Too many requests');
            return $response->withStatus(429);
        }
        
        // Check if bootstrap is complete
        $stmt = $db->query("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_complete'");
        $row = $stmt->fetch();
        
        if ($row && $row['config_value'] === '1') {
            $response->getBody()->write('Bootstrap already complete. Please login at /admin/login');
            return $response->withStatus(403);
        }

        $params = $request->getQueryParams();
        $token = $params['token'] ?? null;

        if (!$token) {
            $response->getBody()->write('Invalid bootstrap token');
            return $response->withStatus(400);
        }
        if (!$this->isValidEnrollmentToken((string) $token)) {
            $response->getBody()->write('Invalid bootstrap token');
            return $response->withStatus(400);
        }

        // Verify token
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_token'");
        $stmt->execute();
        $storedToken = $stmt->fetch();

        if (!$storedToken || $storedToken['config_value'] !== $token) {
            $response->getBody()->write('Invalid or expired bootstrap token');
            return $response->withStatus(400);
        }

        // Check expiry
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_expiry'");
        $stmt->execute();
        $expiry = $stmt->fetch();

        if (!$expiry || !EnrollmentTokenExpiryValidator::isValid((string) ($expiry['config_value'] ?? null))) {
            $response->getBody()->write('Bootstrap token expired');
            return $response->withStatus(400);
        }

        // Get user ID
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_user_id'");
        $stmt->execute();
        $userIdRow = $stmt->fetch();
        $userId = $userIdRow ? (int) $userIdRow['config_value'] : null;

        if (!$userId) {
            $response->getBody()->write('Bootstrap user not found');
            return $response->withStatus(400);
        }

        // Generate WebAuthn registration options
        $stmt = $db->prepare(
            "SELECT u.uuid, u.display_label, o.name AS organization_name, o.logo_url AS organization_logo_url
             FROM users u
             LEFT JOIN organizations o ON o.id = u.organization_id
             WHERE u.id = ?"
        );
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $options = $this->webauthn->generateRegistrationOptions($user['uuid'], $user['display_label'] ?? 'Admin');
        SessionManager::set('bootstrap_registration_context', [
            'token' => (string) $token,
            'user_id' => (int) $userId,
            'challenge' => (string) $options['challenge'],
        ]);

        return $this->renderer->render($response, 'bootstrap/enroll.php', [
            'token' => $token,
            'options' => $options,
            'user' => $user,
            'organization' => [
                'name' => $user['organization_name'] ?? null,
                'logo_url' => $user['organization_logo_url'] ?? null,
            ],
        ]);
    }

    public function enrollWebAuthn(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $limiter = new RateLimiter();
        if (!$limiter->check('ip:' . $ipAddress, 'bootstrap.token.verify', 20, 900)) {
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        // Verify token
        $token = $body['token'] ?? null;
        if (!$token) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Missing token']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        if (!$this->isValidEnrollmentToken((string) $token)) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid token format']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_token'");
        $stmt->execute();
        $storedToken = $stmt->fetch();

        if (!$storedToken || $storedToken['config_value'] !== $token) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid token']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_expiry'");
        $stmt->execute();
        $expiry = $stmt->fetch();
        if (!$expiry || !EnrollmentTokenExpiryValidator::isValid((string) ($expiry['config_value'] ?? null))) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Bootstrap token expired']);
            $response->getBody()->write(json_encode(['error' => 'Token expired']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Get user ID
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_user_id'");
        $stmt->execute();
        $userIdRow = $stmt->fetch();
        $userId = $userIdRow ? (int) $userIdRow['config_value'] : null;

        if (!$userId) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'User not found']);
            $response->getBody()->write(json_encode(['error' => 'User not found']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $registrationContext = (array) SessionManager::get('bootstrap_registration_context', []);
        SessionManager::remove('bootstrap_registration_context');
        $expectedChallenge = (string) ($registrationContext['challenge'] ?? '');
        $contextToken = (string) ($registrationContext['token'] ?? '');
        $contextUserId = (int) ($registrationContext['user_id'] ?? 0);

        // Extract credential data from WebAuthn response
        $credentialId = $body['id'] ?? null;
        $rawId = $body['rawId'] ?? null;
        $attestationObject = $body['response']['attestationObject'] ?? null;
        $clientDataJSON = $body['response']['clientDataJSON'] ?? null;

        if (!$credentialId || !$rawId || !$attestationObject || !$clientDataJSON) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid credential data']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential data']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        if (
            $expectedChallenge === ''
            || $contextToken === ''
            || !hash_equals($contextToken, (string) $token)
            || $contextUserId !== (int) $userId
            || !$this->webauthn->verifyRegistrationResponse((string) $clientDataJSON, $expectedChallenge)
        ) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Registration challenge or origin validation failed']);
            $response->getBody()->write(json_encode(['error' => 'Invalid registration response']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Extract the public key from the attestation object
        $publicKey = $this->webauthn->extractPublicKeyFromAttestation($attestationObject);
        if (!$publicKey) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Failed to extract public key']);
            $response->getBody()->write(json_encode(['error' => 'Invalid attestation']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Store the credential with the extracted public key
        $credentialData = [
            'credential_id' => $credentialId,
            'public_key' => $publicKey,
            'sign_counter' => 0,
            'attestation_type' => 'none',
        ];

        $credentialDbId = $this->webauthn->storeCredential($userId, $credentialData, 'Bootstrap Key');

        $audit->logSuccess('webauthn.registration.success', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credentialDbId,
            'webauthn_credential_public_id' => $credentialId,
        ]);

        // Mark bootstrap as complete
        $stmt = $db->prepare(
            "INSERT INTO system_config (config_key, config_value) VALUES ('bootstrap_complete', '1') 
            ON DUPLICATE KEY UPDATE config_value = '1'"
        );
        $stmt->execute();

        // Delete bootstrap tokens
        $db->exec("DELETE FROM system_config WHERE config_key IN ('bootstrap_token', 'bootstrap_expiry', 'bootstrap_user_id')");

        $response->getBody()->write(json_encode(['success' => true, 'redirect' => '/admin/login']));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function showEnrollmentForm(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $limiter = new RateLimiter();
        if (!$limiter->check('ip:' . $ipAddress, 'enrollment.token.verify', 20, 900)) {
            $response->getBody()->write('Too many requests');
            return $response->withStatus(429);
        }
        
        $params = $request->getQueryParams();
        $token = $params['token'] ?? null;

        if (!$token) {
            $response->getBody()->write('Invalid enrollment link');
            return $response->withStatus(400);
        }
        if (!$this->isValidEnrollmentToken((string) $token)) {
            $response->getBody()->write('Invalid enrollment link');
            return $response->withStatus(400);
        }

        // Look up user_id from token
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = ?");
        $stmt->execute(['enrollment_token_' . $token]);
        $userIdRow = $stmt->fetch();

        if (!$userIdRow) {
            $response->getBody()->write('Invalid or expired enrollment token');
            return $response->withStatus(400);
        }

        $userId = (int) $userIdRow['config_value'];

        // Check expiry
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = ?");
        $stmt->execute(['enrollment_expiry_' . $token]);
        $expiry = $stmt->fetch();

        if (!$expiry || !EnrollmentTokenExpiryValidator::isValid((string) ($expiry['config_value'] ?? null))) {
            $response->getBody()->write('Enrollment token expired');
            return $response->withStatus(400);
        }

        // Get user info
        $stmt = $db->prepare(
            "SELECT u.uuid, u.display_label, o.name AS organization_name, o.logo_url AS organization_logo_url
             FROM users u
             LEFT JOIN organizations o ON o.id = u.organization_id
             WHERE u.id = ?"
        );
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            $response->getBody()->write('User not found');
            return $response->withStatus(400);
        }

        // Generate WebAuthn registration options
        $options = $this->webauthn->generateRegistrationOptions($user['uuid'], $user['display_label'] ?? 'User');
        SessionManager::set('enrollment_registration_context', [
            'token' => (string) $token,
            'user_id' => (int) $userId,
            'challenge' => (string) $options['challenge'],
        ]);

        return $this->renderer->render($response, 'enroll.php', [
            'token' => $token,
            'options' => $options,
            'user' => $user,
            'organization' => [
                'name' => $user['organization_name'] ?? null,
                'logo_url' => $user['organization_logo_url'] ?? null,
            ],
        ]);
    }

    public function enrollKey(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
        $ipAddress = (string) $request->getAttribute('ip_address', '0.0.0.0');
        $limiter = new RateLimiter();
        if (!$limiter->check('ip:' . $ipAddress, 'enrollment.token.verify', 20, 900)) {
            $response->getBody()->write(json_encode(['error' => 'too_many_requests']));
            return $response->withStatus(429)->withHeader('Content-Type', 'application/json');
        }
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        // Get token
        $token = $body['token'] ?? null;
        
        if (!$token) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Missing token']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        if (!$this->isValidEnrollmentToken((string) $token)) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid token format']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Look up user_id from token
        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = ?");
        $stmt->execute(['enrollment_token_' . $token]);
        $userIdRow = $stmt->fetch();

        if (!$userIdRow) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid token']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $userId = (int) $userIdRow['config_value'];

        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = ?");
        $stmt->execute(['enrollment_expiry_' . $token]);
        $expiry = $stmt->fetch();
        if (!$expiry || !EnrollmentTokenExpiryValidator::isValid((string) ($expiry['config_value'] ?? null))) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Enrollment token expired']);
            $response->getBody()->write(json_encode(['error' => 'Token expired']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $registrationContext = (array) SessionManager::get('enrollment_registration_context', []);
        SessionManager::remove('enrollment_registration_context');
        $expectedChallenge = (string) ($registrationContext['challenge'] ?? '');
        $contextToken = (string) ($registrationContext['token'] ?? '');
        $contextUserId = (int) ($registrationContext['user_id'] ?? 0);

        // Extract credential data from WebAuthn response
        $credentialId = $body['id'] ?? null;
        $rawId = $body['rawId'] ?? null;
        $attestationObject = $body['response']['attestationObject'] ?? null;
        $clientDataJSON = $body['response']['clientDataJSON'] ?? null;

        if (!$credentialId || !$rawId || !$attestationObject || !$clientDataJSON) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid credential data']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential data']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        if (
            $expectedChallenge === ''
            || $contextToken === ''
            || !hash_equals($contextToken, (string) $token)
            || $contextUserId !== (int) $userId
            || !$this->webauthn->verifyRegistrationResponse((string) $clientDataJSON, $expectedChallenge)
        ) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Registration challenge or origin validation failed']);
            $response->getBody()->write(json_encode(['error' => 'Invalid registration response']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Extract the public key from the attestation object
        $publicKey = $this->webauthn->extractPublicKeyFromAttestation($attestationObject);
        if (!$publicKey) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Failed to extract public key']);
            $response->getBody()->write(json_encode(['error' => 'Invalid attestation']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Store the credential with the extracted public key
        $credentialData = [
            'credential_id' => $credentialId,
            'public_key' => $publicKey,
            'sign_counter' => 0,
            'attestation_type' => 'none',
        ];

        $credentialDbId = $this->webauthn->storeCredential($userId, $credentialData, 'Enrolled Key');

        $audit->logSuccess('webauthn.registration.success', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credentialDbId,
            'webauthn_credential_public_id' => $credentialId,
        ]);

        // Delete enrollment tokens
        $deleteStmt = $db->prepare("DELETE FROM system_config WHERE config_key IN (?, ?)");
        $deleteStmt->execute([
            'enrollment_token_' . $token,
            'enrollment_expiry_' . $token,
        ]);

        // Determine redirect based on whether this was admin enrollment or portal
        $redirectUrl = '/portal/login';

        $response->getBody()->write(json_encode(['success' => true, 'redirect' => $redirectUrl]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function isValidEnrollmentToken(string $token): bool
    {
        return (bool) preg_match('/^[a-f0-9]{64}$/', $token);
    }
}
