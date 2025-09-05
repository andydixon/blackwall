<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Database;
use BlackWall\Service\WebAuthnService;
use BlackWall\Service\AuditLogger;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;

class BootstrapController
{
    private WebAuthnService $webauthn;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->webauthn = new WebAuthnService();
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
    }

    public function showBootstrapForm(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
        
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

        if ($expiry && new \DateTimeImmutable($expiry['config_value']) < new \DateTimeImmutable()) {
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
        $stmt = $db->prepare("SELECT uuid, display_label FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $options = $this->webauthn->generateRegistrationOptions($user['uuid'], $user['display_label'] ?? 'Admin');

        return $this->renderer->render($response, 'bootstrap/enroll.php', [
            'token' => $token,
            'options' => $options,
            'user' => $user,
        ]);
    }

    public function enrollWebAuthn(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
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

        $stmt = $db->prepare("SELECT config_value FROM system_config WHERE config_key = 'bootstrap_token'");
        $stmt->execute();
        $storedToken = $stmt->fetch();

        if (!$storedToken || $storedToken['config_value'] !== $token) {
            $audit->logFail('webauthn.registration.fail', ['failure_reason' => 'Invalid token']);
            $response->getBody()->write(json_encode(['error' => 'Invalid token']));
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
        
        $params = $request->getQueryParams();
        $token = $params['token'] ?? null;

        if (!$token) {
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

        if ($expiry && new \DateTimeImmutable($expiry['config_value']) < new \DateTimeImmutable()) {
            $response->getBody()->write('Enrollment token expired');
            return $response->withStatus(400);
        }

        // Get user info
        $stmt = $db->prepare("SELECT uuid, display_label FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            $response->getBody()->write('User not found');
            return $response->withStatus(400);
        }

        // Generate WebAuthn registration options
        $options = $this->webauthn->generateRegistrationOptions($user['uuid'], $user['display_label'] ?? 'User');

        return $this->renderer->render($response, 'enroll.php', [
            'token' => $token,
            'options' => $options,
            'user' => $user,
        ]);
    }

    public function enrollKey(Request $request, Response $response): Response
    {
        $db = Database::getInstance();
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
        $db->exec("DELETE FROM system_config WHERE config_key IN ('enrollment_token_{$token}', 'enrollment_expiry_{$token}')");

        // Determine redirect based on whether this was admin enrollment or portal
        $redirectUrl = '/portal/login';

        $response->getBody()->write(json_encode(['success' => true, 'redirect' => $redirectUrl]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
