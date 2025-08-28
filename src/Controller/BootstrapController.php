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

        // Store credential (simplified - real implementation would verify attestation)
        $credentialData = [
            'credential_id' => $body['credential_id'] ?? bin2hex(random_bytes(32)),
            'public_key' => $body['public_key'] ?? 'PLACEHOLDER',
            'sign_counter' => 0,
        ];

        $credentialId = $this->webauthn->storeCredential($userId, $credentialData, 'Bootstrap Key');

        $audit->logSuccess('webauthn.registration.success', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credentialId,
            'webauthn_credential_public_id' => $credentialData['credential_id'],
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
}
