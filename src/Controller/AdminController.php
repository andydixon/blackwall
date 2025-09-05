<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Repository\UserRepository;
use BlackWall\Repository\ProjectRepository;
use BlackWall\Repository\OAuthClientRepository;
use BlackWall\Repository\PrivilegeLevelRepository;
use BlackWall\Repository\UserProjectRoleRepository;
use BlackWall\Service\AuditLogger;
use BlackWall\Service\WebAuthnService;
use BlackWall\Security\SessionManager;
use BlackWall\Security\CSRFProtection;
use BlackWall\Security\TokenHasher;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;
use Ramsey\Uuid\Uuid;

class AdminController
{
    private UserRepository $userRepo;
    private ProjectRepository $projectRepo;
    private OAuthClientRepository $clientRepo;
    private PrivilegeLevelRepository $privilegeRepo;
    private UserProjectRoleRepository $roleRepo;
    private WebAuthnService $webauthn;
    private TokenHasher $hasher;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->userRepo = new UserRepository();
        $this->projectRepo = new ProjectRepository();
        $this->clientRepo = new OAuthClientRepository();
        $this->privilegeRepo = new PrivilegeLevelRepository();
        $this->roleRepo = new UserProjectRoleRepository();
        $this->webauthn = new WebAuthnService();
        $this->hasher = new TokenHasher();
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
    }

    private function renderWithLayout(Response $response, string $template, array $data = []): Response
    {
        // Render the content template
        $contentRenderer = new PhpRenderer(__DIR__ . '/../../templates');
        $contentResponse = $contentRenderer->render(new \Slim\Psr7\Response(), $template, $data);
        $content = (string) $contentResponse->getBody();
        
        // Render with layout
        $data['content'] = $content;
        return $this->renderer->render($response, '_layout.php', $data);
    }

    public function loginForm(Request $request, Response $response): Response
    {
        return $this->renderer->render($response, 'admin/login.php', [
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function loginChallenge(Request $request, Response $response): Response
    {
        $challenge = random_bytes(32);
        
        SessionManager::start();
        SessionManager::set('webauthn_challenge', base64_encode($challenge));

        $options = [
            'challenge' => base64_encode($challenge),
            'timeout' => 60000,
            'rpId' => \BlackWall\Config::get('WEBAUTHN_RP_ID'),
            'userVerification' => 'preferred',
        ];

        $response->getBody()->write(json_encode($options));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function loginVerify(Request $request, Response $response): Response
    {
        SessionManager::start();
        
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        
        $body = $request->getParsedBody();
        $credentialId = $body['id'] ?? null;
        $rawId = $body['rawId'] ?? null;
        $authenticatorData = $body['response']['authenticatorData'] ?? null;
        $clientDataJSON = $body['response']['clientDataJSON'] ?? null;
        $signature = $body['response']['signature'] ?? null;

        if (!$credentialId || !$rawId || !$authenticatorData || !$clientDataJSON || !$signature) {
            $audit->logFail('admin.login.fail', ['failure_reason' => 'Missing credential data']);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $credential = $this->webauthn->getCredentialById($credentialId);
        if (!$credential) {
            $audit->logFail('webauthn.authentication.fail', [
                'failure_reason' => 'Credential not found',
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Verify the WebAuthn assertion
        $expectedChallenge = SessionManager::get('webauthn_challenge');
        if (!$expectedChallenge) {
            $audit->logFail('webauthn.authentication.fail', [
                'failure_reason' => 'No challenge in session',
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Session expired']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $verified = $this->webauthn->verifyAssertion(
            $credentialId,
            $clientDataJSON,
            $authenticatorData,
            $signature,
            $expectedChallenge
        );

        if (!$verified) {
            $audit->logFail('webauthn.authentication.fail', [
                'failure_reason' => 'Signature verification failed',
                'webauthn_credential_public_id' => $credentialId,
            ]);
            $response->getBody()->write(json_encode(['error' => 'Invalid credential']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Clear the challenge from session
        SessionManager::remove('webauthn_challenge');

        $userId = (int) $credential['user_id'];
        SessionManager::set('user_id', $userId);
        SessionManager::regenerateId();

        $audit->logSuccess('admin.login.success', [
            'actor_user_id' => $userId,
            'webauthn_credential_id' => $credential['id'],
            'webauthn_credential_public_id' => $credentialId,
        ]);

        $response->getBody()->write(json_encode(['success' => true, 'redirect' => '/admin/dashboard']));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function logout(Request $request, Response $response): Response
    {
        SessionManager::destroy();
        return $response->withHeader('Location', '/admin/login')->withStatus(302);
    }

    public function dashboard(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $db = \BlackWall\Database::getInstance();
        
        // Get stats
        $stats = [
            'users' => $db->query("SELECT COUNT(*) FROM users")->fetchColumn(),
            'projects' => $db->query("SELECT COUNT(*) FROM projects")->fetchColumn(),
            'clients' => $db->query("SELECT COUNT(*) FROM oauth_clients")->fetchColumn(),
            'audit_count' => $db->query("SELECT COUNT(*) FROM audit_log")->fetchColumn(),
        ];
        
        // Get recent activity
        $stmt = $db->query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 10");
        $recent_logs = $stmt->fetchAll();

        return $this->renderWithLayout($response, 'admin/dashboard.php', [
            'title' => 'Dashboard',
            'stats' => $stats,
            'recent_logs' => $recent_logs,
        ]);
    }

    public function usersList(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $users = $this->userRepo->findAll();

        return $this->renderWithLayout($response, 'admin/users/list.php', [
            'title' => 'Users',
            'users' => $users,
        ]);
    }

    public function userCreate(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        return $this->renderWithLayout($response, 'admin/users/create.php', [
            'title' => 'Create User',
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function userStore(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users')->withStatus(302);
        }

        $uuid = Uuid::uuid4()->toString();
        $user = $this->userRepo->create($uuid, $body['display_label'] ?? null, 'active');

        $audit->logSuccess('admin.user.create', [
            'actor_user_id' => $userId,
            'target_type' => 'user',
            'target_id' => (string) $user->id,
        ]);

        return $response->withHeader('Location', '/admin/users/' . $user->id)->withStatus(302);
    }

    public function projectsList(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $projects = $this->projectRepo->findAll();

        return $this->renderWithLayout($response, 'admin/projects/list.php', [
            'title' => 'Projects',
            'projects' => $projects,
        ]);
    }

    public function projectCreate(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        return $this->renderWithLayout($response, 'admin/projects/create.php', [
            'title' => 'Create Project',
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function projectStore(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            return $response->withHeader('Location', '/admin/projects')->withStatus(302);
        }

        $uuid = Uuid::uuid4()->toString();
        $project = $this->projectRepo->create($uuid, $body['name'], $userId, 'active');

        // Create default privilege levels
        $this->privilegeRepo->create($project->id, 1, 'Admin', 'Project administrator');
        $this->privilegeRepo->create($project->id, 2, 'User', 'Regular user');

        $audit->logSuccess('admin.project.create', [
            'actor_user_id' => $userId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'target_type' => 'project',
            'target_id' => (string) $project->id,
        ]);

        return $response->withHeader('Location', '/admin/projects/' . $project->id)->withStatus(302);
    }

    public function projectDetail(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $project = $this->projectRepo->findById((int) $args['id']);
        if (!$project) {
            return $response->withStatus(404);
        }

        return $this->renderWithLayout($response, 'admin/projects/detail.php', [
            'title' => $project->name,
            'project' => $project,
        ]);
    }

    public function auditLog(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $params = $request->getQueryParams();
        
        $audit = new AuditLogger();
        $filters = [
            'date_from' => $params['date_from'] ?? null,
            'date_to' => $params['date_to'] ?? null,
            'project_uuid' => $params['project_uuid'] ?? null,
            'ip_address' => $params['ip_address'] ?? null,
            'event_type' => $params['event_type'] ?? null,
            'outcome' => $params['outcome'] ?? null,
            'correlation_id' => $params['correlation_id'] ?? null,
        ];

        $page = (int) ($params['page'] ?? 1);
        $perPage = 50;
        $offset = ($page - 1) * $perPage;

        $logs = $audit->search($filters, $perPage, $offset);
        $total = $audit->countSearch($filters);

        return $this->renderWithLayout($response, 'admin/audit/log.php', [
            'title' => 'Audit Log',
            'logs' => $logs,
            'filters' => $filters,
            'page' => $page,
            'perPage' => $perPage,
            'total' => $total,
            'pages' => ceil($total / $perPage),
        ]);
    }

    public function userDetail(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $userId = (int) $args['id'];
        $user = $this->userRepo->findById($userId);
        
        if (!$user) {
            return $response->withStatus(404);
        }

        // Get WebAuthn credentials
        $credentials = $this->webauthn->getUserCredentials($userId);

        // Get project assignments
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            'SELECT upr.*, p.name as project_name 
             FROM user_project_roles upr
             JOIN projects p ON upr.project_id = p.id
             WHERE upr.user_id = ?
             ORDER BY upr.created_at DESC'
        );
        $stmt->execute([$userId]);
        $assignments = $stmt->fetchAll();

        // Check if there's a new enrollment link in query params
        $enrollmentLink = $request->getQueryParams()['enrollment_link'] ?? null;

        return $this->renderWithLayout($response, 'admin/users/detail.php', [
            'title' => 'User Details',
            'user' => $user,
            'credentials' => $credentials,
            'assignments' => $assignments,
            'csrfToken' => CSRFProtection::generateToken(),
            'enrollmentLink' => $enrollmentLink,
        ]);
    }

    public function userUpdate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $userId = (int) $args['id'];
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userId)->withStatus(302);
        }

        $displayLabel = $body['display_label'] ?? null;
        $status = $body['status'] ?? 'active';

        $this->userRepo->update($userId, $displayLabel, $status);

        $audit->logSuccess('admin.user.update', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'user',
            'target_id' => (string) $userId,
            'changes' => ['status' => $status],
        ]);

        return $response->withHeader('Location', '/admin/users/' . $userId)->withStatus(302);
    }
    public function projectUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevels(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevelCreate(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevelUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevelDelete(Request $request, Response $response, array $args): Response { return $response; }
    public function projectAssignments(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $projectId = (int) $args['id'];
        $project = $this->projectRepo->findById($projectId);

        if (!$project) {
            return $response->withStatus(404);
        }

        // Get all assignments for this project with user info
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            'SELECT upr.*, u.uuid as user_uuid, u.display_label as user_display_label
             FROM user_project_roles upr
             JOIN users u ON upr.user_id = u.id
             WHERE upr.project_id = ?
             ORDER BY upr.created_at DESC'
        );
        $stmt->execute([$projectId]);
        $assignments = $stmt->fetchAll();

        // Get all users for the dropdown
        $allUsers = $this->userRepo->findAll();

        // Get privilege levels for this project (or create default ones)
        $privilegeLevels = [];
        for ($i = 1; $i <= 10; $i++) {
            $privilegeLevels[] = ['level' => $i, 'name' => "Level $i"];
        }

        return $this->renderWithLayout($response, 'admin/projects/assignments.php', [
            'title' => 'User Assignments - ' . $project->name,
            'project' => $project,
            'assignments' => $assignments,
            'allUsers' => $allUsers,
            'privilegeLevels' => $privilegeLevels,
        ]);
    }
    public function assignmentCreate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $projectId = (int) $args['id'];
        $body = $request->getParsedBody();
        $userId = (int) ($body['user_id'] ?? 0);
        $privilegeLevel = (int) ($body['privilege_level'] ?? 0);

        if (!$userId || !$privilegeLevel) {
            return $response->withHeader('Location', "/admin/projects/{$projectId}/assignments")->withStatus(302);
        }

        // Check if assignment already exists
        $existing = $this->roleRepo->findByUserAndProject($userId, $projectId);
        if (!$existing) {
            $this->roleRepo->create($userId, $projectId, $privilegeLevel);
        }

        return $response->withHeader('Location', "/admin/projects/{$projectId}/assignments")->withStatus(302);
    }

    public function assignmentUpdate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $assignmentId = (int) $args['id'];
        $body = $request->getParsedBody();
        $privilegeLevel = (int) ($body['privilege_level'] ?? 0);

        if ($privilegeLevel) {
            $this->roleRepo->update($assignmentId, $privilegeLevel);
        }

        $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
        return $response->withHeader('Location', $referer)->withStatus(302);
    }

    public function assignmentDelete(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $assignmentId = (int) $args['id'];
        $this->roleRepo->delete($assignmentId);

        $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
        return $response->withHeader('Location', $referer)->withStatus(302);
    }
    public function clientsList(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $projectId = (int) $args['id'];
        $project = $this->projectRepo->findById($projectId);

        if (!$project) {
            return $response->withStatus(404);
        }

        // Get all OAuth clients for this project
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            'SELECT * FROM oauth_clients WHERE project_id = ? ORDER BY created_at DESC'
        );
        $stmt->execute([$projectId]);
        $clients = $stmt->fetchAll();

        return $this->renderWithLayout($response, 'admin/clients/list.php', [
            'title' => 'OAuth Clients - ' . $project->name,
            'project' => $project,
            'clients' => $clients,
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }
    public function clientCreate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $projectId = (int) $args['projectId'];
        $project = $this->projectRepo->findById($projectId);

        if (!$project) {
            return $response->withStatus(404);
        }

        return $this->renderWithLayout($response, 'admin/clients/create.php', [
            'title' => 'Create OAuth Client',
            'project' => $project,
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function clientStore(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $projectId = (int) $args['projectId'];
        $body = $request->getParsedBody();

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            return $response->withHeader('Location', "/admin/projects/{$projectId}/clients")->withStatus(302);
        }

        $clientId = \Ramsey\Uuid\Uuid::uuid4()->toString();
        $clientSecret = isset($body['is_confidential']) ? bin2hex(random_bytes(32)) : null;
        $isConfidential = isset($body['is_confidential']);

        $redirectUris = array_filter(array_map('trim', explode("\n", $body['redirect_uris'])));

        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            'INSERT INTO oauth_clients (project_id, client_id, client_secret_hash, name, redirect_uris, grants, pkce_required, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $projectId,
            $clientId,
            $clientSecret ? $this->hasher->hash($clientSecret) : null,
            $body['name'],
            json_encode($redirectUris),
            json_encode(['authorization_code', 'refresh_token']),
            $isConfidential ? 0 : 1, // PKCE required for public clients
            'active'
        ]);

        $newClientId = $db->lastInsertId();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');
        $audit->logSuccess('admin.client.create', [
            'actor_user_id' => $userId,
            'oauth_client_id' => $newClientId,
        ]);

        return $response->withHeader('Location', "/admin/clients/{$newClientId}?secret=" . urlencode($clientSecret ?: ''))->withStatus(302);
    }

    public function clientDetail(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $clientId = (int) $args['id'];
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare('SELECT * FROM oauth_clients WHERE id = ?');
        $stmt->execute([$clientId]);
        $client = $stmt->fetch();

        if (!$client) {
            return $response->withStatus(404);
        }

        $project = $this->projectRepo->findById($client['project_id']);

        $secret = $request->getQueryParams()['secret'] ?? null;

        return $this->renderWithLayout($response, 'admin/clients/detail.php', [
            'title' => 'OAuth Client',
            'client' => $client,
            'project' => $project,
            'secret' => $secret,
        ]);
    }
    public function clientUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function auditExport(Request $request, Response $response): Response { return $response; }

    public function generateEnrollmentLink(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $userId = (int) $args['id'];
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userId)->withStatus(302);
        }

        $user = $this->userRepo->findById($userId);
        if (!$user) {
            return $response->withStatus(404);
        }

        // Generate a secure enrollment token
        $token = bin2hex(random_bytes(32));
        $expiry = (new \DateTime())->add(new \DateInterval('P1D'))->format('Y-m-d H:i:s');

        $db = \BlackWall\Database::getInstance();
        
        // Store token in system_config with user_id embedded in the key
        $stmt = $db->prepare(
            "INSERT INTO system_config (config_key, config_value) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE config_value = ?"
        );
        $stmt->execute(['enrollment_token_' . $token, (string) $userId, (string) $userId]);
        $stmt->execute(['enrollment_expiry_' . $token, $expiry, $expiry]);

        $audit->logSuccess('admin.user.enrollment_link', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'user',
            'target_id' => (string) $userId,
        ]);

        // Generate the enrollment URL
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'blackwall.dixon.cx';
        $baseUrl = $scheme . '://' . $host;
        $enrollmentLink = $baseUrl . '/enroll?token=' . urlencode($token);

        return $response->withHeader(
            'Location',
            '/admin/users/' . $userId . '?enrollment_link=' . urlencode($enrollmentLink)
        )->withStatus(302);
    }

    public function deleteCredential(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $userId = (int) $args['id'];
        $credentialId = (int) $args['credentialId'];
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userId)->withStatus(302);
        }

        $this->webauthn->deleteCredential($credentialId);

        $audit->logSuccess('admin.user.credential.delete', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'user',
            'target_id' => (string) $userId,
            'webauthn_credential_id' => $credentialId,
        ]);

        return $response->withHeader('Location', '/admin/users/' . $userId)->withStatus(302);
    }

    private function checkAuth(): bool
    {
        SessionManager::start();
        return SessionManager::has('user_id');
    }
}
