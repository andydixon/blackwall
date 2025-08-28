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

    public function loginForm(Request $request, Response $response): Response
    {
        return $this->renderer->render($response, 'admin/login.php', [
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function loginChallenge(Request $request, Response $response): Response
    {
        // Return WebAuthn challenge for login
        // Simplified: return a placeholder
        $challenge = ['challenge' => base64_encode(random_bytes(32))];
        
        SessionManager::start();
        SessionManager::set('webauthn_challenge', $challenge['challenge']);

        $response->getBody()->write(json_encode($challenge));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function loginVerify(Request $request, Response $response): Response
    {
        SessionManager::start();
        
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        // Simplified: Accept any credential and find user
        // Real implementation would verify WebAuthn assertion
        
        $body = $request->getParsedBody();
        $credentialId = $body['credential_id'] ?? null;

        if (!$credentialId) {
            $audit->logFail('admin.login.fail', ['failure_reason' => 'Missing credential_id']);
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

        return $this->renderer->render($response, 'admin/dashboard.php', [
            'title' => 'Dashboard',
        ]);
    }

    public function usersList(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        $users = $this->userRepo->findAll();

        return $this->renderer->render($response, 'admin/users/list.php', [
            'title' => 'Users',
            'users' => $users,
        ]);
    }

    public function userCreate(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        return $this->renderer->render($response, 'admin/users/create.php', [
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

        return $this->renderer->render($response, 'admin/projects/list.php', [
            'title' => 'Projects',
            'projects' => $projects,
        ]);
    }

    public function projectCreate(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }

        return $this->renderer->render($response, 'admin/projects/create.php', [
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

        return $this->renderer->render($response, 'admin/projects/detail.php', [
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

        return $this->renderer->render($response, 'admin/audit/log.php', [
            'title' => 'Audit Log',
            'logs' => $logs,
            'filters' => $filters,
            'page' => $page,
            'perPage' => $perPage,
            'total' => $total,
            'pages' => ceil($total / $perPage),
        ]);
    }

    // Placeholder methods for other admin functions
    public function userDetail(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        $response->getBody()->write('User detail page');
        return $response;
    }

    public function userUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function projectUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevels(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevelCreate(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevelUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function privilegeLevelDelete(Request $request, Response $response, array $args): Response { return $response; }
    public function projectAssignments(Request $request, Response $response, array $args): Response { return $response; }
    public function assignmentCreate(Request $request, Response $response, array $args): Response { return $response; }
    public function assignmentUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function assignmentDelete(Request $request, Response $response, array $args): Response { return $response; }
    public function clientsList(Request $request, Response $response, array $args): Response { return $response; }
    public function clientCreate(Request $request, Response $response, array $args): Response { return $response; }
    public function clientStore(Request $request, Response $response, array $args): Response { return $response; }
    public function clientDetail(Request $request, Response $response, array $args): Response { return $response; }
    public function clientUpdate(Request $request, Response $response, array $args): Response { return $response; }
    public function auditExport(Request $request, Response $response): Response { return $response; }

    private function checkAuth(): bool
    {
        SessionManager::start();
        return SessionManager::has('user_id');
    }
}
