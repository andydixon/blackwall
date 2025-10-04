<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Domain\PrivilegeLabelResolver;
use BlackWall\Repository\UserRepository;
use BlackWall\Repository\ProjectRepository;
use BlackWall\Repository\OAuthClientRepository;
use BlackWall\Repository\PrivilegeLevelRepository;
use BlackWall\Repository\UserProjectRoleRepository;
use BlackWall\Service\ApprovalService;
use BlackWall\Service\AdminAuthorizationService;
use BlackWall\Service\AuditLogger;
use BlackWall\Service\MaintenanceService;
use BlackWall\Service\WebAuthnService;
use BlackWall\Security\SessionManager;
use BlackWall\Security\CSRFProtection;
use BlackWall\Security\ErrorTraceCodec;
use BlackWall\Security\TokenHasher;
use BlackWall\Config;
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
    private ApprovalService $approvalService;
    private AdminAuthorizationService $adminAuthz;
    private WebAuthnService $webauthn;
    private MaintenanceService $maintenance;
    private TokenHasher $hasher;
    private PhpRenderer $renderer;

    public function __construct()
    {
        $this->userRepo = new UserRepository();
        $this->projectRepo = new ProjectRepository();
        $this->clientRepo = new OAuthClientRepository();
        $this->privilegeRepo = new PrivilegeLevelRepository();
        $this->roleRepo = new UserProjectRoleRepository();
        $this->approvalService = new ApprovalService();
        $this->adminAuthz = new AdminAuthorizationService();
        $this->webauthn = new WebAuthnService();
        $this->maintenance = new MaintenanceService();
        $this->hasher = new TokenHasher();
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
    }

    private function renderWithLayout(Response $response, string $template, array $data = []): Response
    {
        SessionManager::start();
        $currentUserId = SessionManager::get('user_id');
        $data['currentAdminRole'] = $currentUserId ? $this->adminAuthz->getRole((int) $currentUserId) : null;

        // Render the content template
        $contentRenderer = new PhpRenderer(__DIR__ . '/../../templates');
        $contentResponse = $contentRenderer->render(new \Slim\Psr7\Response(), $template, $data);
        $content = (string) $contentResponse->getBody();
        
        // Render with layout
        $data['content'] = $content;
        return $this->renderer->render($response, '_layout.php', $data);
    }

    private function hasCapability(string $capability): bool
    {
        SessionManager::start();
        $userId = (int) SessionManager::get('user_id');
        $role = $this->adminAuthz->getRole($userId) ?? 'auditor';

        $matrix = [
            'super_admin' => [
                'view_dashboard', 'view_users', 'manage_users', 'view_projects', 'manage_projects',
                'view_clients', 'manage_clients', 'view_assignments', 'manage_assignments',
                'view_privileges', 'manage_privileges', 'view_audit', 'view_maintenance',
                'manage_roles', 'decode_error_trace',
                'delete_credentials_direct', 'change_user_status_direct', 'delete_privilege_direct',
                'view_approvals', 'decide_approvals',
            ],
            'operator' => [
                'view_dashboard', 'view_users', 'manage_users', 'view_projects', 'manage_projects',
                'view_clients', 'manage_clients', 'view_assignments', 'manage_assignments',
                'view_privileges', 'manage_privileges', 'view_audit', 'view_maintenance',
                'view_approvals',
            ],
            'auditor' => [
                'view_dashboard', 'view_audit', 'view_maintenance', 'decode_error_trace', 'view_approvals',
            ],
        ];

        return in_array($capability, $matrix[$role] ?? [], true);
    }

    private function requireCapability(Response $response, string $capability): ?Response
    {
        if ($this->hasCapability($capability)) {
            return null;
        }
        return $response->withStatus(403);
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
        if (($deny = $this->requireCapability($response, 'view_dashboard')) !== null) {
            return $deny;
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

        // Outcome analytics (success/fail) for today/week/month
        $stmt = $db->query(
            "SELECT
                outcome,
                SUM(created_at >= CURDATE()) AS today_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
             FROM audit_log
             WHERE outcome IN ('success', 'fail')
             GROUP BY outcome"
        );
        $outcomeRows = $stmt->fetchAll();

        $outcomeStats = [
            'success' => ['today' => 0, 'week' => 0, 'month' => 0],
            'fail' => ['today' => 0, 'week' => 0, 'month' => 0],
        ];

        foreach ($outcomeRows as $row) {
            $outcome = (string) $row['outcome'];
            if (!isset($outcomeStats[$outcome])) {
                continue;
            }

            $outcomeStats[$outcome] = [
                'today' => (int) $row['today_count'],
                'week' => (int) $row['week_count'],
                'month' => (int) $row['month_count'],
            ];
        }

        $breakdownSuccessStmt = $db->query(
            "SELECT
                event_type,
                SUM(created_at >= CURDATE()) AS today_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
             FROM audit_log
             WHERE outcome = 'success'
               AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
             GROUP BY event_type
             ORDER BY month_count DESC, week_count DESC, today_count DESC, event_type ASC
             LIMIT 12"
        );
        $successBreakdown = $breakdownSuccessStmt->fetchAll();

        $breakdownFailStmt = $db->query(
            "SELECT
                event_type,
                SUM(created_at >= CURDATE()) AS today_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
             FROM audit_log
             WHERE outcome = 'fail'
               AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
             GROUP BY event_type
             ORDER BY month_count DESC, week_count DESC, today_count DESC, event_type ASC
             LIMIT 12"
        );
        $failBreakdown = $breakdownFailStmt->fetchAll();

        return $this->renderWithLayout($response, 'admin/dashboard.php', [
            'title' => 'Dashboard',
            'stats' => $stats,
            'recent_logs' => $recent_logs,
            'outcomeStats' => $outcomeStats,
            'successBreakdown' => $successBreakdown,
            'failBreakdown' => $failBreakdown,
        ]);
    }

    public function usersList(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_users')) !== null) {
            return $deny;
        }

        $users = $this->userRepo->findAll();

        return $this->renderWithLayout($response, 'admin/users/list.php', [
            'title' => 'Users',
            'users' => $users,
        ]);
    }

    public function adminRoles(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_roles')) !== null) {
            return $deny;
        }

        $actorUserId = (int) SessionManager::get('user_id');
        if (!$this->adminAuthz->isSuperAdmin($actorUserId)) {
            return $response->withStatus(403);
        }

        return $this->renderWithLayout($response, 'admin/roles.php', [
            'title' => 'Admin Roles',
            'roles' => $this->adminAuthz->listRoles(),
            'users' => $this->userRepo->findAll(1000, 0),
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function adminRoleUpsert(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_roles')) !== null) {
            return $deny;
        }

        $actorUserId = (int) SessionManager::get('user_id');
        if (!$this->adminAuthz->isSuperAdmin($actorUserId)) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/roles')->withStatus(302);
        }

        $userId = (int) ($body['user_id'] ?? 0);
        $role = (string) ($body['role'] ?? '');
        $allowed = ['super_admin', 'operator', 'auditor'];
        if ($userId < 1 || !in_array($role, $allowed, true)) {
            return $response->withHeader('Location', '/admin/roles')->withStatus(302);
        }

        $existingRole = $this->adminAuthz->getRole($userId);
        $targetUser = $this->userRepo->findById($userId);
        if (
            $existingRole === 'super_admin'
            && $role !== 'super_admin'
            && $targetUser !== null
            && $targetUser->status === 'active'
            && $this->adminAuthz->countActiveRoleOnActiveUsers('super_admin') <= 1
        ) {
            return $response->withHeader('Location', '/admin/roles?error=last_super_admin')->withStatus(302);
        }

        $this->adminAuthz->upsertRole($userId, $role);
        $audit->logSuccess('admin.role.upsert', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'admin_role',
            'target_id' => (string) $userId,
            'message' => "Set admin role to {$role}",
        ]);

        return $response->withHeader('Location', '/admin/roles')->withStatus(302);
    }

    public function adminRoleRevoke(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_roles')) !== null) {
            return $deny;
        }

        $actorUserId = (int) SessionManager::get('user_id');
        if (!$this->adminAuthz->isSuperAdmin($actorUserId)) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/roles')->withStatus(302);
        }

        $userId = (int) ($args['userId'] ?? 0);
        if ($userId < 1) {
            return $response->withHeader('Location', '/admin/roles')->withStatus(302);
        }

        // Prevent removing your own role from current session.
        if ($userId === $actorUserId) {
            return $response->withHeader('Location', '/admin/roles?error=self_revoke')->withStatus(302);
        }

        $existingRole = $this->adminAuthz->getRole($userId);
        $targetUser = $this->userRepo->findById($userId);
        if (
            $existingRole === 'super_admin'
            && $targetUser !== null
            && $targetUser->status === 'active'
            && $this->adminAuthz->countActiveRoleOnActiveUsers('super_admin') <= 1
        ) {
            return $response->withHeader('Location', '/admin/roles?error=last_super_admin')->withStatus(302);
        }

        $this->adminAuthz->revokeRole($userId);
        $audit->logSuccess('admin.role.revoke', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'admin_role',
            'target_id' => (string) $userId,
            'message' => 'Revoked admin role',
        ]);

        return $response->withHeader('Location', '/admin/roles')->withStatus(302);
    }

    public function approvalsList(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_approvals')) !== null) {
            return $deny;
        }

        $actorUserId = (int) SessionManager::get('user_id');

        return $this->renderWithLayout($response, 'admin/approvals.php', [
            'title' => 'Approvals',
            'approvals' => $this->approvalService->listVisibleToUser(
                $actorUserId,
                $this->adminAuthz->isSuperAdmin($actorUserId),
                200
            ),
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function approvalApprove(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'decide_approvals')) !== null) {
            return $deny;
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/approvals?error=csrf')->withStatus(302);
        }

        $approvalId = (int) ($args['id'] ?? 0);
        $approval = $this->approvalService->getById($approvalId);
        if (!$approval || $approval['status'] !== 'pending') {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }

        if ((int) $approval['requested_by_user_id'] === $actorUserId) {
            return $response->withHeader('Location', '/admin/approvals?error=self_decide')->withStatus(302);
        }

        $payload = json_decode((string) $approval['payload_json'], true);
        $payload = is_array($payload) ? $payload : [];

        $executed = $this->executeApprovalAction((string) $approval['action_type'], $payload, $actorUserId);
        if (!$executed) {
            $this->approvalService->decide($approvalId, 'rejected', $actorUserId, 'Execution failed');
            return $response->withHeader('Location', '/admin/approvals?error=execution_failed')->withStatus(302);
        }

        if (!$this->approvalService->decide($approvalId, 'approved', $actorUserId, trim((string) ($body['note'] ?? '')))) {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }
        $audit->logSuccess('admin.approval.approve', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'approval_request',
            'target_id' => (string) $approvalId,
            'message' => 'Approved request',
        ]);

        return $response->withHeader('Location', '/admin/approvals?success=approved')->withStatus(302);
    }

    public function approvalReject(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'decide_approvals')) !== null) {
            return $deny;
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/approvals?error=csrf')->withStatus(302);
        }

        $approvalId = (int) ($args['id'] ?? 0);
        $decided = $this->approvalService->decide(
            $approvalId,
            'rejected',
            $actorUserId,
            trim((string) ($body['note'] ?? ''))
        );
        if (!$decided) {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }
        $audit->logInfo('admin.approval.reject', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'approval_request',
            'target_id' => (string) $approvalId,
            'message' => 'Rejected request',
        ]);

        return $response->withHeader('Location', '/admin/approvals?success=rejected')->withStatus(302);
    }

    public function approvalCancel(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_approvals')) !== null) {
            return $deny;
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/approvals?error=csrf')->withStatus(302);
        }

        $approvalId = (int) ($args['id'] ?? 0);
        $cancelled = $this->approvalService->cancelByRequester(
            $approvalId,
            $actorUserId,
            trim((string) ($body['note'] ?? 'Cancelled by requester'))
        );
        if (!$cancelled) {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }

        $audit->logInfo('admin.approval.cancel', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'approval_request',
            'target_id' => (string) $approvalId,
            'message' => 'Cancelled request',
        ]);

        return $response->withHeader('Location', '/admin/approvals?success=cancelled')->withStatus(302);
    }

    public function maintenance(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_maintenance')) !== null) {
            return $deny;
        }

        $runs = $this->maintenance->getRecentRuns(100);

        return $this->renderWithLayout($response, 'admin/maintenance.php', [
            'title' => 'Maintenance',
            'runs' => $runs,
        ]);
    }

    public function errorTraceDecodeForm(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'decode_error_trace')) !== null) {
            return $deny;
        }

        return $this->renderWithLayout($response, 'admin/error_trace.php', [
            'title' => 'Decode Error Trace',
            'csrfToken' => CSRFProtection::generateToken(),
            'inputPayload' => '',
            'decodedTrace' => null,
            'decodeError' => null,
        ]);
    }

    public function errorTraceDecode(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'decode_error_trace')) !== null) {
            return $deny;
        }

        $body = $request->getParsedBody();
        $payload = trim((string) ($body['payload'] ?? ''));

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/error-trace')->withStatus(302);
        }

        $decodedTrace = null;
        $decodeError = null;
        if ($payload !== '') {
            try {
                $decodedTrace = ErrorTraceCodec::decode($payload);
                $audit->logInfo('admin.error_trace.decode', [
                    'actor_user_id' => $actorUserId,
                    'message' => 'Decoded encrypted error trace payload',
                ]);
            } catch (\Throwable $e) {
                $decodeError = $e->getMessage();
            }
        }

        return $this->renderWithLayout($response, 'admin/error_trace.php', [
            'title' => 'Decode Error Trace',
            'csrfToken' => CSRFProtection::generateToken(),
            'inputPayload' => $payload,
            'decodedTrace' => $decodedTrace,
            'decodeError' => $decodeError,
        ]);
    }

    public function userCreate(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_users')) !== null) {
            return $deny;
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
        if (($deny = $this->requireCapability($response, 'manage_users')) !== null) {
            return $deny;
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
            'target_id' => $user->uuid,
        ]);

        return $response->withHeader('Location', '/admin/users/' . $user->uuid)->withStatus(302);
    }

    public function projectsList(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_projects')) !== null) {
            return $deny;
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
        if (($deny = $this->requireCapability($response, 'manage_projects')) !== null) {
            return $deny;
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
        if (($deny = $this->requireCapability($response, 'manage_projects')) !== null) {
            return $deny;
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
        $this->privilegeRepo->create($project->id, 3, 'Restricted User', 'Restricted project user');

        $audit->logSuccess('admin.project.create', [
            'actor_user_id' => $userId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'target_type' => 'project',
            'target_id' => $project->uuid,
        ]);

        return $response->withHeader('Location', '/admin/projects/' . $project->uuid)->withStatus(302);
    }

    public function projectDetail(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_projects')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);
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
        if (($deny = $this->requireCapability($response, 'view_audit')) !== null) {
            return $deny;
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
        if (($deny = $this->requireCapability($response, 'view_users')) !== null) {
            return $deny;
        }

        $userUuid = (string) ($args['userUuid'] ?? '');
        $user = $this->userRepo->findByUuid($userUuid);
        
        if (!$user) {
            return $response->withStatus(404);
        }
        $userId = $user->id;

        // Get WebAuthn credentials
        $credentials = $this->webauthn->getUserCredentials($userId);

        // Get project assignments
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            'SELECT upr.*, p.uuid AS project_uuid, p.name as project_name, ppl.name AS privilege_name
             FROM user_project_roles upr
             JOIN projects p ON upr.project_id = p.id
             LEFT JOIN project_privilege_levels ppl
               ON ppl.project_id = upr.project_id
              AND ppl.level = upr.privilege_level
             WHERE upr.user_id = ?
             ORDER BY upr.created_at DESC'
        );
        $stmt->execute([$userId]);
        $assignments = $stmt->fetchAll();
        foreach ($assignments as &$assignment) {
            $assignment['privilege_label'] = PrivilegeLabelResolver::resolve(
                (int) $assignment['privilege_level'],
                $assignment['privilege_name'] ?? null
            );
        }
        unset($assignment);

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
        if (($deny = $this->requireCapability($response, 'manage_users')) !== null) {
            return $deny;
        }

        $userUuid = (string) ($args['userUuid'] ?? '');
        $user = $this->userRepo->findByUuid($userUuid);
        if (!$user) {
            return $response->withStatus(404);
        }
        $userId = $user->id;
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $user->uuid)->withStatus(302);
        }

        $displayLabel = $body['display_label'] ?? null;
        $status = $body['status'] ?? 'active';
        if (!in_array($status, ['active', 'disabled'], true)) {
            return $response->withHeader('Location', '/admin/users/' . $user->uuid)->withStatus(302);
        }

        $isDisablingActiveSuperAdmin = (
            $user->status === 'active'
            && $status === 'disabled'
            && $this->adminAuthz->getRole($user->id) === 'super_admin'
        );
        if (
            $isDisablingActiveSuperAdmin
            && $this->adminAuthz->countActiveRoleOnActiveUsers('super_admin') <= 1
        ) {
            return $response->withHeader('Location', '/admin/users/' . $user->uuid . '?error=last_super_admin')->withStatus(302);
        }

        if ($status !== $user->status && !$this->hasCapability('change_user_status_direct')) {
            $this->approvalService->create(
                'change_user_status',
                [
                    'user_uuid' => $user->uuid,
                    'requested_status' => $status,
                ],
                $actorUserId
            );

            return $response->withHeader('Location', '/admin/users/' . $user->uuid . '?success=status_change_requested')->withStatus(302);
        }

        $this->userRepo->update($userId, $displayLabel, $status);

        $audit->logSuccess('admin.user.update', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'user',
            'target_id' => $user->uuid,
            'changes' => ['status' => $status],
        ]);

        return $response->withHeader('Location', '/admin/users/' . $user->uuid)->withStatus(302);
    }
    public function projectUpdate(Request $request, Response $response, array $args): Response { return $response; }

    public function privilegeLevels(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_privileges')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);
        if (!$project) {
            return $response->withStatus(404);
        }

        $levels = $this->privilegeRepo->findAllByProject($project->id);
        $levelRows = [];
        $existingLevels = [];

        foreach ($levels as $level) {
            $effectiveName = PrivilegeLabelResolver::resolve($level->level, $level->name);
            $defaultName = PrivilegeLabelResolver::resolve($level->level, null);

            $levelRows[] = [
                'entity' => $level,
                'effective_name' => $effectiveName,
                'default_name' => $defaultName,
                'is_override' => $level->name !== $defaultName,
                'in_use' => $this->privilegeRepo->isLevelInUse($project->id, $level->level),
            ];
            $existingLevels[] = $level->level;
        }

        $availableLevels = [];
        for ($i = 1; $i <= 10; $i++) {
            if (!in_array($i, $existingLevels, true)) {
                $availableLevels[] = [
                    'level' => $i,
                    'default_name' => PrivilegeLabelResolver::resolve($i, null),
                ];
            }
        }

        $query = $request->getQueryParams();

        return $this->renderWithLayout($response, 'admin/projects/privileges.php', [
            'title' => 'Privilege Levels - ' . $project->name,
            'project' => $project,
            'levelRows' => $levelRows,
            'availableLevels' => $availableLevels,
            'csrfToken' => CSRFProtection::generateToken(),
            'success' => $query['success'] ?? null,
            'error' => $query['error'] ?? null,
        ]);
    }

    public function privilegeLevelCreate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_privileges')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);
        if (!$project) {
            return $response->withStatus(404);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=csrf")->withStatus(302);
        }

        $level = (int) ($body['level'] ?? 0);
        $name = trim((string) ($body['name'] ?? ''));
        $description = trim((string) ($body['description'] ?? ''));
        $description = $description === '' ? null : $description;

        if ($level < 1 || $level > 10) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=invalid_level")->withStatus(302);
        }

        if ($name === '') {
            $name = PrivilegeLabelResolver::resolve($level, null);
        }

        try {
            $this->privilegeRepo->create($project->id, $level, $name, $description);
        } catch (\Throwable $e) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=duplicate")->withStatus(302);
        }

        $audit->logSuccess('admin.privilege.create', [
            'actor_user_id' => $actorUserId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'privilege_level' => $level,
            'privilege_name' => $name,
            'target_type' => 'project_privilege_level',
        ]);

        return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?success=created")->withStatus(302);
    }

    public function privilegeLevelUpdate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_privileges')) !== null) {
            return $deny;
        }

        $levelId = (int) ($args['id'] ?? 0);
        $level = $this->privilegeRepo->findById($levelId);
        if (!$level) {
            return $response->withStatus(404);
        }

        $project = $this->projectRepo->findById($level->projectId);
        if (!$project) {
            return $response->withStatus(404);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=csrf")->withStatus(302);
        }

        $name = trim((string) ($body['name'] ?? ''));
        $description = trim((string) ($body['description'] ?? ''));
        $description = $description === '' ? null : $description;

        if ($name === '') {
            $name = PrivilegeLabelResolver::resolve($level->level, null);
        }

        try {
            $this->privilegeRepo->update($level->id, $name, $description);
        } catch (\Throwable $e) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=duplicate")->withStatus(302);
        }

        $audit->logSuccess('admin.privilege.update', [
            'actor_user_id' => $actorUserId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'privilege_level' => $level->level,
            'privilege_name' => $name,
            'target_type' => 'project_privilege_level',
            'target_id' => (string) $level->id,
        ]);

        return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?success=updated")->withStatus(302);
    }

    public function privilegeLevelDelete(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_privileges')) !== null) {
            return $deny;
        }

        $levelId = (int) ($args['id'] ?? 0);
        $level = $this->privilegeRepo->findById($levelId);
        if (!$level) {
            return $response->withStatus(404);
        }

        $project = $this->projectRepo->findById($level->projectId);
        if (!$project) {
            return $response->withStatus(404);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=csrf")->withStatus(302);
        }

        if ($this->privilegeRepo->isLevelInUse($project->id, $level->level)) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?error=in_use")->withStatus(302);
        }

        if (!$this->hasCapability('delete_privilege_direct')) {
            $this->approvalService->create(
                'delete_privilege_level',
                [
                    'level_id' => $level->id,
                ],
                $actorUserId
            );

            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?success=delete_requested")->withStatus(302);
        }

        $this->privilegeRepo->delete($level->id);

        $audit->logSuccess('admin.privilege.delete', [
            'actor_user_id' => $actorUserId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'privilege_level' => $level->level,
            'target_type' => 'project_privilege_level',
            'target_id' => (string) $level->id,
        ]);

        return $response->withHeader('Location', "/admin/projects/{$project->uuid}/privileges?success=deleted")->withStatus(302);
    }
    public function projectAssignments(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_assignments')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);

        if (!$project) {
            return $response->withStatus(404);
        }
        $projectId = $project->id;

        // Get all assignments for this project with user info
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            'SELECT upr.*, u.uuid as user_uuid, u.display_label as user_display_label, ppl.name AS privilege_name
             FROM user_project_roles upr
             JOIN users u ON upr.user_id = u.id
             LEFT JOIN project_privilege_levels ppl
               ON ppl.project_id = upr.project_id
              AND ppl.level = upr.privilege_level
             WHERE upr.project_id = ?
             ORDER BY upr.created_at DESC'
        );
        $stmt->execute([$projectId]);
        $assignments = $stmt->fetchAll();
        foreach ($assignments as &$assignment) {
            $assignment['privilege_label'] = PrivilegeLabelResolver::resolve(
                (int) $assignment['privilege_level'],
                $assignment['privilege_name'] ?? null
            );
        }
        unset($assignment);

        // Get all users for the dropdown
        $allUsers = $this->userRepo->findAll();

        // Get privilege levels for this project (or create default ones)
        $privilegeLevels = [];
        for ($i = 1; $i <= 10; $i++) {
            $custom = $this->privilegeRepo->findByProjectAndLevel($projectId, $i);
            $privilegeLevels[] = [
                'level' => $i,
                'name' => PrivilegeLabelResolver::resolve($i, $custom?->name),
            ];
        }

        return $this->renderWithLayout($response, 'admin/projects/assignments.php', [
            'title' => 'User Assignments - ' . $project->name,
            'project' => $project,
            'assignments' => $assignments,
            'allUsers' => $allUsers,
            'privilegeLevels' => $privilegeLevels,
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }
    public function assignmentCreate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_assignments')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);
        if (!$project) {
            return $response->withStatus(404);
        }
        $projectId = $project->id;
        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=csrf")->withStatus(302);
        }

        $userId = (int) ($body['user_id'] ?? 0);
        $privilegeLevel = (int) ($body['privilege_level'] ?? 0);

        if (!$userId || !$privilegeLevel) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=invalid")->withStatus(302);
        }

        // Check if assignment already exists
        $existing = $this->roleRepo->findByUserAndProject($userId, $projectId);
        if (!$existing) {
            $created = $this->roleRepo->create($userId, $projectId, $privilegeLevel);
            $audit->logSuccess('admin.assignment.create', [
                'actor_user_id' => $actorUserId,
                'project_id' => $project->id,
                'project_uuid' => $project->uuid,
                'target_type' => 'user_project_role',
                'target_id' => (string) $created->id,
                'message' => "Assigned user {$userId} at privilege level {$privilegeLevel}",
            ]);
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?success=created")->withStatus(302);
        }

        return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=exists")->withStatus(302);
    }

    public function assignmentUpdate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_assignments')) !== null) {
            return $deny;
        }

        $assignmentId = (int) $args['id'];
        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
            return $response->withHeader('Location', $referer)->withStatus(302);
        }

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
        if (($deny = $this->requireCapability($response, 'manage_assignments')) !== null) {
            return $deny;
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');
        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
            return $response->withHeader('Location', $referer)->withStatus(302);
        }

        $assignmentId = (int) $args['id'];
        $assignment = $this->roleRepo->findById($assignmentId);
        $this->roleRepo->delete($assignmentId);
        if ($assignment !== null) {
            $audit->logSuccess('admin.assignment.delete', [
                'actor_user_id' => $actorUserId,
                'project_id' => $assignment->projectId,
                'target_type' => 'user_project_role',
                'target_id' => (string) $assignment->id,
                'message' => "Removed assignment for user {$assignment->userId}",
            ]);
        }

        $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
        return $response->withHeader('Location', $referer)->withStatus(302);
    }
    public function clientsList(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_clients')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);

        if (!$project) {
            return $response->withStatus(404);
        }
        $projectId = $project->id;

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
        if (($deny = $this->requireCapability($response, 'manage_clients')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);

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
        if (($deny = $this->requireCapability($response, 'manage_clients')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);
        if (!$project) {
            return $response->withStatus(404);
        }
        $projectId = $project->id;
        $body = $request->getParsedBody();

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/clients")->withStatus(302);
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

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');
        $audit->logSuccess('admin.client.create', [
            'actor_user_id' => $userId,
            'oauth_client_public_id' => $clientId,
        ]);

        return $response->withHeader('Location', "/admin/clients/{$clientId}?secret=" . urlencode($clientSecret ?: ''))->withStatus(302);
    }

    public function clientDetail(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_clients')) !== null) {
            return $deny;
        }

        $clientPublicId = (string) ($args['clientPublicId'] ?? '');
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare('SELECT * FROM oauth_clients WHERE client_id = ?');
        $stmt->execute([$clientPublicId]);
        $client = $stmt->fetch();

        if (!$client) {
            return $response->withStatus(404);
        }

        $project = $this->projectRepo->findById((int) $client['project_id']);

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
        if (($deny = $this->requireCapability($response, 'manage_users')) !== null) {
            return $deny;
        }

        $userUuid = (string) ($args['userUuid'] ?? '');
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userUuid)->withStatus(302);
        }

        $user = $this->userRepo->findByUuid($userUuid);
        if (!$user) {
            return $response->withStatus(404);
        }
        $userId = $user->id;

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
            'target_id' => $user->uuid,
        ]);

        // Generate the enrollment URL
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'blackwall.cx';
        $baseUrl = $scheme . '://' . $host;
        $enrollmentLink = $baseUrl . '/enroll?token=' . urlencode($token);

        return $response->withHeader(
            'Location',
            '/admin/users/' . $user->uuid . '?enrollment_link=' . urlencode($enrollmentLink)
        )->withStatus(302);
    }

    public function deleteCredential(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_users')) !== null) {
            return $deny;
        }

        $userUuid = (string) ($args['userUuid'] ?? '');
        $credentialPublicId = (string) ($args['credentialPublicId'] ?? '');
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userUuid)->withStatus(302);
        }

        $user = $this->userRepo->findByUuid($userUuid);
        if (!$user) {
            return $response->withStatus(404);
        }
        $userId = $user->id;

        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare('SELECT id, user_id FROM webauthn_credentials WHERE credential_id = ?');
        $stmt->execute([$credentialPublicId]);
        $credential = $stmt->fetch();
        if (!$credential || (int) $credential['user_id'] !== $userId) {
            return $response->withHeader('Location', '/admin/users/' . $user->uuid)->withStatus(302);
        }
        $credentialId = (int) $credential['id'];

        $db = \BlackWall\Database::getInstance();
        $countStmt = $db->prepare('SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?');
        $countStmt->execute([$userId]);
        $currentKeyCount = (int) $countStmt->fetchColumn();
        $minKeys = max(1, Config::getInt('MIN_WEBAUTHN_KEYS', 1));
        if ($currentKeyCount <= $minKeys) {
            return $response->withHeader('Location', '/admin/users/' . $user->uuid . '?error=min_keys')->withStatus(302);
        }

        if (!$this->hasCapability('delete_credentials_direct')) {
            $this->approvalService->create(
                'delete_user_credential',
                [
                    'user_uuid' => $user->uuid,
                    'credential_public_id' => $credentialPublicId,
                ],
                $actorUserId
            );

            return $response->withHeader('Location', '/admin/users/' . $user->uuid . '?success=delete_requested')->withStatus(302);
        }

        $audit->logSuccess('admin.user.credential.delete', [
            'actor_user_id' => $actorUserId,
            'target_type' => 'user',
            'target_id' => $user->uuid,
            'webauthn_credential_id' => $credentialId,
            'webauthn_credential_public_id' => $credentialPublicId,
        ]);

        $this->webauthn->deleteCredential($credentialId);

        return $response->withHeader('Location', '/admin/users/' . $user->uuid)->withStatus(302);
    }

    private function executeApprovalAction(string $actionType, array $payload, int $actorUserId): bool
    {
        switch ($actionType) {
            case 'delete_user_credential':
                $userUuid = (string) ($payload['user_uuid'] ?? '');
                $credentialPublicId = (string) ($payload['credential_public_id'] ?? '');
                if ($userUuid === '' || $credentialPublicId === '') {
                    return false;
                }

                $user = $this->userRepo->findByUuid($userUuid);
                if (!$user) {
                    return false;
                }

                $db = \BlackWall\Database::getInstance();
                $stmt = $db->prepare('SELECT id, user_id FROM webauthn_credentials WHERE credential_id = ?');
                $stmt->execute([$credentialPublicId]);
                $credential = $stmt->fetch();
                if (!$credential || (int) $credential['user_id'] !== $user->id) {
                    return false;
                }

                $countStmt = $db->prepare('SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?');
                $countStmt->execute([$user->id]);
                $keyCount = (int) $countStmt->fetchColumn();
                $minKeys = max(1, Config::getInt('MIN_WEBAUTHN_KEYS', 1));
                if ($keyCount <= $minKeys) {
                    return false;
                }

                /** @var AuditLogger $audit */
                $audit = new AuditLogger();
                $audit->logSuccess('admin.user.credential.delete.approved', [
                    'actor_user_id' => $actorUserId,
                    'target_type' => 'user',
                    'target_id' => $user->uuid,
                    'webauthn_credential_id' => (int) $credential['id'],
                    'webauthn_credential_public_id' => $credentialPublicId,
                    'message' => 'Credential deleted via approval workflow',
                ]);

                return $this->webauthn->deleteCredential((int) $credential['id']);

            case 'change_user_status':
                $userUuid = (string) ($payload['user_uuid'] ?? '');
                $requestedStatus = (string) ($payload['requested_status'] ?? '');
                if ($userUuid === '' || !in_array($requestedStatus, ['active', 'disabled'], true)) {
                    return false;
                }

                $user = $this->userRepo->findByUuid($userUuid);
                if (!$user) {
                    return false;
                }

                $isDisablingActiveSuperAdmin = (
                    $user->status === 'active'
                    && $requestedStatus === 'disabled'
                    && $this->adminAuthz->getRole($user->id) === 'super_admin'
                );
                if (
                    $isDisablingActiveSuperAdmin
                    && $this->adminAuthz->countActiveRoleOnActiveUsers('super_admin') <= 1
                ) {
                    return false;
                }

                $this->userRepo->update($user->id, $user->displayLabel, $requestedStatus);

                /** @var AuditLogger $audit */
                $audit = new AuditLogger();
                $audit->logSuccess('admin.user.status_change.approved', [
                    'actor_user_id' => $actorUserId,
                    'target_type' => 'user',
                    'target_id' => $user->uuid,
                    'message' => "User status changed to {$requestedStatus} via approval workflow",
                ]);

                return true;

            case 'delete_privilege_level':
                $levelId = (int) ($payload['level_id'] ?? 0);
                if ($levelId < 1) {
                    return false;
                }

                $level = $this->privilegeRepo->findById($levelId);
                if (!$level) {
                    return false;
                }

                if ($this->privilegeRepo->isLevelInUse($level->projectId, $level->level)) {
                    return false;
                }

                $this->privilegeRepo->delete($level->id);

                /** @var AuditLogger $audit */
                $audit = new AuditLogger();
                $audit->logSuccess('admin.privilege.delete.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $level->projectId,
                    'privilege_level' => $level->level,
                    'target_type' => 'project_privilege_level',
                    'target_id' => (string) $level->id,
                    'message' => 'Privilege level deleted via approval workflow',
                ]);

                return true;
        }

        return false;
    }

    private function checkAuth(): bool
    {
        SessionManager::start();
        if (!SessionManager::has('user_id')) {
            return false;
        }

        $userId = (int) SessionManager::get('user_id');
        return $this->adminAuthz->isAdmin($userId);
    }
}
