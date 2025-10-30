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
use BlackWall\Security\RateLimiter;
use BlackWall\Security\AdminMutationPolicy;
use BlackWall\Security\AuditExportSigner;
use BlackWall\Security\ApprovalDecisionPolicy;
use BlackWall\Security\AdminScopedViewPolicy;
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
    private ?array $cachedScope = null;

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
        if ($currentUserId) {
            $scope = $this->getAdminScope((int) $currentUserId);
            if ($scope['is_super_admin']) {
                $data['currentAdminRole'] = 'super_admin';
            } elseif ($scope['is_admin']) {
                $data['currentAdminRole'] = 'operator';
            } else {
                $data['currentAdminRole'] = null;
            }
        } else {
            $data['currentAdminRole'] = null;
        }

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
        $scope = $this->getAdminScope($userId);
        $role = $scope['is_super_admin'] ? 'super_admin' : ($scope['is_admin'] ? 'operator' : 'auditor');

        $matrix = [
            'super_admin' => [
                'view_dashboard', 'view_users', 'manage_users', 'view_projects', 'manage_projects',
                'view_clients', 'manage_clients', 'view_assignments', 'manage_assignments',
                'view_privileges', 'manage_privileges', 'view_audit', 'view_maintenance',
                'manage_roles', 'decode_error_trace', 'view_scope_debug', 'view_docs',
                'delete_credentials_direct', 'change_user_status_direct', 'delete_privilege_direct',
                'change_project_status_direct', 'change_client_status_direct',
                'update_project_settings_direct', 'update_client_settings_direct',
                'assignment_mutations_direct',
                'view_approvals', 'decide_approvals',
            ],
            'operator' => [
                'view_dashboard', 'view_users', 'manage_users', 'view_projects', 'manage_projects',
                'view_clients', 'manage_clients', 'view_assignments', 'manage_assignments',
                'view_privileges', 'manage_privileges', 'view_audit', 'view_docs',
                'view_approvals', 'view_scope_debug',
            ],
            'auditor' => [
                'view_dashboard', 'view_audit', 'view_maintenance', 'decode_error_trace', 'view_approvals', 'view_scope_debug', 'view_docs',
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
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        $projectIds = $scope['project_ids'];

        if (!$scope['is_super_admin'] && empty($projectIds)) {
            $stats = ['users' => 0, 'projects' => 0, 'clients' => 0, 'audit_count' => 0];
            $recent_logs = [];
            $outcomeRows = [];
            $successBreakdown = [];
            $failBreakdown = [];
        } elseif ($scope['is_super_admin']) {
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
        } else {
            $projectPlaceholders = implode(',', array_fill(0, count($projectIds), '?'));
            $statsStmt = $db->prepare(
                "SELECT
                    (SELECT COUNT(DISTINCT upr.user_id) FROM user_project_roles upr WHERE upr.project_id IN ({$projectPlaceholders})) AS users_count,
                    (SELECT COUNT(*) FROM projects p WHERE p.id IN ({$projectPlaceholders})) AS projects_count,
                    (SELECT COUNT(*) FROM oauth_clients c WHERE c.project_id IN ({$projectPlaceholders})) AS clients_count,
                    (SELECT COUNT(*) FROM audit_log a WHERE a.project_id IN ({$projectPlaceholders})) AS audit_count"
            );
            $statsStmt->execute(array_merge($projectIds, $projectIds, $projectIds, $projectIds));
            $statRow = $statsStmt->fetch() ?: [];
            $stats = [
                'users' => (int) ($statRow['users_count'] ?? 0),
                'projects' => (int) ($statRow['projects_count'] ?? 0),
                'clients' => (int) ($statRow['clients_count'] ?? 0),
                'audit_count' => (int) ($statRow['audit_count'] ?? 0),
            ];

            $recentStmt = $db->prepare(
                "SELECT * FROM audit_log
                 WHERE project_id IN ({$projectPlaceholders})
                 ORDER BY created_at DESC
                 LIMIT 10"
            );
            $recentStmt->execute($projectIds);
            $recent_logs = $recentStmt->fetchAll();

            $outcomeStmt = $db->prepare(
                "SELECT
                    outcome,
                    SUM(created_at >= CURDATE()) AS today_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
                 FROM audit_log
                 WHERE outcome IN ('success', 'fail')
                   AND project_id IN ({$projectPlaceholders})
                 GROUP BY outcome"
            );
            $outcomeStmt->execute($projectIds);
            $outcomeRows = $outcomeStmt->fetchAll();

            $successStmt = $db->prepare(
                "SELECT
                    event_type,
                    SUM(created_at >= CURDATE()) AS today_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
                 FROM audit_log
                 WHERE outcome = 'success'
                   AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                   AND project_id IN ({$projectPlaceholders})
                 GROUP BY event_type
                 ORDER BY month_count DESC, week_count DESC, today_count DESC, event_type ASC
                 LIMIT 12"
            );
            $successStmt->execute($projectIds);
            $successBreakdown = $successStmt->fetchAll();

            $failStmt = $db->prepare(
                "SELECT
                    event_type,
                    SUM(created_at >= CURDATE()) AS today_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
                 FROM audit_log
                 WHERE outcome = 'fail'
                   AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                   AND project_id IN ({$projectPlaceholders})
                 GROUP BY event_type
                 ORDER BY month_count DESC, week_count DESC, today_count DESC, event_type ASC
                 LIMIT 12"
            );
            $failStmt->execute($projectIds);
            $failBreakdown = $failStmt->fetchAll();
        }

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


        $actorUserId = (int) SessionManager::get('user_id');
        $myPendingApprovals = $this->hasCapability('view_approvals')
            ? $this->approvalService->listPendingByRequester($actorUserId, 6)
            : [];
        $approvalStats = $this->hasCapability('view_approvals')
            ? $this->approvalService->summariseVisibleToUser($actorUserId, $scope['is_super_admin'], $scope['project_ids'])
            : [
                'pending' => ['today' => 0, 'week' => 0, 'month' => 0],
                'approved' => ['today' => 0, 'week' => 0, 'month' => 0],
                'rejected' => ['today' => 0, 'week' => 0, 'month' => 0],
                'cancelled' => ['today' => 0, 'week' => 0, 'month' => 0],
            ];
        $pendingWarningDays = max(1, Config::getInt('ADMIN_APPROVAL_PENDING_WARNING_DAYS', 3));
        $approvalSla = $this->hasCapability('view_approvals')
            ? $this->approvalService->summariseSlaVisibleToUser(
                $actorUserId,
                $scope['is_super_admin'],
                $scope['project_ids'],
                $pendingWarningDays
            )
            : [
                'decision_count' => 0,
                'median_seconds' => 0,
                'p95_seconds' => 0,
                'pending_older_than_threshold' => 0,
                'pending_warning_days' => $pendingWarningDays,
                'oldest_pending_created_at' => null,
            ];
        $csrfSecurityStats = $this->dashboardSecurityEventStats($db, 'security.csrf.fail', $scope['is_super_admin'], $projectIds);
        $rateLimitSecurityStats = $this->dashboardSecurityEventStats($db, 'security.rate_limit.admin_mutation', $scope['is_super_admin'], $projectIds);
        $csrfTopProjects = $this->dashboardSecurityTopProjects($db, 'security.csrf.fail', $scope['is_super_admin'], $projectIds);
        $rateLimitTopProjects = $this->dashboardSecurityTopProjects($db, 'security.rate_limit.admin_mutation', $scope['is_super_admin'], $projectIds);

        return $this->renderWithLayout($response, 'admin/dashboard.php', [
            'title' => 'Dashboard',
            'stats' => $stats,
            'recent_logs' => $recent_logs,
            'outcomeStats' => $outcomeStats,
            'successBreakdown' => $successBreakdown,
            'failBreakdown' => $failBreakdown,
            'myPendingApprovals' => $myPendingApprovals,
            'approvalStats' => $approvalStats,
            'approvalSla' => $approvalSla,
            'csrfSecurityStats' => $csrfSecurityStats,
            'rateLimitSecurityStats' => $rateLimitSecurityStats,
            'csrfTopProjects' => $csrfTopProjects,
            'rateLimitTopProjects' => $rateLimitTopProjects,
            'csrfToken' => CSRFProtection::generateToken(),
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

        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if ($scope['is_super_admin']) {
            $users = $this->userRepo->findAll();
        } elseif (!empty($scope['project_ids'])) {
            $db = \BlackWall\Database::getInstance();
            $placeholders = implode(',', array_fill(0, count($scope['project_ids']), '?'));
            $stmt = $db->prepare(
                "SELECT DISTINCT u.*
                 FROM users u
                 JOIN user_project_roles upr ON upr.user_id = u.id
                 WHERE upr.project_id IN ({$placeholders})
                 ORDER BY u.created_at DESC"
            );
            $stmt->execute($scope['project_ids']);
            $rows = $stmt->fetchAll();
            $users = array_map(
                static fn(array $row): \BlackWall\Model\User => new \BlackWall\Model\User(
                    id: (int) $row['id'],
                    uuid: (string) $row['uuid'],
                    displayLabel: $row['display_label'],
                    status: (string) $row['status'],
                    createdAt: new \DateTimeImmutable((string) $row['created_at']),
                    updatedAt: new \DateTimeImmutable((string) $row['updated_at'])
                ),
                $rows
            );
        } else {
            $users = [];
        }

        return $this->renderWithLayout($response, 'admin/users/list.php', [
            'title' => 'Users',
            'users' => $users,
            'canCreateUser' => $scope['is_super_admin'],
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
        if (!$this->getAdminScope($actorUserId)['is_super_admin']) {
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
        if (!$this->getAdminScope($actorUserId)['is_super_admin']) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'role_upsert', '/admin/roles')) !== null) {
            return $limited;
        }

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
        if (!$this->getAdminScope($actorUserId)['is_super_admin']) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'role_revoke', '/admin/roles')) !== null) {
            return $limited;
        }

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
        $scope = $this->getAdminScope($actorUserId);
        $includeAll = $scope['is_super_admin'];
        $visibleProjectIds = $includeAll ? [] : $scope['project_ids'];
        $params = $request->getQueryParams();
        $filters = [
            'status' => $params['status'] ?? '',
            'action_type' => $params['action_type'] ?? '',
            'project_uuid' => $params['project_uuid'] ?? '',
            'failure_reason' => $params['failure_reason'] ?? '',
            'requested_by_uuid' => $params['requested_by_uuid'] ?? '',
            'date_from' => $params['date_from'] ?? '',
            'date_to' => $params['date_to'] ?? '',
        ];
        if (!$includeAll && !empty($filters['project_uuid']) && !$this->canAccessProjectUuid((string) $filters['project_uuid'])) {
            $filters['project_uuid'] = '__no_access__';
        }
        $page = max(1, (int) ($params['page'] ?? 1));
        $perPage = 50;
        $offset = ($page - 1) * $perPage;
        $approvals = $this->approvalService->searchVisibleToUser(
            $actorUserId,
            $includeAll,
            $filters,
            $perPage,
            $offset,
            $visibleProjectIds
        );
        $total = $this->approvalService->countVisibleToUser($actorUserId, $includeAll, $filters, $visibleProjectIds);

        return $this->renderWithLayout($response, 'admin/approvals.php', [
            'title' => 'Approvals',
            'approvals' => $approvals,
            'filters' => $filters,
            'failureReasonOptions' => ['missing_capability', 'out_of_scope', 'self_decision'],
            'page' => $page,
            'perPage' => $perPage,
            'total' => $total,
            'pages' => (int) ceil($total / $perPage),
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function approvalApprove(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');
        $body = $request->getParsedBody();
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'approval_approve', '/admin/approvals')) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/approvals?error=csrf')->withStatus(302);
        }

        $approvalId = (int) ($args['id'] ?? 0);
        $approval = $this->approvalService->getById($approvalId);
        if (!$approval || $approval['status'] !== 'pending') {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }
        $scope = $this->getAdminScope($actorUserId);
        $denyReason = ApprovalDecisionPolicy::denialReason(
            $this->hasCapability('decide_approvals'),
            $approval,
            $scope,
            $actorUserId
        );
        if ($denyReason !== null) {
            $audit->logFail('admin.approval.decision.denied', [
                'actor_user_id' => $actorUserId,
                'project_id' => $approval['project_id'] ?? null,
                'target_type' => 'approval_request',
                'target_id' => (string) $approvalId,
                'failure_reason' => $denyReason,
                'message' => 'Approval decision denied: ' . str_replace('_', ' ', $denyReason),
            ]);
            if ($denyReason === 'self_decision') {
                return $response->withHeader('Location', '/admin/approvals?error=self_decide')->withStatus(302);
            }
            return $response->withStatus(403);
        }

        $payload = json_decode((string) $approval['payload_json'], true);
        $payload = is_array($payload) ? $payload : [];

        $executed = $this->executeApprovalAction((string) $approval['action_type'], $payload, $actorUserId);
        if (!$executed) {
            $this->approvalService->decide($approvalId, 'rejected', $actorUserId, 'Execution failed');
            $audit->logFail('admin.approval.execution.fail', [
                'actor_user_id' => $actorUserId,
                'project_id' => $approval['project_id'] ?? null,
                'target_type' => 'approval_request',
                'target_id' => (string) $approvalId,
                'failure_reason' => 'execution_failed',
                'message' => 'Approval execution failed',
            ]);
            return $response->withHeader('Location', '/admin/approvals?error=execution_failed')->withStatus(302);
        }

        if (!$this->approvalService->decide($approvalId, 'approved', $actorUserId, trim((string) ($body['note'] ?? '')))) {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }
        $audit->logSuccess('admin.approval.approve', [
            'actor_user_id' => $actorUserId,
            'project_id' => $approval['project_id'] ?? null,
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
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');
        $body = $request->getParsedBody();
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'approval_reject', '/admin/approvals')) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/approvals?error=csrf')->withStatus(302);
        }

        $approvalId = (int) ($args['id'] ?? 0);
        $approval = $this->approvalService->getById($approvalId);
        if (!$approval || $approval['status'] !== 'pending') {
            return $response->withHeader('Location', '/admin/approvals?error=not_pending')->withStatus(302);
        }
        $scope = $this->getAdminScope($actorUserId);
        $denyReason = ApprovalDecisionPolicy::denialReason(
            $this->hasCapability('decide_approvals'),
            $approval,
            $scope,
            $actorUserId
        );
        if ($denyReason !== null) {
            $audit->logFail('admin.approval.decision.denied', [
                'actor_user_id' => $actorUserId,
                'project_id' => $approval['project_id'] ?? null,
                'target_type' => 'approval_request',
                'target_id' => (string) $approvalId,
                'failure_reason' => $denyReason,
                'message' => 'Approval rejection denied: ' . str_replace('_', ' ', $denyReason),
            ]);
            if ($denyReason === 'self_decision') {
                return $response->withHeader('Location', '/admin/approvals?error=self_decide')->withStatus(302);
            }
            return $response->withStatus(403);
        }

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
            'project_id' => $approval['project_id'] ?? null,
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
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'approval_cancel', '/admin/approvals')) !== null) {
            return $limited;
        }

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
            $audit->logFail('admin.approval.cancel.denied', [
                'actor_user_id' => $actorUserId,
                'target_type' => 'approval_request',
                'target_id' => (string) $approvalId,
                'failure_reason' => 'not_pending_or_not_requester',
                'message' => 'Approval cancellation denied',
            ]);
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

    public function docsHome(Request $request, Response $response): Response
    {
        return $this->renderDocsPage($response, 'overview');
    }

    public function docsPage(Request $request, Response $response, array $args): Response
    {
        return $this->renderDocsPage($response, (string) ($args['page'] ?? 'overview'));
    }

    public function scopeDebug(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_scope_debug')) !== null) {
            return $deny;
        }

        $userId = (int) SessionManager::get('user_id');
        $scope = $this->getAdminScope($userId);
        $superProjectName = (string) Config::get('ADMIN_SUPER_PROJECT_NAME', 'BlackWall Admin');
        $superProjectUuid = (string) Config::get('ADMIN_SUPER_PROJECT_UUID', '');

        return $this->renderWithLayout($response, 'admin/scope_debug.php', [
            'title' => 'Scope Debug',
            'scope' => $scope,
            'userId' => $userId,
            'superProjectName' => $superProjectName,
            'superProjectUuid' => $superProjectUuid,
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
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'error_trace_decode', '/admin/error-trace')) !== null) {
            return $limited;
        }

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

        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if (!$scope['is_super_admin']) {
            return $response->withStatus(403);
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

        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if (!$scope['is_super_admin']) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'user_create', '/admin/users')) !== null) {
            return $limited;
        }

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

        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if ($scope['is_super_admin']) {
            $projects = $this->projectRepo->findAll();
        } elseif (!empty($scope['project_ids'])) {
            $db = \BlackWall\Database::getInstance();
            $placeholders = implode(',', array_fill(0, count($scope['project_ids']), '?'));
            $stmt = $db->prepare(
                "SELECT * FROM projects
                 WHERE id IN ({$placeholders})
                 ORDER BY created_at DESC"
            );
            $stmt->execute($scope['project_ids']);
            $rows = $stmt->fetchAll();
            $projects = array_map(
                static fn(array $row): \BlackWall\Model\Project => new \BlackWall\Model\Project(
                    id: (int) $row['id'],
                    uuid: (string) $row['uuid'],
                    name: (string) $row['name'],
                    ownerUserId: !empty($row['owner_user_id']) ? (int) $row['owner_user_id'] : null,
                    status: (string) $row['status'],
                    createdAt: new \DateTimeImmutable((string) $row['created_at']),
                    updatedAt: new \DateTimeImmutable((string) $row['updated_at'])
                ),
                $rows
            );
        } else {
            $projects = [];
        }

        return $this->renderWithLayout($response, 'admin/projects/list.php', [
            'title' => 'Projects',
            'projects' => $projects,
            'canCreateProject' => $scope['is_super_admin'],
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

        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if (!$scope['is_super_admin']) {
            return $response->withStatus(403);
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

        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if (!$scope['is_super_admin']) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $userId = SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'project_create', '/admin/projects')) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }

        return $this->renderWithLayout($response, 'admin/projects/detail.php', [
            'title' => $project->name,
            'project' => $project,
            'csrfToken' => CSRFProtection::generateToken(),
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
        $filters = $this->extractAuditFilters($params);
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if (!$scope['is_super_admin']) {
            if (!empty($filters['project_uuid']) && !$this->canAccessProjectUuid((string) $filters['project_uuid'])) {
                $filters['project_uuid'] = '__no_access__';
            } else {
                $filters['project_ids'] = $scope['project_ids'];
            }
        }

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

    public function auditExport(Request $request, Response $response): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_audit')) !== null) {
            return $deny;
        }

        $params = $request->getQueryParams();
        $filters = $this->extractAuditFilters($params);
        $limit = max(1, min(10000, (int) ($params['limit'] ?? 2000)));
        $detached = ((string) ($params['detached'] ?? '0')) === '1';
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if (!$scope['is_super_admin']) {
            if (!empty($filters['project_uuid']) && !$this->canAccessProjectUuid((string) $filters['project_uuid'])) {
                $filters['project_uuid'] = '__no_access__';
            } else {
                $filters['project_ids'] = $scope['project_ids'];
            }
        }

        $audit = new AuditLogger();
        $rows = $audit->search($filters, $limit, 0);

        $handle = fopen('php://temp', 'r+');
        if ($handle === false) {
            return $response->withStatus(500);
        }

        fputcsv($handle, [
            'created_at', 'event_type', 'outcome', 'message', 'correlation_id',
            'ip_address', 'actor_user_uuid', 'project_uuid', 'oauth_client_public_id',
            'webauthn_credential_public_id', 'target_type', 'target_id', 'metadata_json',
        ]);

        foreach ($rows as $row) {
            fputcsv($handle, [
                (string) ($row['created_at'] ?? ''),
                (string) ($row['event_type'] ?? ''),
                (string) ($row['outcome'] ?? ''),
                (string) ($row['message'] ?? ''),
                (string) ($row['correlation_id'] ?? ''),
                (string) ($row['ip_address'] ?? ''),
                (string) ($row['actor_user_uuid'] ?? ''),
                (string) ($row['project_uuid'] ?? ''),
                (string) ($row['oauth_client_public_id'] ?? ''),
                (string) ($row['webauthn_credential_public_id'] ?? ''),
                (string) ($row['target_type'] ?? ''),
                (string) ($row['target_id'] ?? ''),
                (string) ($row['metadata_json'] ?? ''),
            ]);
        }

        rewind($handle);
        $csv = stream_get_contents($handle);
        fclose($handle);
        if ($csv === false) {
            return $response->withStatus(500);
        }

        $filename = 'audit_export_' . gmdate('Ymd_His') . '.csv';
        $sha256 = AuditExportSigner::sha256($csv);
        $signature = AuditExportSigner::signIfConfigured($csv);

        /** @var AuditLogger|null $requestAudit */
        $requestAudit = $request->getAttribute('audit_logger');
        if ($requestAudit instanceof AuditLogger) {
            $requestAudit->logInfo('admin.audit.export', [
                'actor_user_id' => (int) SessionManager::get('user_id'),
                'message' => 'Exported filtered audit logs (rows=' . count($rows) . ', detached=' . ($detached ? 'yes' : 'no') . ')',
                'target_type' => 'audit_export',
                'target_id' => $filename,
            ]);
        }

        if ($detached) {
            $manifest = [
                'filename' => $filename,
                'generated_at_utc' => gmdate('c'),
                'row_count' => count($rows),
                'sha256' => $sha256,
                'signature' => $signature['signature'] ?? null,
                'signature_algorithm' => $signature['algorithm'] ?? null,
                'signature_key_id' => $signature['key_id'] ?? null,
                'download_url' => '/admin/audit/export?' . http_build_query(array_merge($filters, ['limit' => $limit])),
                'filters' => $filters,
            ];
            $response->getBody()->write((string) json_encode($manifest, JSON_PRETTY_PRINT));
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Cache-Control', 'no-store');
        }

        $response->getBody()->write($csv);
        $response = $response
            ->withHeader('Content-Type', 'text/csv; charset=utf-8')
            ->withHeader('Content-Disposition', 'attachment; filename="' . $filename . '"')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('X-BlackWall-Audit-Export-SHA256', $sha256);

        if ($signature !== null) {
            $response = $response
                ->withHeader('X-BlackWall-Audit-Export-Signature', $signature['signature'])
                ->withHeader('X-BlackWall-Audit-Export-Signature-Alg', $signature['algorithm'])
                ->withHeader('X-BlackWall-Audit-Export-Signature-Key-Id', $signature['key_id']);
        }

        return $response;
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
        if (!$this->canAccessUserId($userId)) {
            return $response->withStatus(403);
        }

        // Get WebAuthn credentials
        $credentials = $this->webauthn->getUserCredentials($userId);

        // Get project assignments (scoped for non-super admins)
        $db = \BlackWall\Database::getInstance();
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if ($scope['is_super_admin']) {
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
        } else {
            $placeholders = implode(',', array_fill(0, count($scope['project_ids']), '?'));
            $stmt = $db->prepare(
                "SELECT upr.*, p.uuid AS project_uuid, p.name as project_name, ppl.name AS privilege_name
                 FROM user_project_roles upr
                 JOIN projects p ON upr.project_id = p.id
                 LEFT JOIN project_privilege_levels ppl
                   ON ppl.project_id = upr.project_id
                  AND ppl.level = upr.privilege_level
                 WHERE upr.user_id = ?
                   AND upr.project_id IN ({$placeholders})
                 ORDER BY upr.created_at DESC"
            );
            $stmt->execute(array_merge([$userId], $scope['project_ids']));
        }
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
        if (!$this->canAccessUserId($userId)) {
            return $response->withStatus(403);
        }
        $body = $request->getParsedBody();

        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'user_update', '/admin/users/' . $user->uuid)) !== null) {
            return $limited;
        }

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
            && $this->isUserScopedSuperAdmin($user->id)
        );
        if (
            $isDisablingActiveSuperAdmin
            && $this->countActiveScopedSuperAdmins() <= 1
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
    public function projectUpdate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_projects')) !== null) {
            return $deny;
        }

        $projectUuid = (string) ($args['projectUuid'] ?? '');
        $project = $this->projectRepo->findByUuid($projectUuid);
        if (!$project) {
            return $response->withStatus(404);
        }
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'project_update', '/admin/projects/' . $project->uuid)) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}?error=csrf")->withStatus(302);
        }

        $name = trim((string) ($body['name'] ?? ''));
        $status = (string) ($body['status'] ?? 'active');
        if ($name === '' || !in_array($status, ['active', 'disabled'], true)) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}?error=invalid")->withStatus(302);
        }

        if (AdminMutationPolicy::shouldRequireProjectSettingsApproval(
            $this->hasCapability('update_project_settings_direct'),
            $project->name,
            $project->status,
            $name,
            $status
        )) {
            $this->approvalService->create(
                'update_project_settings',
                [
                    'project_uuid' => $project->uuid,
                    'requested_name' => $name,
                    'requested_status' => $status,
                ],
                $actorUserId,
                $project->id
            );

            return $response->withHeader('Location', "/admin/projects/{$project->uuid}?success=settings_change_requested")->withStatus(302);
        }

        $this->projectRepo->update($project->id, $name, $status);

        $audit->logSuccess('admin.project.update', [
            'actor_user_id' => $actorUserId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'target_type' => 'project',
            'target_id' => $project->uuid,
            'message' => "Updated project settings (status={$status})",
        ]);

        return $response->withHeader('Location', "/admin/projects/{$project->uuid}?success=updated")->withStatus(302);
    }

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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
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
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'privilege_create', '/admin/projects/' . $project->uuid . '/privileges')) !== null) {
            return $limited;
        }

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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'privilege_update', '/admin/projects/' . $project->uuid . '/privileges')) !== null) {
            return $limited;
        }

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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'privilege_delete', '/admin/projects/' . $project->uuid . '/privileges')) !== null) {
            return $limited;
        }

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
                $actorUserId,
                $project->id
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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
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

        // Get all users for the dropdown (scoped for non-super admins)
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        if ($scope['is_super_admin']) {
            $allUsers = $this->userRepo->findAll();
        } else {
            $placeholders = implode(',', array_fill(0, count($scope['project_ids']), '?'));
            $stmt = $db->prepare(
                "SELECT DISTINCT u.*
                 FROM users u
                 JOIN user_project_roles upr ON upr.user_id = u.id
                 WHERE upr.project_id IN ({$placeholders})
                 ORDER BY u.created_at DESC"
            );
            $stmt->execute($scope['project_ids']);
            $rows = $stmt->fetchAll();
            $allUsers = array_map(
                static fn(array $row): \BlackWall\Model\User => new \BlackWall\Model\User(
                    id: (int) $row['id'],
                    uuid: (string) $row['uuid'],
                    displayLabel: $row['display_label'],
                    status: (string) $row['status'],
                    createdAt: new \DateTimeImmutable((string) $row['created_at']),
                    updatedAt: new \DateTimeImmutable((string) $row['updated_at'])
                ),
                $rows
            );
        }

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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }
        $projectId = $project->id;
        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'assignment_create', '/admin/projects/' . $project->uuid . '/assignments')) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=csrf")->withStatus(302);
        }

        $userId = (int) ($body['user_id'] ?? 0);
        $privilegeLevel = (int) ($body['privilege_level'] ?? 0);

        if (!$userId || !$privilegeLevel) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=invalid")->withStatus(302);
        }
        if (!$this->canAccessUserId($userId)) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=user_out_of_scope")->withStatus(302);
        }

        // Check if assignment already exists
        $existing = $this->roleRepo->findByUserAndProject($userId, $projectId);
        if ($existing) {
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?error=exists")->withStatus(302);
        }

        if (AdminMutationPolicy::shouldRequireAssignmentApproval($this->hasCapability('assignment_mutations_direct'))) {
            $this->approvalService->create(
                'create_assignment',
                [
                    'project_uuid' => $project->uuid,
                    'user_id' => $userId,
                    'privilege_level' => $privilegeLevel,
                ],
                $actorUserId,
                $project->id
            );
            return $response->withHeader('Location', "/admin/projects/{$project->uuid}/assignments?success=create_requested")->withStatus(302);
        }

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
        $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'assignment_update', $referer)) !== null) {
            return $limited;
        }
        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', $referer)->withStatus(302);
        }

        $privilegeLevel = (int) ($body['privilege_level'] ?? 0);
        if ($privilegeLevel < 1 || $privilegeLevel > 10) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }

        $assignment = $this->roleRepo->findById($assignmentId);
        if ($assignment === null) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }
        if (!$this->canAccessProjectId($assignment->projectId)) {
            return $response->withStatus(403);
        }

        if (AdminMutationPolicy::shouldRequireAssignmentApproval($this->hasCapability('assignment_mutations_direct'))) {
            $this->approvalService->create(
                'update_assignment',
                [
                    'assignment_id' => $assignmentId,
                    'requested_privilege_level' => $privilegeLevel,
                ],
                (int) SessionManager::get('user_id'),
                $assignment->projectId
            );
            return $response->withHeader('Location', $this->appendQueryParam($referer, 'success', 'update_requested'))->withStatus(302);
        }

        $this->roleRepo->update($assignmentId, $privilegeLevel);
        $audit->logSuccess('admin.assignment.update', [
            'actor_user_id' => (int) SessionManager::get('user_id'),
            'project_id' => $assignment->projectId,
            'target_type' => 'user_project_role',
            'target_id' => (string) $assignment->id,
            'message' => "Updated assignment privilege level to {$privilegeLevel}",
        ]);

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
        $referer = $request->getHeaderLine('Referer') ?: '/admin/projects';
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'assignment_delete', $referer)) !== null) {
            return $limited;
        }
        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', $referer)->withStatus(302);
        }

        $assignmentId = (int) $args['id'];
        $assignment = $this->roleRepo->findById($assignmentId);
        if ($assignment === null) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }
        if (!$this->canAccessProjectId($assignment->projectId)) {
            return $response->withStatus(403);
        }

        if (AdminMutationPolicy::shouldRequireAssignmentApproval($this->hasCapability('assignment_mutations_direct'))) {
            $this->approvalService->create(
                'delete_assignment',
                [
                    'assignment_id' => $assignmentId,
                ],
                $actorUserId,
                $assignment->projectId
            );
            return $response->withHeader('Location', $this->appendQueryParam($referer, 'success', 'delete_requested'))->withStatus(302);
        }

        $this->roleRepo->delete($assignmentId);
        $audit->logSuccess('admin.assignment.delete', [
            'actor_user_id' => $actorUserId,
            'project_id' => $assignment->projectId,
            'target_type' => 'user_project_role',
            'target_id' => (string) $assignment->id,
            'message' => "Removed assignment for user {$assignment->userId}",
        ]);

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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
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
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }
        $projectId = $project->id;
        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'client_create', '/admin/projects/' . $project->uuid . '/clients')) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
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
        if ($project === null) {
            return $response->withStatus(404);
        }
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }

        $secret = $request->getQueryParams()['secret'] ?? null;

        return $this->renderWithLayout($response, 'admin/clients/detail.php', [
            'title' => 'OAuth Client',
            'client' => $client,
            'project' => $project,
            'secret' => $secret,
            'csrfToken' => CSRFProtection::generateToken(),
        ]);
    }

    public function clientUpdate(Request $request, Response $response, array $args): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'manage_clients')) !== null) {
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
        if ($project === null) {
            return $response->withStatus(404);
        }
        if (!$this->canAccessProjectId($project->id)) {
            return $response->withStatus(403);
        }

        $body = $request->getParsedBody();
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        $actorUserId = (int) SessionManager::get('user_id');
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'client_update', '/admin/clients/' . $clientPublicId)) !== null) {
            return $limited;
        }
        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', "/admin/clients/{$clientPublicId}?error=csrf")->withStatus(302);
        }

        $name = trim((string) ($body['name'] ?? ''));
        $status = (string) ($body['status'] ?? 'active');
        $redirectUrisRaw = (string) ($body['redirect_uris'] ?? '');
        $redirectUris = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $redirectUrisRaw) ?: [])));
        $scopes = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string) ($body['scopes'] ?? '')) ?: [])));
        $accessTokenType = (string) ($body['access_token_type'] ?? $client['access_token_type']);
        $accessTokenLifetime = (int) ($body['access_token_lifetime'] ?? $client['access_token_lifetime']);
        $refreshTokenLifetime = (int) ($body['refresh_token_lifetime'] ?? $client['refresh_token_lifetime']);
        $oidcEnabled = isset($body['oidc_enabled']) ? 1 : 0;

        if (
            $name === ''
            || !in_array($status, ['active', 'disabled'], true)
            || empty($redirectUris)
            || !in_array($accessTokenType, ['jwt', 'opaque'], true)
            || $accessTokenLifetime < 60
            || $accessTokenLifetime > 86400
            || $refreshTokenLifetime < 300
            || $refreshTokenLifetime > 7776000
        ) {
            return $response->withHeader('Location', "/admin/clients/{$clientPublicId}?error=invalid")->withStatus(302);
        }

        $currentSettings = [
            'name' => (string) $client['name'],
            'status' => (string) $client['status'],
            'redirect_uris' => json_decode((string) ($client['redirect_uris'] ?? '[]'), true) ?: [],
            'scopes' => json_decode((string) ($client['scopes'] ?? '[]'), true) ?: [],
            'access_token_type' => (string) ($client['access_token_type'] ?? 'jwt'),
            'access_token_lifetime' => (int) ($client['access_token_lifetime'] ?? 3600),
            'refresh_token_lifetime' => (int) ($client['refresh_token_lifetime'] ?? 2592000),
            'oidc_enabled' => (int) ($client['oidc_enabled'] ?? 1),
        ];
        $requestedSettings = [
            'name' => $name,
            'status' => $status,
            'redirect_uris' => $redirectUris,
            'scopes' => $scopes,
            'access_token_type' => $accessTokenType,
            'access_token_lifetime' => $accessTokenLifetime,
            'refresh_token_lifetime' => $refreshTokenLifetime,
            'oidc_enabled' => $oidcEnabled,
        ];

        if (AdminMutationPolicy::shouldRequireClientSettingsApproval(
            $this->hasCapability('update_client_settings_direct'),
            $currentSettings,
            $requestedSettings
        )) {
            $this->approvalService->create(
                'update_client_settings',
                [
                    'client_public_id' => $clientPublicId,
                    'settings' => $requestedSettings,
                ],
                $actorUserId,
                $project->id
            );

            return $response->withHeader('Location', "/admin/clients/{$clientPublicId}?success=settings_change_requested")->withStatus(302);
        }

        $grants = json_decode((string) ($client['grants'] ?? '[]'), true);
        $grants = is_array($grants) && !empty($grants) ? $grants : ['authorization_code', 'refresh_token'];

        $this->clientRepo->update((int) $client['id'], [
            'name' => $name,
            'redirect_uris' => $redirectUris,
            'grants' => $grants,
            'scopes' => $scopes,
            'access_token_type' => $accessTokenType,
            'access_token_lifetime' => $accessTokenLifetime,
            'refresh_token_lifetime' => $refreshTokenLifetime,
            'oidc_enabled' => $oidcEnabled,
            'status' => $status,
        ]);

        $audit->logSuccess('admin.client.update', [
            'actor_user_id' => $actorUserId,
            'project_id' => $project->id,
            'project_uuid' => $project->uuid,
            'oauth_client_public_id' => $clientPublicId,
            'target_type' => 'oauth_client',
            'target_id' => $clientPublicId,
            'message' => "Updated OAuth client settings (status={$status})",
        ]);

        return $response->withHeader('Location', "/admin/clients/{$clientPublicId}?success=updated")->withStatus(302);
    }

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
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'user_enrollment_link', '/admin/users/' . $userUuid)) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userUuid)->withStatus(302);
        }

        $user = $this->userRepo->findByUuid($userUuid);
        if (!$user) {
            return $response->withStatus(404);
        }
        $userId = $user->id;
        if (!$this->canAccessUserId($userId)) {
            return $response->withStatus(403);
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
        if (($limited = $this->enforceAdminMutationRateLimit($request, $response, $audit, 'credential_delete', '/admin/users/' . $userUuid)) !== null) {
            return $limited;
        }

        if (!CSRFProtection::validateToken($body['csrf_token'] ?? '')) {
            $audit->logFail('security.csrf.fail');
            return $response->withHeader('Location', '/admin/users/' . $userUuid)->withStatus(302);
        }

        $user = $this->userRepo->findByUuid($userUuid);
        if (!$user) {
            return $response->withStatus(404);
        }
        $userId = $user->id;
        if (!$this->canAccessUserId($userId)) {
            return $response->withStatus(403);
        }

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
                if (!$this->canAccessUserId($user->id)) {
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
                if (!$this->canAccessUserId($user->id)) {
                    return false;
                }

                $isDisablingActiveSuperAdmin = (
                    $user->status === 'active'
                    && $requestedStatus === 'disabled'
                    && $this->isUserScopedSuperAdmin($user->id)
                );
                if (
                    $isDisablingActiveSuperAdmin
                    && $this->countActiveScopedSuperAdmins() <= 1
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
                if (!$this->canAccessProjectId($level->projectId)) {
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

            case 'create_assignment':
                $projectUuid = (string) ($payload['project_uuid'] ?? '');
                $userId = (int) ($payload['user_id'] ?? 0);
                $privilegeLevel = (int) ($payload['privilege_level'] ?? 0);
                if ($projectUuid === '' || $userId < 1 || $privilegeLevel < 1 || $privilegeLevel > 10) {
                    return false;
                }

                $project = $this->projectRepo->findByUuid($projectUuid);
                if ($project === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($project->id)) {
                    return false;
                }
                if (!$this->canAccessUserId($userId)) {
                    return false;
                }

                $existing = $this->roleRepo->findByUserAndProject($userId, $project->id);
                if ($existing !== null) {
                    return false;
                }

                $created = $this->roleRepo->create($userId, $project->id, $privilegeLevel);
                $audit = new AuditLogger();
                $audit->logSuccess('admin.assignment.create.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $project->id,
                    'project_uuid' => $project->uuid,
                    'target_type' => 'user_project_role',
                    'target_id' => (string) $created->id,
                    'message' => "Assignment created via approval workflow (user_id={$userId}, level={$privilegeLevel})",
                ]);
                return true;

            case 'update_assignment':
                $assignmentId = (int) ($payload['assignment_id'] ?? 0);
                $requestedLevel = (int) ($payload['requested_privilege_level'] ?? 0);
                if ($assignmentId < 1 || $requestedLevel < 1 || $requestedLevel > 10) {
                    return false;
                }

                $assignment = $this->roleRepo->findById($assignmentId);
                if ($assignment === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($assignment->projectId)) {
                    return false;
                }

                $this->roleRepo->update($assignmentId, $requestedLevel);
                $audit = new AuditLogger();
                $audit->logSuccess('admin.assignment.update.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $assignment->projectId,
                    'target_type' => 'user_project_role',
                    'target_id' => (string) $assignment->id,
                    'message' => "Assignment updated via approval workflow (level={$requestedLevel})",
                ]);
                return true;

            case 'delete_assignment':
                $assignmentId = (int) ($payload['assignment_id'] ?? 0);
                if ($assignmentId < 1) {
                    return false;
                }

                $assignment = $this->roleRepo->findById($assignmentId);
                if ($assignment === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($assignment->projectId)) {
                    return false;
                }

                $this->roleRepo->delete($assignmentId);
                $audit = new AuditLogger();
                $audit->logSuccess('admin.assignment.delete.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $assignment->projectId,
                    'target_type' => 'user_project_role',
                    'target_id' => (string) $assignment->id,
                    'message' => "Assignment deleted via approval workflow (user_id={$assignment->userId})",
                ]);
                return true;

            case 'update_project_settings':
                $projectUuid = (string) ($payload['project_uuid'] ?? '');
                $requestedName = trim((string) ($payload['requested_name'] ?? ''));
                $requestedStatus = (string) ($payload['requested_status'] ?? '');
                if ($projectUuid === '' || $requestedName === '' || !in_array($requestedStatus, ['active', 'disabled'], true)) {
                    return false;
                }

                $project = $this->projectRepo->findByUuid($projectUuid);
                if ($project === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($project->id)) {
                    return false;
                }

                $this->projectRepo->update($project->id, $requestedName, $requestedStatus);
                $audit = new AuditLogger();
                $audit->logSuccess('admin.project.update.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $project->id,
                    'project_uuid' => $project->uuid,
                    'target_type' => 'project',
                    'target_id' => $project->uuid,
                    'message' => "Project settings updated via approval workflow (status={$requestedStatus})",
                ]);
                return true;

            case 'update_client_settings':
                $clientPublicId = (string) ($payload['client_public_id'] ?? '');
                $settings = $payload['settings'] ?? null;
                if ($clientPublicId === '' || !is_array($settings)) {
                    return false;
                }

                $name = trim((string) ($settings['name'] ?? ''));
                $status = (string) ($settings['status'] ?? '');
                $redirectUris = is_array($settings['redirect_uris'] ?? null) ? $settings['redirect_uris'] : [];
                $scopes = is_array($settings['scopes'] ?? null) ? $settings['scopes'] : [];
                $accessTokenType = (string) ($settings['access_token_type'] ?? '');
                $accessTokenLifetime = (int) ($settings['access_token_lifetime'] ?? 0);
                $refreshTokenLifetime = (int) ($settings['refresh_token_lifetime'] ?? 0);
                $oidcEnabled = (int) (($settings['oidc_enabled'] ?? 0) ? 1 : 0);

                if (
                    $name === ''
                    || !in_array($status, ['active', 'disabled'], true)
                    || empty($redirectUris)
                    || !in_array($accessTokenType, ['jwt', 'opaque'], true)
                    || $accessTokenLifetime < 60
                    || $accessTokenLifetime > 86400
                    || $refreshTokenLifetime < 300
                    || $refreshTokenLifetime > 7776000
                ) {
                    return false;
                }

                $client = $this->clientRepo->findByClientId($clientPublicId);
                if ($client === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($client->projectId)) {
                    return false;
                }

                $this->clientRepo->update($client->id, [
                    'name' => $name,
                    'redirect_uris' => $redirectUris,
                    'grants' => $client->grants,
                    'scopes' => $scopes,
                    'access_token_type' => $accessTokenType,
                    'access_token_lifetime' => $accessTokenLifetime,
                    'refresh_token_lifetime' => $refreshTokenLifetime,
                    'oidc_enabled' => $oidcEnabled,
                    'status' => $status,
                ]);

                $audit = new AuditLogger();
                $audit->logSuccess('admin.client.update.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $client->projectId,
                    'oauth_client_public_id' => $client->clientId,
                    'target_type' => 'oauth_client',
                    'target_id' => $client->clientId,
                    'message' => "OAuth client settings updated via approval workflow (status={$status})",
                ]);
                return true;

            case 'change_project_status':
                $projectUuid = (string) ($payload['project_uuid'] ?? '');
                $requestedStatus = (string) ($payload['requested_status'] ?? '');
                if ($projectUuid === '' || !in_array($requestedStatus, ['active', 'disabled'], true)) {
                    return false;
                }

                $project = $this->projectRepo->findByUuid($projectUuid);
                if ($project === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($project->id)) {
                    return false;
                }

                $this->projectRepo->update($project->id, $project->name, $requestedStatus);

                /** @var AuditLogger $audit */
                $audit = new AuditLogger();
                $audit->logSuccess('admin.project.status_change.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $project->id,
                    'project_uuid' => $project->uuid,
                    'target_type' => 'project',
                    'target_id' => $project->uuid,
                    'message' => "Project status changed to {$requestedStatus} via approval workflow",
                ]);

                return true;

            case 'change_client_status':
                $clientPublicId = (string) ($payload['client_public_id'] ?? '');
                $requestedStatus = (string) ($payload['requested_status'] ?? '');
                if ($clientPublicId === '' || !in_array($requestedStatus, ['active', 'disabled'], true)) {
                    return false;
                }

                $client = $this->clientRepo->findByClientId($clientPublicId);
                if ($client === null) {
                    return false;
                }
                if (!$this->canAccessProjectId($client->projectId)) {
                    return false;
                }

                $this->clientRepo->update($client->id, [
                    'name' => $client->name,
                    'redirect_uris' => $client->redirectUris,
                    'grants' => $client->grants,
                    'scopes' => $client->scopes,
                    'access_token_type' => $client->accessTokenType,
                    'access_token_lifetime' => $client->accessTokenLifetime,
                    'refresh_token_lifetime' => $client->refreshTokenLifetime,
                    'oidc_enabled' => $client->oidcEnabled ? 1 : 0,
                    'status' => $requestedStatus,
                ]);

                /** @var AuditLogger $audit */
                $audit = new AuditLogger();
                $audit->logSuccess('admin.client.status_change.approved', [
                    'actor_user_id' => $actorUserId,
                    'project_id' => $client->projectId,
                    'oauth_client_public_id' => $client->clientId,
                    'target_type' => 'oauth_client',
                    'target_id' => $client->clientId,
                    'message' => "OAuth client status changed to {$requestedStatus} via approval workflow",
                ]);

                return true;
        }

        return false;
    }

    private function enforceAdminMutationRateLimit(
        Request $request,
        Response $response,
        AuditLogger $audit,
        string $action,
        string $redirectUrl
    ): ?Response {
        $maxAttempts = max(1, Config::getInt('ADMIN_MUTATION_RATE_LIMIT_ATTEMPTS', 60));
        $windowSeconds = max(1, Config::getInt('ADMIN_MUTATION_RATE_LIMIT_WINDOW_SECONDS', 60));

        $userId = (int) SessionManager::get('user_id');
        $ipAddress = (string) ($request->getAttribute('ip_address') ?? '0.0.0.0');
        $identifier = "admin_user:{$userId}|ip:{$ipAddress}";

        $limiter = new RateLimiter();
        if ($limiter->check($identifier, 'admin.mutation.' . $action, $maxAttempts, $windowSeconds)) {
            return null;
        }

        $audit->logFail('security.rate_limit.admin_mutation', [
            'actor_user_id' => $userId,
            'ip_address' => $ipAddress,
            'message' => "Admin mutation rate limit exceeded for {$action}",
        ]);

        return $response
            ->withHeader('Location', $this->appendQueryParam($redirectUrl, 'error', 'rate_limited'))
            ->withStatus(302);
    }

    private function appendQueryParam(string $url, string $key, string $value): string
    {
        $separator = str_contains($url, '?') ? '&' : '?';
        return $url . $separator . rawurlencode($key) . '=' . rawurlencode($value);
    }

    private function renderDocsPage(Response $response, string $slug): Response
    {
        if (!$this->checkAuth()) {
            return $response->withHeader('Location', '/admin/login')->withStatus(302);
        }
        if (($deny = $this->requireCapability($response, 'view_docs')) !== null) {
            return $deny;
        }

        $pages = $this->docsGuidePages();
        if (!isset($pages[$slug])) {
            return $response->withStatus(404);
        }

        $orderedSlugs = array_keys($pages);
        $currentIndex = array_search($slug, $orderedSlugs, true);
        $previousSlug = ($currentIndex !== false && $currentIndex > 0) ? $orderedSlugs[$currentIndex - 1] : null;
        $nextSlug = ($currentIndex !== false && $currentIndex < count($orderedSlugs) - 1) ? $orderedSlugs[$currentIndex + 1] : null;

        return $this->renderWithLayout($response, 'admin/docs/guide.php', [
            'title' => 'Documentation',
            'docsPages' => $pages,
            'currentSlug' => $slug,
            'currentPage' => $pages[$slug],
            'previousSlug' => $previousSlug,
            'nextSlug' => $nextSlug,
        ]);
    }

    private function docsGuidePages(): array
    {
        return [
            'overview' => [
                'title' => 'Overview',
                'summary' => 'Platform purpose, capability model, and documentation map.',
                'template' => 'overview.php',
            ],
            'quick-start' => [
                'title' => 'Administrator Quick Start',
                'summary' => 'First-session steps and immediate safety checks.',
                'template' => 'quick_start.php',
            ],
            'access-model' => [
                'title' => 'Access Model and Scope',
                'summary' => 'How admin scope, super admin rules, and visibility boundaries work.',
                'template' => 'access_model.php',
            ],
            'users-and-enrolment' => [
                'title' => 'Users and Enrolment',
                'summary' => 'User lifecycle, enrolment links, WebAuthn credentials, and status control.',
                'template' => 'users_and_enrolment.php',
            ],
            'projects-and-privileges' => [
                'title' => 'Projects, Privileges, and Assignments',
                'summary' => 'Project governance, privilege levels, and assignment administration.',
                'template' => 'projects_and_privileges.php',
            ],
            'oauth-clients' => [
                'title' => 'OAuth Clients and Authorisation Flows',
                'summary' => 'Client configuration, security posture, and flow expectations.',
                'template' => 'oauth_clients.php',
            ],
            'approvals' => [
                'title' => 'Approvals Workflow',
                'summary' => 'Submission, decisioning, denial reasons, and operational handling.',
                'template' => 'approvals.php',
            ],
            'audit-and-security' => [
                'title' => 'Audit and Security Operations',
                'summary' => 'Audit search/export, security indicators, and response actions.',
                'template' => 'audit_and_security.php',
            ],
            'metrics-and-vmagent' => [
                'title' => 'Metrics and vmagent Event Push',
                'summary' => 'Dashboard metrics, event push configuration, and validation.',
                'template' => 'metrics_and_vmagent.php',
            ],
            'maintenance-and-dr' => [
                'title' => 'Maintenance, Backup, and Recovery',
                'summary' => 'Routine maintenance, backup standards, and recovery rehearsal.',
                'template' => 'maintenance_and_dr.php',
            ],
            'troubleshooting' => [
                'title' => 'Troubleshooting and Diagnostics',
                'summary' => 'Common faults, diagnostic sequence, and corrective actions.',
                'template' => 'troubleshooting.php',
            ],
            'reference' => [
                'title' => 'Reference and Glossary',
                'summary' => 'Environment variable reference, route index, and glossary.',
                'template' => 'reference.php',
            ],
        ];
    }

    private function dashboardSecurityEventStats(
        \PDO $db,
        string $eventType,
        bool $isSuperAdmin,
        array $projectIds
    ): array {
        if (!$isSuperAdmin && empty($projectIds)) {
            return ['today' => 0, 'week' => 0, 'month' => 0];
        }

        if ($isSuperAdmin) {
            $stmt = $db->prepare(
                "SELECT
                    SUM(created_at >= CURDATE()) AS today_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
                 FROM audit_log
                 WHERE event_type = ?"
            );
            $stmt->execute([$eventType]);
        } else {
            $placeholders = implode(',', array_fill(0, count($projectIds), '?'));
            $stmt = $db->prepare(
                "SELECT
                    SUM(created_at >= CURDATE()) AS today_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS week_count,
                    SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS month_count
                 FROM audit_log
                 WHERE event_type = ?
                   AND project_id IN ({$placeholders})"
            );
            $stmt->execute(array_merge([$eventType], $projectIds));
        }

        $row = $stmt->fetch() ?: [];
        return [
            'today' => (int) ($row['today_count'] ?? 0),
            'week' => (int) ($row['week_count'] ?? 0),
            'month' => (int) ($row['month_count'] ?? 0),
        ];
    }

    private function dashboardSecurityTopProjects(
        \PDO $db,
        string $eventType,
        bool $isSuperAdmin,
        array $projectIds,
        int $limit = 5
    ): array {
        if (!$isSuperAdmin && empty($projectIds)) {
            return [];
        }

        if ($isSuperAdmin) {
            $stmt = $db->prepare(
                "SELECT
                    COALESCE(MAX(p.uuid), 'unscoped') AS project_uuid,
                    COALESCE(MAX(p.name), 'Unscoped') AS project_name,
                    COUNT(*) AS month_count
                 FROM audit_log a
                 LEFT JOIN projects p ON p.id = a.project_id
                 WHERE a.event_type = ?
                   AND a.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                 GROUP BY COALESCE(a.project_id, 0)
                 ORDER BY month_count DESC
                 LIMIT {$limit}"
            );
            $stmt->execute([$eventType]);
        } else {
            $placeholders = implode(',', array_fill(0, count($projectIds), '?'));
            $stmt = $db->prepare(
                "SELECT
                    p.uuid AS project_uuid,
                    p.name AS project_name,
                    COUNT(*) AS month_count
                 FROM audit_log a
                 JOIN projects p ON p.id = a.project_id
                 WHERE a.event_type = ?
                   AND a.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                   AND a.project_id IN ({$placeholders})
                 GROUP BY p.uuid, p.name
                 ORDER BY month_count DESC
                 LIMIT {$limit}"
            );
            $stmt->execute(array_merge([$eventType], $projectIds));
        }

        return $stmt->fetchAll();
    }

    private function checkAuth(): bool
    {
        SessionManager::start();
        if (!SessionManager::has('user_id')) {
            return false;
        }

        $userId = (int) SessionManager::get('user_id');
        return $this->getAdminScope($userId)['is_admin'];
    }

    private function getAdminScope(int $userId): array
    {
        if ($userId < 1) {
            return [
                'is_admin' => false,
                'is_super_admin' => false,
                'project_ids' => [],
                'project_uuids' => [],
                'project_uuid_set' => [],
            ];
        }

        if ($this->cachedScope !== null && (int) ($this->cachedScope['user_id'] ?? 0) === $userId) {
            return $this->cachedScope;
        }

        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            "SELECT p.id, p.uuid, p.name
             FROM user_project_roles upr
             JOIN projects p ON p.id = upr.project_id
             WHERE upr.user_id = ? AND upr.privilege_level = 1"
        );
        $stmt->execute([$userId]);
        $rows = $stmt->fetchAll();

        $isAdmin = !empty($rows);
        $isSuperAdmin = false;
        $projectIds = [];
        $projectUuids = [];

        foreach ($rows as $row) {
            $projectIds[] = (int) $row['id'];
            $projectUuids[] = (string) $row['uuid'];
            if ($this->isSuperProject((string) $row['uuid'], (string) ($row['name'] ?? ''))) {
                $isSuperAdmin = true;
            }
        }

        if ($isSuperAdmin) {
            $all = $db->query('SELECT id, uuid FROM projects')->fetchAll();
            $projectIds = array_map(static fn(array $r): int => (int) $r['id'], $all);
            $projectUuids = array_map(static fn(array $r): string => (string) $r['uuid'], $all);
        }

        $scope = [
            'user_id' => $userId,
            'is_admin' => $isAdmin,
            'is_super_admin' => $isSuperAdmin,
            'project_ids' => array_values(array_unique($projectIds)),
            'project_uuids' => array_values(array_unique($projectUuids)),
            'project_uuid_set' => array_fill_keys(array_values(array_unique($projectUuids)), true),
        ];
        $this->cachedScope = $scope;
        return $scope;
    }

    private function canAccessProjectId(int $projectId): bool
    {
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        return AdminScopedViewPolicy::canAccessProjectId($scope, $projectId);
    }

    private function canAccessProjectUuid(string $projectUuid): bool
    {
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        return AdminScopedViewPolicy::canAccessProjectUuid($scope, $projectUuid);
    }

    private function canAccessUserId(int $userId): bool
    {
        $scope = $this->getAdminScope((int) SessionManager::get('user_id'));
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare('SELECT DISTINCT project_id FROM user_project_roles WHERE user_id = ?');
        $stmt->execute([$userId]);
        $userProjectIds = array_map(static fn(array $row): int => (int) $row['project_id'], $stmt->fetchAll());
        return AdminScopedViewPolicy::canAccessUserByProjects($scope, $userProjectIds);
    }

    private function isUserScopedSuperAdmin(int $userId): bool
    {
        if ($userId < 1) {
            return false;
        }

        $db = \BlackWall\Database::getInstance();
        $stmt = $db->prepare(
            "SELECT p.uuid, p.name
             FROM user_project_roles upr
             JOIN projects p ON p.id = upr.project_id
             WHERE upr.user_id = ? AND upr.privilege_level = 1"
        );
        $stmt->execute([$userId]);
        $rows = $stmt->fetchAll();

        foreach ($rows as $row) {
            if ($this->isSuperProject((string) $row['uuid'], (string) $row['name'])) {
                return true;
            }
        }

        return false;
    }

    private function countActiveScopedSuperAdmins(): int
    {
        $db = \BlackWall\Database::getInstance();
        $stmt = $db->query(
            "SELECT upr.user_id, p.uuid, p.name
             FROM user_project_roles upr
             JOIN projects p ON p.id = upr.project_id
             JOIN users u ON u.id = upr.user_id
             WHERE upr.privilege_level = 1
               AND u.status = 'active'"
        );
        $rows = $stmt->fetchAll();

        $userIds = [];
        foreach ($rows as $row) {
            if ($this->isSuperProject((string) $row['uuid'], (string) $row['name'])) {
                $userIds[] = (int) $row['user_id'];
            }
        }

        return count(array_unique($userIds));
    }

    private function isSuperProject(string $projectUuid, string $projectName): bool
    {
        $adminProjectName = strtolower(trim((string) Config::get('ADMIN_SUPER_PROJECT_NAME', 'BlackWall Admin')));
        $adminProjectUuid = trim((string) Config::get('ADMIN_SUPER_PROJECT_UUID', ''));
        $rowName = strtolower(trim($projectName));
        return ($adminProjectUuid !== '' && $projectUuid === $adminProjectUuid) || $rowName === $adminProjectName;
    }

    private function extractAuditFilters(array $params): array
    {
        return [
            'date_from' => $params['date_from'] ?? null,
            'date_to' => $params['date_to'] ?? null,
            'project_uuid' => $params['project_uuid'] ?? null,
            'ip_address' => $params['ip_address'] ?? null,
            'event_type' => $params['event_type'] ?? null,
            'outcome' => $params['outcome'] ?? null,
            'correlation_id' => $params['correlation_id'] ?? null,
        ];
    }
}
