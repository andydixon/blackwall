# Implementation Guide

Namespace: `\\andydixon\\blackwall` (PSR-4), autoloaded via composer.

1. Install
   - Run `composer install` in this folder.
   - Ensure PHP >= 8.1.
2. Configure
   - Set env: `BW_DSN`, `BW_DB_USER`, `BW_DB_PASS`.
   - SSO env: `BW_SSO_CLIENT_ID`, `BW_SSO_CLIENT_SECRET`, `BW_SSO_AUTHORIZE_URL`, `BW_SSO_TOKEN_URL`, `BW_SSO_USERINFO_URL`, `BW_SSO_REDIRECT_URI`.
3. Database
   - Apply `sql/migrations.sql` to your DB.
   - `projects.id` is a UUID (CHAR(36)).
4. Routes
   - `/login` → redirects to provider authorize.
   - `/callback` → handles provider callback, validates `state`, stores user in session.
   - `/logout` → clears session.
   - `/admin` → admin page (see gating below).
5. Parent Auth Integration
   - The SSO provider expects parent system user IDs in `user_info` response as integer `id` and fields `email`, `name`.
   - Map existing users by their parent IDs; no separate users table here.
6. Project Privileges
   - Privilege values: 1=admin, 2=user, other=project-specific.
   - Use `UserProjectRepository::getPrivilege($userId,$projectId)` in your app to enforce access.
7. Admin Access Gating
   - Admin UI is restricted to users with privilege=1 on project named "SSO Administration".
   - The project is auto-created on first access if missing.
   - Seed at least one admin by inserting a row for their parent user_id and the project's UUID:
     - Create project if needed (example MySQL): `INSERT IGNORE INTO projects (id,name) VALUES (UUID(), 'SSO Administration');`
     - Find the project UUID: `SELECT id FROM projects WHERE name='SSO Administration';`
     - Grant admin: `INSERT INTO user_projects (user_id, project_id, privilege) VALUES (<user_id>, '<project_uuid>', 1) ON DUPLICATE KEY UPDATE privilege=VALUES(privilege);`
8. Usage in Existing Project
   - Specify target project UUID.
   - After `/callback`, read session user (`AuthSession::getUser()`), then check privileges.

Example:
```php
use andydixon\\blackwall\\Service\\AuthSession;
use andydixon\\blackwall\\Repository\\UserProjectRepository;

$user = AuthSession::getUser();
if (!$user) { header('Location: /login'); exit; }
$upr = new UserProjectRepository();
$up = $upr->getPrivilege((int)$user['id'], $projectUuid);
if (!$up || $up->privilege < 2) { http_response_code(403); echo 'Forbidden'; exit; }
```
