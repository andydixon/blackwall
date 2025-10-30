# BlackWall User Manual (UK English)

## 1. Purpose

BlackWall is an OAuth 2.1 and OpenID Connect authorisation server with WebAuthn-based sign-in, scoped administration, project-level access control, audit logging, and approval workflows for sensitive actions.

This manual covers day-to-day use for:

- Administrators (`/admin`)
- Project users (`/portal`)
- Client operators integrating OAuth clients

## 2. Access Paths

- Home: `/`
- Admin sign-in: `/admin/login`
- Admin dashboard: `/admin/dashboard`
- User portal sign-in: `/portal/login`
- User portal dashboard: `/portal`
- Error trace decoder (authorised admins only): `/admin/error-trace`
- Scope diagnostics (authorised admins only): `/admin/scope`

## 2.1 Administrator Quick Start (First 15 Minutes)

1. Sign in at `/admin/login` with your WebAuthn authenticator.
2. Open `/admin/scope` and confirm your scope is correct.
3. Review `/admin/dashboard` for:
   - approval backlog
   - security widgets (CSRF and rate-limit hits)
4. Open `/admin/approvals` and check:
   - pending requests
   - denied decision reasons (`missing_capability`, `out_of_scope`, `self_decision`)
5. Open `/admin/audit` and verify recent login and admin activity entries.
6. If you are super admin, confirm at least one additional active super-admin path exists to avoid lockout risk.

## 3. Roles and Scope

### 3.1 Project Privilege Levels

- Level 1: `Admin`
- Level 2: `User`
- Level 3: `Restricted User`
- Other levels: `Custom Rules (level n)`

### 3.2 Admin Access Model

- A user can sign in to `/admin` if they are Level 1 on at least one project.
- Project admins can only view and manage data in their project scope.
- Super admins are users who are Level 1 on the configured admin project (`BlackWall Admin` by default, or `ADMIN_SUPER_PROJECT_UUID`).
- Super admins can view all projects and administrative data.

### 3.3 Scope Debugging

Use `/admin/scope` to inspect:

- current admin role scope
- scoped project UUIDs
- whether super-admin matching is active

## 4. Signing In

### 4.1 Admin Sign-In

1. Open `/admin/login`.
2. Complete WebAuthn verification.
3. On success, you are redirected to `/admin/dashboard`.

### 4.2 Portal Sign-In

1. Open `/portal/login`.
2. Complete WebAuthn verification.
3. You are redirected to `/portal`.

## 5. Admin Dashboard

The dashboard includes:

- high-level totals (users, projects, clients, audit logs)
- success/fail activity counts (today/week/month)
- event breakdown tables for success and fail outcomes
- approval KPI cards (`pending`, `approved`, `rejected`, `cancelled`)
- approval SLA indicators (median and P95 decision time)
- security widgets for:
  - CSRF failures (scoped)
  - admin mutation rate-limit hits (scoped)
- recent activity feed

## 6. Users

### 6.1 View Users

- Open `/admin/users`.
- Project admins see only users assigned to their scoped projects.
- Super admins see all users.

### 6.2 Create User

- Super admin only.
- Use `/admin/users/create`.

### 6.3 Edit User

On `/admin/users/{userUuid}` you can:

- update display label
- change status (`active` or `disabled`)
- generate an enrolment link
- request or perform credential deletion (subject to policy)

## 7. Projects

### 7.1 View Projects

- Open `/admin/projects`.
- Project admins see only in-scope projects.
- Super admins see all projects.

### 7.2 Create Project

- Super admin only.
- Use `/admin/projects/create`.

### 7.3 Project Detail

On `/admin/projects/{projectUuid}` you can:

- update project name/status
- open privilege levels
- manage assignments
- manage OAuth clients

## 8. Privilege Levels

Open `/admin/projects/{projectUuid}/privileges` to:

- add custom levels
- edit labels/descriptions
- delete unused levels (or submit approval where required)

## 9. Assignments

Open `/admin/projects/{projectUuid}/assignments` to:

- assign users to projects
- update privilege levels
- remove assignments

Assignment actions may require approval depending on policy and role capabilities.

## 10. OAuth Clients

Use `/admin/projects/{projectUuid}/clients` to:

- create a client
- view client settings
- update redirect URIs, scopes, token settings, and status

Sensitive client changes may require approval.

## 11. Approvals

Open `/admin/approvals` to:

- view pending and historical requests
- filter by status, action, project UUID, requester UUID, date, and denial reason
- approve/reject requests (authorised decision-makers only)
- cancel your own pending requests

Denial quick filters are available for:

- `missing_capability`
- `out_of_scope`
- `self_decision`

## 12. Audit Logs

Open `/admin/audit` to:

- search by date, project UUID, event type, outcome, IP, and correlation ID
- export filtered CSV data from `/admin/audit/export`

Project admins see only audit data in their scope.

## 13. Maintenance and Diagnostics

- Maintenance view: `/admin/maintenance` (super admin)
- Error trace decoder: `/admin/error-trace` (authorised admins)
- Scope diagnostics: `/admin/scope` (authorised admins)

## 14. Portal Key Management

In `/portal`, a user can:

- add WebAuthn keys
- remove keys (subject to minimum key retention policy)
- sign out

## 15. Common Errors and Resolutions

### 15.1 “The operation is insecure”

Usually indicates a browser/WebAuthn context issue. Check:

- HTTPS is valid
- RP ID/domain matches expected host
- browser WebAuthn support and security context

### 15.2 `403` on admin pages

Likely out-of-scope or missing capability. Check `/admin/scope`.

### 15.3 Approval cannot be decided

Possible reasons:

- request is no longer pending
- actor is the requester (self decision blocked)
- actor lacks capability
- request is outside actor scope

### 15.4 CSRF validation failed

Refresh the page and retry so a fresh token is used.

## 16. Good Operating Practice

- Keep at least one active super admin at all times.
- Review approval denials and execution failures regularly.
- Review scoped security widgets for unusual spikes.
- Use project UUID links rather than numeric IDs.
- Record incident context using correlation IDs from the audit log.

## 17. Glossary

- `Scope`: the set of projects an admin can view/manage.
- `Super admin`: admin with global scope via the configured admin project.
- `Approval request`: queued high-risk action requiring explicit decision.
- `SLA`: service-level indicator for approval decision latency.
