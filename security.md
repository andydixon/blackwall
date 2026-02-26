# BlackWall Security Model

Last reviewed: 2026-02-26

## Scope

This document defines the production security model for the BlackWall authentication platform:

- PHP custom web application (no framework authz layer)
- OAuth2/OIDC provider
- WebAuthn authentication ceremonies
- Admin interface
- User portal
- Cryptbin secure storage endpoints
- Multi-tenant data model (`organizations -> projects -> users/clients`, with key assignment relationships)

## Threat Model

Assumed attacker capabilities:

- Public internet access to all public endpoints
- Can self-register and create organizations/projects/clients where allowed
- Can send crafted IDs/UUIDs and cross-tenant references
- Can automate token, login, WebAuthn, and export endpoints
- Can attempt CSRF, IDOR, privilege escalation, stale-session reuse, and over-scoped OAuth flows

Out of scope:

- Full host compromise
- Compromise of external KMS/HSM layers not controlled by this application

## Data Classification

Highly sensitive:

- OAuth authorization codes, access tokens, refresh tokens
- OAuth client secrets
- WebAuthn credential public IDs + counters + linkage metadata
- Cryptbin wrapped DEKs and metadata bindings

Sensitive:

- Tenant identifiers and assignment metadata
- Audit records with actor/project/client linkage
- Enrollment URLs/tokens

Operational:

- Metrics and aggregate counters
- Documentation and static assets

## Tenant Isolation Invariants (Must Hold)

1. A request scoped to organization A must never read or mutate organization B resources.
2. Project-bound operations must validate project membership/access server-side for every request.
3. OAuth client operations must validate `client -> project -> organization` lineage.
4. Key/credential actions must validate ownership or explicit project-scoped authorization.
5. Approval decisions must enforce actor scope and action/project scope at decision time.
6. Portal views must show only active, in-scope project assignments for the authenticated user.
7. Any user-supplied ID/UUID must be re-bound to caller scope before database mutation.

## Core Security Controls

- CSRF protection on state-changing endpoints
- Strict redirect URI policy and exact-match validation
- PKCE S256 enforcement and authorization-code single use
- OIDC nonce replay protections
- Rate limiting on auth, OAuth control, and high-cost admin endpoints
- Active-state enforcement for users/projects/clients during critical auth flows
- Refresh-token rotation with reuse detection and token family revocation
- Refresh-scope revalidation against current client scope allowlist
- JWT revocation-aware userinfo checks
- WebAuthn challenge expiry + single-use semantics + UV/UP checks
- Session hardening (`Secure`, `HttpOnly`, `SameSite`, strict mode, ID rotation, cookie clear on destroy)
- Security headers middleware defaults (CSP, HSTS for HTTPS, frame/ctype/referrer/permissions controls)
- Audit logging for authz and security-relevant events

## Top Risks To Monitor

1. Cross-tenant IDOR in newly added endpoints.
2. Confused deputy admin actions where request IDs are accepted without scope re-binding.
3. OAuth client misconfiguration leading to unexpected `invalid_scope` / `invalid_grant` behavior.
4. Weak proxy trust configuration causing IP-based abuse-control bypass.
5. Regressions in CSRF enforcement for newly introduced POST mutations.

## Verification Checklist

Run locally before release:

```bash
composer test
composer test -- --display-warnings --display-deprecations --display-notices
```

Manual security checks:

1. Attempt cross-tenant access using foreign `organizationUuid`, `projectUuid`, `userUuid`, `clientPublicId`, and credential IDs.
2. Attempt OAuth authorize with a scope not enabled for the client and verify `invalid_scope`.
3. Rotate/tighten client scopes, then try refresh-token exchange and verify `invalid_grant`.
4. Verify logout invalidates server session and clears browser session cookie.
5. Verify admin mutation endpoints reject missing/invalid CSRF tokens.

## Change Management Rule

Security-relevant changes must:

- be small and reviewable,
- include regression tests that reproduce the attack path,
- be committed as one issue per commit with security-focused commit messages.
