# Functionality and Next Steps Report

## 1. Executive Summary

BlackWall already covers a broad identity-management surface: WebAuthn login/enrollment, OAuth/OIDC, SAML IdP, SCIM, tenant/project administration, approval workflows, Cryptbin, webhooks, audit integrity, maintenance, and Terraform automation. The most valuable next work is to make those features operationally predictable: enforce machine-token scope intent, finish OIDC/SAML conformance, make multi-step writes transactional, add health/observability, and establish browser/protocol integration testing.

The audit fixed concrete correctness defects in SCIM default activation, OAuth introspection issuer output, app URL validation, one-time secret rendering, error handling, resource limits, webhook networking, and provider input/response handling.

## 2. Current Functional Risks

- **SCIM state semantics:** omitted `active` previously disabled newly created/replaced users. The decoder now distinguishes omitted from explicit `false`; retain regression coverage.
- **Partial database state:** organization signup and several admin workflows ignore `Exec`, `Scan`, or `LastInsertId` errors and perform related writes without transactions. A mid-flow failure can leave orphaned or active-but-unusable records.
- **Rate-limit accuracy:** the limiter now fails closed, but concurrent read-modify-write operations can lose increments.
- **OIDC conformance:** discovery advertises `fragment` and `form_post`, while authorization responses are effectively query-based. `max_age` and `id_token_hint` are documented but not enforced.
- **Operational startup:** database connection setup does not provide an explicit application readiness endpoint or strong startup/readiness contract.
- **Machine-token expectations:** scopes are displayed and stored but do not constrain behavior, which is likely to surprise operators and automation authors.
- **Public signup lifecycle:** tenant/user records become active before identity verification and abandoned signups lack a clear cleanup lifecycle.

## 3. Code Quality Improvements

1. Replace ignored database errors in security- and state-critical handlers with explicit propagation and structured logs. Start with signup, SAML project/user lookups, admin CRUD, and SCIM bulk/list paths.
2. Wrap multi-write state transitions in transactions with rollback: organization creation, enrollment setup, approval execution, user/project assignment changes, and OAuth client lifecycle changes.
3. Consolidate repeated request decoding/validation into typed helpers that preserve field presence, as done for SCIM `active`.
4. Make rate limiting atomic in SQL and expose a result type distinguishing allowed, blocked, and backend-failure states.
5. Replace global configuration access in services with injected immutable configuration to simplify tests and prevent hidden coupling.
6. Add bounded pagination consistently to admin lists, audit export, SCIM, and machine APIs; return stable cursors or explicit maximums.

## 4. Frontend Interaction and Error-Handling Improvements

- Self-host Bootstrap and move inline scripts/styles into versioned static assets so pages can run under a strict CSP.
- Add a shared frontend error boundary/helper for fetch/WebAuthn failures that displays a safe message and logs non-sensitive context with a correlation ID.
- Disable submit buttons while requests are in flight and restore them on every failure path to prevent duplicate mutations.
- Validate forms client-side only as convenience; keep server-side validation authoritative and map stable error codes to field-level feedback.
- Add graceful behavior when WebAuthn is unavailable, cancelled, times out, or returns an unsupported authenticator response.
- Test CDN/network failure and script load ordering until external assets are removed.

## 5. Testing Roadmap

- **Unit:** token scope matching, atomic rate-limit outcomes, OIDC response mode/max-age/id-token-hint logic, SAML signature/replay validation, transaction rollback helpers.
- **Integration:** MySQL-backed tenant isolation, admin capability plus token scope, signup/enrollment transactions, OAuth code/refresh/introspection lifecycle, SCIM pagination/filtering, webhook delivery and retry behavior.
- **End-to-end:** WebAuthn enrollment/login, OAuth consent and denial, SAML SP login, SCIM provisioning, Cryptbin create/share/view/delete, admin one-time secret display, logout/session invalidation.
- **Abuse/boundary:** maximum body/upload sizes, decompression bombs, parallel rate-limit attempts, distributed signup, large tenants, slow webhook destinations, DNS rebinding, malformed protocol documents.
- **Frontend:** Playwright checks for every form/button/modal, console-error assertions, accessibility scans, keyboard navigation, and narrow/mobile layouts.
- **Deployment:** container health/readiness, migrations from a prior release, backup/restore plus Cryptbin key recovery, reverse-proxy headers, and TLS-only production startup.

## 6. Recommended New Functionality

- Enforced, documented admin API scopes with token templates for Terraform, SCIM read/write, audit read, and full administration.
- Configurable self-signup policy: disabled, invite-only, verified-domain, or open with approval/quota.
- `/healthz` and `/readyz` endpoints separating process health from database/migration/key readiness.
- Webhook delivery queue with concurrency limits, retry policy, dead-letter inspection, destination status, and operator replay.
- Key lifecycle tooling for session/CSRF/audit/JWT/Cryptbin rotation, including Cryptbin DEK rewrap without data re-encryption.
- OIDC conformance completion for response modes, `max_age`, `id_token_hint`, session management expectations, and automated conformance testing.
- SAML request-signature policy, request-ID replay cache, SP-specific algorithm controls, and metadata rotation workflow.

## 7. Next-Level Opportunities

- **Observability:** OpenTelemetry traces, structured logs, correlation IDs, RED metrics, audit-chain verification alerts, and dashboards for auth failures/rate limiting/webhooks/signups.
- **Reliability:** explicit DB pool settings, startup ping/readiness, graceful drain, migration locking, transactional outbox for audit/webhook events, and backup restoration drills.
- **Security engineering:** CI secret scanning, SBOM, signed artifacts/images, dependency update automation, image scanning, policy checks, and external penetration testing after secret rotation.
- **Performance:** realistic large-tenant benchmarks, query plans/index review, cursor pagination, batched claim/scope lookups, and bounded export jobs.
- **Accessibility/product:** WCAG review, consistent empty/error/loading states, clearer destructive-action confirmation, and operator-visible scope/risk summaries.
- **Developer experience:** API schema/OpenAPI generation, protocol fixtures, local TLS/dev certificates, deterministic integration environments, and release/migration compatibility tests.

## 8. Prioritised Action Plan

- **Immediate:** rotate/purge exposed secrets; deploy current fixes; verify production configuration; document Compose as development-only.
- **Short-term:** enforce token scopes with a compatibility migration; transactionally repair signup and other multi-write workflows; add health/readiness and DB startup checks; make rate limiting atomic.
- **Medium-term:** complete OIDC and SAML conformance work; add MySQL integration and browser E2E suites; self-host frontend assets and tighten CSP; add bounded pagination and webhook queueing.
- **Long-term:** formalize key rotation and disaster recovery; add tracing/SLOs; build artifact provenance/SBOM; perform sustained load testing and an independent penetration test.

## 9. Caveats and Validation Needed

This report is based on static review and local Go tests, not production traffic, browser automation, live MySQL concurrency tests, or external identity-provider conformance suites. Product owners must confirm intended signup policy, token-scope compatibility, and supported OAuth/SAML behavior before changing public contracts. Production operators must verify proxy topology, network egress controls, secrets distribution, backup/key recovery, and whether the deleted legacy PHP tree has any remaining deployment dependency.
