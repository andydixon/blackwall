# Security Audit Report

## 1. Executive Summary

BlackWall has a generally sound authentication foundation: WebAuthn is used for interactive authentication, OAuth redirect URIs and PKCE are validated, cookies are protected, authorization is capability- and project-aware, SQL calls are parameterized, and audit logging is pervasive. The audit nevertheless confirmed several high-impact weaknesses.

The most urgent issue is that `prod.config.yaml` containing production credentials and cryptographic keys was committed to Git. This fix removes it from the current repository state and adds ignore rules, but every exposed credential must be rotated and the file must be purged from Git history and downstream clones. Other confirmed issues fixed in this audit include one-time credentials in redirect URLs, webhook SSRF, unbounded request and SAML decompression input, vulnerable dependencies/toolchains, unsafe Cryptbin verifier parameters, verbose internal errors, plaintext Terraform provider endpoints, and fragile SCIM default handling.

Residual risk remains around unenforced admin-token scopes, public tenant creation abuse, unsigned SAML AuthnRequests, a permissive Content Security Policy, and deployment defaults. These require product or compatibility decisions rather than isolated patches.

## 2. Scope Reviewed

- Go application source under `cmd/` and `internal/`, embedded HTML templates and browser JavaScript.
- Authentication, sessions, WebAuthn, OAuth/OIDC, SAML, SCIM, admin API tokens, Cryptbin, webhooks, rate limiting, audit logging, and tenant boundaries.
- MySQL schema/migrations, configuration loading, Dockerfile, Compose, Apache proxy configuration, documentation, and tests.
- Root Go module and `tools/terraform-provider-blackwall` module, including dependency manifests and generated sums.
- The user-deleted `legacy_php/` tree was explicitly excluded and was not modified, staged, tested, or assessed.

## 3. Methodology

The review combined static source analysis, route and trust-boundary mapping, adversarial data-flow tracing, dependency and toolchain scanning, configuration and deployment review, DoS/resource-control analysis, frontend/template review, and regression-test review. Safe unit-test-shaped proofs were added for confirmed issues. Verification used `go test`, race testing, `go vet`, `go build`, and `govulncheck` in both Go modules.

## 4. Risk Rating Method

Severity reflects exploitability, required privileges, confidentiality/integrity/availability impact, and blast radius. Confidence reflects the quality of direct code/configuration evidence. `Critical` indicates likely compromise of production secrets or broad system control; `High` indicates practical remote compromise or severe resource exhaustion; `Medium` indicates meaningful impact with prerequisites or constrained scope; `Low` indicates defense-in-depth or limited impact.

## 5. Attack Surface Map

- **Unauthenticated:** home, organization signup, enrollment, OAuth discovery/authorize/login, SAML metadata/SSO, Cryptbin create/read flows, static assets.
- **Authenticated users:** portal, WebAuthn enrollment/login state, OAuth consent, project-scoped claims, Cryptbin WebAuthn-gated access.
- **Administrators:** cookie-authenticated admin UI, approval workflows, project/user/client/SP management, maintenance and audit functions.
- **Machine clients:** bearer-authenticated admin JSON API and SCIM, OAuth token/introspection/revocation, SAML service providers, Terraform provider.
- **Outbound trust boundary:** configurable webhook destinations and DNS, external Bootstrap assets, database, optional metrics destination.
- **Sensitive stores:** MySQL identity/token/audit data, encrypted session cookies, filesystem Cryptbin ciphertext/metadata, signing keys and KEKs in configuration.

## 6. Findings Summary Table

| ID | Severity | Confidence | Title | Component | Status |
|---|---|---|---|---|---|
| SEC-001 | Critical | High | Production secrets committed to Git | `prod.config.yaml`, Git history | Partially Fixed |
| SEC-002 | High | High | One-time credentials exposed in redirect URLs | Admin UI secret creation flows | Fixed |
| SEC-003 | High | High | Webhook delivery allowed SSRF and redirects | Webhook service | Fixed |
| SEC-004 | High | High | Unbounded request bodies and SAML inflation | HTTP server, SAML parser | Fixed |
| SEC-005 | High | High | Reachable dependency/toolchain vulnerabilities | Both Go modules, Docker builder | Fixed |
| SEC-006 | Medium | High | Admin API token scopes are not enforced | Admin API and SCIM authorization | Open |
| SEC-007 | Medium | High | Public signup can create active tenant state | Organization signup | Open |
| SEC-008 | Medium | High | Rate limiter was fail-open and race-prone | Database rate limiter | Partially Fixed |
| SEC-009 | Medium | High | CSP permits inline code and external CDN execution | Security headers, templates | Open |
| SEC-010 | Medium | High | Internal errors disclosed implementation details | API, SCIM, SAML, templates | Fixed |
| SEC-011 | Medium | High | Cryptbin verifier trusted stored Argon2 costs | Cryptbin key verification | Fixed |
| SEC-012 | Medium | High | Terraform provider allowed insecure hosts and large responses | Terraform provider | Fixed |
| SEC-013 | Low | High | Unsigned SAML AuthnRequests are accepted | SAML IdP | Open |
| SEC-014 | Medium | High | Deployment defaults lack production isolation and limits | Compose and container runtime | Open |

## 7. Detailed Findings

### Finding ID: SEC-001

#### Title
Production secrets committed to Git

#### Severity
Critical

#### Confidence
High

#### Affected Files / Components
`prod.config.yaml`; commit history including `42a48ca`; database, session, CSRF, Cryptbin KEK, metrics, and audit-signing credentials.

#### Description
A production configuration containing live-looking secrets was tracked in Git. Removing the current file does not remove values from previous commits, forks, caches, CI artifacts, or developer clones.

#### Evidence
`git log --all -- prod.config.yaml` confirms the file in history. The fix removes it from the index and `.gitignore:1-4` now excludes local and production configuration files. Secret values are intentionally omitted from this report.

#### Attack Scenario
Anyone with repository/history access retrieves the old file and forges sessions or audit signatures, decrypts wrapped Cryptbin keys, accesses metrics, or connects to the database, depending on network reachability.

#### Impact
Potential full compromise of authentication state, protected data, audit integrity, and production infrastructure.

#### Recommendation
Rotate every value from the exposed file immediately, invalidate active sessions/tokens, rewrap or migrate protected keys where required, purge the file from all Git refs with `git filter-repo`, force-update remotes, and notify clone owners to reclone.

#### Safer Example
Keep only `config.example.yaml` with placeholders; inject production secrets through a managed secret store or mounted file outside version control.

#### Suggested Tests
Add CI secret scanning and a check that tracked files do not match `*prod*.yaml`, private-key patterns, or high-confidence token formats.

#### References
CWE-798; OWASP ASVS V14.1; OWASP A02:2021 Cryptographic Failures.

#### Assumptions / Limitations
The audit did not test whether the exposed values are currently active. Treat them as compromised regardless.

### Finding ID: SEC-002

#### Title
One-time credentials exposed in redirect URLs

#### Severity
High

#### Confidence
High

#### Affected Files / Components
`internal/handler/admin.go`, `internal/handler/admin_enterprise.go`, `internal/handler/helpers.go`; OAuth client secrets, admin bearer tokens, enrollment tokens.

#### Description
Newly created plaintext credentials were placed in redirect query strings. URLs leak through browser history, access logs, reverse proxies, screenshots, analytics, and referrers.

#### Evidence
The fixed handlers now store one-time values in the encrypted session using flash keys and consume them through `adminBaseData`; redirects retain only non-sensitive status values. Regression coverage is in `internal/handler/session_flash_test.go`.

#### Attack Scenario
An operator creates a client or token; a proxy or browser-history reader captures the redirect URL and reuses the credential.

#### Impact
Unauthorized OAuth client use, admin API access, or account enrollment.

#### Recommendation
Retain the session-backed one-time display and ensure access logs never contain generated credentials.

#### Safer Example
Store plaintext in the encrypted session, render it once on the destination page, then delete it before saving the session.

#### Suggested Tests
Assert redirects never contain `secret`, `token`, or enrollment plaintext and that a second page load no longer displays the value.

#### References
CWE-598; OWASP ASVS V2.10.4.

#### Assumptions / Limitations
Session confidentiality depends on rotation of the exposed session key from SEC-001.

### Finding ID: SEC-003

#### Title
Webhook delivery allowed SSRF and redirects

#### Severity
High

#### Confidence
High

#### Affected Files / Components
`internal/service/webhooks.go`, webhook target creation and outbound delivery.

#### Description
Webhook URLs could direct the server to loopback, private, link-local, or metadata networks, and the default HTTP client could follow redirects. DNS rebinding was also possible if validation and connection resolution differed.

#### Evidence
The fixed transport disables proxies and redirects, resolves the hostname at dial time, rejects any non-public resolved address, and applies connection/TLS/response-header timeouts. Tests cover private literals, localhost, redirects, and public targets.

#### Attack Scenario
A scoped administrator configures a webhook to an internal control plane or a public URL that redirects/rebinds to `169.254.169.254` or a private database endpoint.

#### Impact
Internal network probing, metadata credential theft, and invocation of unauthenticated internal services.

#### Recommendation
Keep direct, validated dialing. For stronger isolation, deliver through an egress proxy with an explicit destination allow-list.

#### Safer Example
Resolve and validate IPs immediately before dialing; reject loopback, private, link-local, multicast, unspecified, and reserved ranges; never follow redirects.

#### Suggested Tests
Add integration tests with controlled DNS rebinding and IPv4-mapped IPv6 addresses.

#### References
CWE-918; OWASP A10:2021 SSRF; OWASP API7:2023 SSRF.

#### Assumptions / Limitations
IP classification is defense in depth; network egress controls remain recommended.

### Finding ID: SEC-004

#### Title
Unbounded request bodies and SAML inflation

#### Severity
High

#### Confidence
High

#### Affected Files / Components
`cmd/blackwall/main.go:152,416-423`; `internal/middleware/request_limits.go`; `internal/service/saml.go:228-270`; Apache body limit.

#### Description
The server lacked a global request-body cap and key HTTP timeouts, while SAML Redirect binding decompressed attacker-controlled DEFLATE data without an output limit.

#### Evidence
The fix adds a configurable 8 MiB body cap, 10-second header timeout, header-size limit, existing read/write/idle timeouts, and a 1 MiB bounded SAML decode/decompression path. The Apache proxy limit was corrected from 80 MiB to 8 MiB.

#### Attack Scenario
An unauthenticated client streams an oversized/chunked request or submits a small compressed SAML payload that expands aggressively, consuming memory and CPU across concurrent requests.

#### Impact
Process memory pressure, connection exhaustion, increased GC, and service unavailability.

#### Recommendation
Retain app and proxy limits; add endpoint-specific smaller limits for JSON/form routes and load-test concurrency under the configured ceiling.

#### Safer Example
Wrap bodies with `http.MaxBytesReader`, reject oversized `Content-Length`, and use `io.LimitReader` around decompression.

#### Suggested Tests
Existing tests cover known-size and streamed bodies plus SAML inflation. Add reverse-proxy integration and slow-client tests.

#### References
CWE-400; OWASP ASVS V13.4.1.

#### Assumptions / Limitations
The global limit is intentionally large enough for configured Cryptbin payloads; endpoint-level limits would reduce residual cost.

### Finding ID: SEC-005

#### Title
Reachable dependency and toolchain vulnerabilities

#### Severity
High

#### Confidence
High

#### Affected Files / Components
Root and Terraform-provider `go.mod`/`go.sum`; `Dockerfile` builder image.

#### Description
Initial scanning identified reachable vulnerabilities in Chi, JWT, gRPC/network dependencies, and the Go standard library/toolchain.

#### Evidence
Dependencies were upgraded, both modules now select Go 1.26.4, and the Docker builder uses `golang:1.26.4-alpine`. Final `govulncheck ./...` reports no reachable vulnerabilities in either module.

#### Attack Scenario
An attacker targets a vulnerable HTTP/JWT/network code path or malformed protocol input covered by a published advisory.

#### Impact
Advisory-dependent authentication, availability, or remote attack impact.

#### Recommendation
Run `govulncheck` and dependency update automation in CI; rebuild runtime images regularly.

#### Safer Example
Pin a patched Go toolchain and reviewed direct dependency versions, while committing module sums.

#### Suggested Tests
Fail CI on reachable `govulncheck` findings and verify the built binary's Go version.

#### References
CWE-1104; OWASP A06:2021 Vulnerable and Outdated Components.

#### Assumptions / Limitations
Final scans still report vulnerabilities in unused symbols/modules for the root module; these are not called by current code but should be monitored.

### Finding ID: SEC-006

#### Title
Admin API token scopes are not enforced

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`internal/service/admin_tokens.go:57-71,122-143`; `internal/handler/admin_api.go:66-104`; SCIM authentication; admin token documentation.

#### Description
Token scope strings are stored and propagated but authorization checks only the owning user's admin role/capabilities. A token labelled `scim:read` can exercise every endpoint available to that user.

#### Evidence
`requireAPICapability` checks `AdminRole` only. `TokenScope` is populated but not consulted. Documentation explicitly calls scopes advisory.

#### Attack Scenario
A narrowly labelled automation token is leaked. Operators expect limited SCIM read access, but the holder can modify projects, clients, users, and other resources allowed to the owner.

#### Impact
Privilege breadth exceeds operator intent, increasing blast radius of machine-token compromise.

#### Recommendation
Define stable endpoint scopes, enforce both role capability and token scope, migrate existing tokens explicitly, and deny unknown scopes.

#### Safer Example
Require `admin:full` or a route-specific scope such as `scim:read` before the capability check succeeds.

#### Suggested Tests
Table-test every API/SCIM route with full, correct narrow, incorrect narrow, empty, and unknown scopes.

#### References
CWE-862; OWASP API5:2023 Broken Function Level Authorization.

#### Assumptions / Limitations
Enforcement was not added because existing automation may rely on documented advisory behavior; it needs a compatibility plan.

### Finding ID: SEC-007

#### Title
Public signup can create active tenant state

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`internal/handler/bootstrap.go:356-431`; organization signup route.

#### Description
Any unauthenticated client can create an active organization, active user, and enrollment records. Protection is limited to five attempts per apparent IP per hour.

#### Evidence
The handler inserts active rows before identity verification and relies on an IP-keyed database rate limit.

#### Attack Scenario
A distributed client or attacker with rotating addresses creates many tenants/users, consumes database capacity, reserves slugs, and increases operational cleanup load.

#### Impact
Resource exhaustion, namespace abuse, noisy audit/storage growth, and support burden.

#### Recommendation
Make self-signup configurable; create pending records; require email/domain verification or an invite; add global and per-domain quotas plus cleanup of abandoned signups.

#### Safer Example
Persist a short-lived pending signup and activate the tenant only after a verified challenge.

#### Suggested Tests
Abuse-test distributed signup, duplicate slugs, abandoned-record cleanup, and disabled-signup behavior.

#### References
CWE-400; OWASP API4:2023 Unrestricted Resource Consumption.

#### Assumptions / Limitations
Severity depends on whether public self-service tenant creation is an intended product feature.

### Finding ID: SEC-008

#### Title
Rate limiter was fail-open and race-prone

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`internal/security/rate_limit.go:21-91`; all rate-limited authentication and public flows.

#### Description
Database errors allowed requests, update errors were ignored, and probabilistic cleanup could start overlapping goroutines. The read-modify-write attempt counter is still non-atomic under concurrency.

#### Evidence
The fix now denies on database/read/update failure and uses an atomic single-flight guard for cleanup. The counter still performs separate `SELECT` and `UPDATE` operations.

#### Attack Scenario
An attacker creates DB pressure or sends parallel attempts. Before the fix, errors bypassed throttling; concurrent requests can still lose increments and permit more attempts than configured.

#### Impact
Reduced brute-force and abuse protection during failures or concurrency spikes.

#### Recommendation
Replace the read-modify-write flow with a single atomic SQL upsert/update returning the effective count, and distinguish security-critical fail-closed limits from availability-oriented limits.

#### Safer Example
Use a transaction/row lock or atomic `INSERT ... ON DUPLICATE KEY UPDATE attempts=attempts+1` followed by a consistent result.

#### Suggested Tests
Add MySQL-backed concurrency tests, injected DB-error tests, and cleanup single-flight tests.

#### References
CWE-362; CWE-307; OWASP ASVS V2.2.1.

#### Assumptions / Limitations
Fail-closed behavior can deny service during DB outages; that is preferable for authentication/security-sensitive routes but should be observed operationally.

### Finding ID: SEC-009

#### Title
CSP permits inline code and external CDN execution

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`internal/middleware/middleware.go:146-179`; embedded templates loading Bootstrap from jsDelivr and using inline scripts/styles.

#### Description
The Content Security Policy includes `'unsafe-inline'` for scripts and styles and permits scripts from a public CDN. This materially reduces CSP's value against XSS and introduces external supply-chain availability/integrity risk. CDN tags do not include Subresource Integrity.

#### Evidence
The policy and multiple templates directly reference `cdn.jsdelivr.net`; inline code is widespread.

#### Attack Scenario
An HTML injection flaw can execute inline script despite CSP, or a compromised CDN path serves executable JavaScript to BlackWall users.

#### Impact
Session actions, admin operations, and displayed secrets could be exposed in the browser context.

#### Recommendation
Self-host pinned assets, move inline code/styles to static files, and adopt nonce- or hash-based CSP without `'unsafe-inline'`.

#### Safer Example
`script-src 'self' 'nonce-<per-response-random>'; style-src 'self'` with no third-party executable origin.

#### Suggested Tests
Browser smoke tests under report-only strict CSP, CSP violation collection, and static checks forbidding new inline event handlers/scripts.

#### References
CWE-79; OWASP ASVS V14.4.3; OWASP A03:2021 Injection.

#### Assumptions / Limitations
No exploitable reflected/stored XSS was confirmed in reviewed server-rendered paths; this is defense-in-depth and supply-chain risk.

### Finding ID: SEC-010

#### Title
Internal errors disclosed implementation details

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
JSON admin API, SCIM errors, SAML generation/lookup, and template parse/render failures.

#### Description
Several 500 responses returned raw database, network, template, or cryptographic error strings to clients.

#### Evidence
The fixed response helpers replace 5xx details with `internal server error`; SAML and template paths log detailed errors server-side and send generic responses. Regression tests cover JSON API and SCIM behavior.

#### Attack Scenario
An attacker deliberately triggers failures and learns schema names, addresses, driver behavior, template paths, or cryptographic implementation details useful for follow-on attacks.

#### Impact
Information disclosure and improved attacker reconnaissance.

#### Recommendation
Continue separating structured server diagnostics from stable, non-sensitive client errors; include correlation IDs for support.

#### Safer Example
Log `err` with route/context server-side, return `{ "error": "internal_error", "message": "internal server error" }`.

#### Suggested Tests
Fuzz/inject service and database failures and assert responses contain no raw error substrings.

#### References
CWE-209; OWASP ASVS V7.4.1.

#### Assumptions / Limitations
Some 4xx validation errors intentionally remain descriptive because they reflect attacker-supplied invalid values, not internal failures.

### Finding ID: SEC-011

#### Title
Cryptbin verifier trusted stored Argon2 costs

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`internal/service/cryptbin.go:438-472`; Cryptbin metadata verification paths.

#### Description
Argon2 memory, time, thread, salt, and output-length parameters were parsed from stored metadata and passed directly to `argon2.IDKey`. Corrupt or maliciously imported metadata could request extreme memory/CPU allocation.

#### Evidence
The fixed verifier requires Argon2 version 19 and exact supported cost, salt, and hash lengths before invoking Argon2. A regression test rejects a 1 GiB memory request without performing it.

#### Attack Scenario
An attacker or compromised administrative process replaces/imports metadata with `m=1048576`; a view or key-verification request attempts a 1 GiB allocation.

#### Impact
Process OOM, CPU exhaustion, and Cryptbin availability loss.

#### Recommendation
Retain strict parameter bounds and validate metadata at ingestion/read time.

#### Safer Example
Reject any PHC record whose parameters differ from the service's supported profile before deriving a key.

#### Suggested Tests
Cover excessive memory/time/threads, unsupported versions, malformed fields, and oversized decoded hashes.

#### References
CWE-400; OWASP ASVS V6.2.

#### Assumptions / Limitations
Direct filesystem write access is normally privileged; import, restore, or storage compromise makes the trigger realistic.

### Finding ID: SEC-012

#### Title
Terraform provider allowed insecure hosts and large responses

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`tools/terraform-provider-blackwall/internal/provider/provider.go`; `internal/client/client.go` in the provider module.

#### Description
Provider configuration accepted plaintext remote HTTP endpoints and the client read response bodies without a size ceiling.

#### Evidence
The fixed provider requires HTTPS except loopback development endpoints, rejects credentials/path/query/fragment in the configured host, and limits response bodies to 8 MiB. Tests cover endpoint validation and oversized responses.

#### Attack Scenario
An operator accidentally configures remote HTTP and exposes bearer credentials to interception, or a compromised endpoint returns an unbounded response to exhaust Terraform memory.

#### Impact
Admin token theft and workstation/CI resource exhaustion.

#### Recommendation
Keep strict URL validation and bounded reads; support custom CAs rather than an insecure TLS bypass.

#### Safer Example
Allow `https://blackwall.example` and only `http://localhost:<port>` for local development.

#### Suggested Tests
Cover redirects to HTTP/private origins, custom CA handling, compressed oversized responses, and timeout behavior.

#### References
CWE-319; CWE-400; OWASP ASVS V9.1.

#### Assumptions / Limitations
The provider still trusts the host's configured TLS roots and normal Go proxy environment behavior.

### Finding ID: SEC-013

#### Title
Unsigned SAML AuthnRequests are accepted

#### Severity
Low

#### Confidence
High

#### Affected Files / Components
`internal/handler/saml.go:18-31`; SAML SP configuration and SSO route.

#### Description
The IdP accepts unsigned AuthnRequests for compatibility. Entity ID registration, exact ACS matching, project membership, and signed responses constrain impact, but request authenticity and integrity are not guaranteed.

#### Evidence
The handler explicitly documents non-enforcement. SP certificates can be stored, but request-signature verification is not performed in the handler flow.

#### Attack Scenario
An attacker crafts an AuthnRequest for a registered SP and causes a logged-in user to initiate SSO, potentially creating login-CSRF/confused-navigation behavior or manipulating RelayState within SP handling constraints.

#### Impact
Limited SSO request spoofing and workflow confusion; assertions remain signed and sent only to the registered ACS.

#### Recommendation
Offer per-SP `require_signed_authn_requests`, verify Redirect/POST signatures against the configured certificate, and constrain RelayState length.

#### Safer Example
Require valid signatures for SPs that supply a signing certificate while preserving an explicit compatibility opt-out.

#### Suggested Tests
Valid/invalid Redirect signatures, POST XML signatures, algorithm restrictions, replayed request IDs, and oversized RelayState.

#### References
CWE-345; OWASP ASVS V3.7.

#### Assumptions / Limitations
Actual impact depends on each SP's RelayState validation and session behavior.

### Finding ID: SEC-014

#### Title
Deployment defaults lack production isolation and limits

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`docker-compose.yml:1-30`; Docker runtime configuration.

#### Description
Compose publishes the application on all interfaces, uses documented static database passwords, pins MySQL only to a major/minor tag, and defines no CPU, memory, PID, filesystem, capability, or network segmentation controls. There is no application health/readiness check.

#### Evidence
The Compose file exposes `8080:8080`, embeds default credentials, and supplies only restart/DB health behavior.

#### Attack Scenario
A deployment reuses the sample unchanged on a reachable host. Attackers reach the app directly, guess database credentials if the DB becomes exposed, or amplify application-level DoS without container resource ceilings.

#### Impact
Credential compromise, expanded network exposure, and host-level resource contention.

#### Recommendation
Mark Compose as development-only; bind to loopback behind TLS proxy; use secrets; pin reviewed image digests; add health/readiness endpoints, limits, read-only root filesystem, dropped capabilities, and isolated networks.

#### Safer Example
Use `127.0.0.1:8080:8080`, external secret mounts, `read_only: true`, `cap_drop: [ALL]`, and explicit resource quotas.

#### Suggested Tests
Container smoke/health tests, image scanning, startup DB readiness tests, and deployment-policy linting.

#### References
CWE-16; CWE-798; OWASP ASVS V14.1.

#### Assumptions / Limitations
Compose may be intended only for development, but the file does not enforce or prominently state that boundary.

## 8. Blackhat-Style Abuse Paths

1. **Repository access to production compromise:** retrieve historical `prod.config.yaml`, use still-valid database/session/KEK/signing material, then forge or access protected state. Defensive breakpoints are immediate rotation, session invalidation, key migration, history purge, and secret scanning.
2. **Scoped admin to internal-network pivot:** before SEC-003, create a webhook targeting cloud metadata or a redirecting/rebinding host, trigger delivery, and collect internal responses/side effects. The new direct validated transport breaks this chain; egress filtering should enforce it externally.
3. **Public resource exhaustion:** distribute organization signups while streaming maximum-size requests and expensive authentication/parser work. Global limits now cap individual bodies and SAML inflation, but tenant creation quotas and infrastructure limits remain needed.
4. **Narrow-token expectation failure:** obtain a token labelled `scim:read`, then call unrelated admin endpoints because only the owner's role is enforced. Endpoint scope enforcement is the required breakpoint.

## 9. Denial-of-Service Review

Confirmed body, header, timeout, SAML decompression, Argon2 cost, Terraform response, and cleanup-goroutine weaknesses were fixed. The rate limiter now fails closed but still needs atomic counters. Remaining credible vectors include distributed public signup, global 8 MiB request concurrency, unbounded administrative list/report queries in large installations, outbound webhook concurrency without a queue/circuit breaker, and absent container quotas. Safe load tests should cover connection saturation, maximum Cryptbin payload concurrency, signup floods, webhook destination stalls, and large tenant datasets.

## 10. Dependency and Supply-Chain Review

Both modules have committed sums and pass final `govulncheck` with no reachable vulnerabilities. Direct dependencies and Go were upgraded, including Chi, JWT, `x/net`, and gRPC, and the builder uses Go 1.26.4. The runtime and MySQL images are tag-pinned rather than digest-pinned, and browser pages execute Bootstrap from jsDelivr without SRI. Add automated dependency updates, image scanning, SBOM generation, provenance/signing, and self-hosted browser assets.

## 11. Secrets and Sensitive Data Review

SEC-001 is the dominant risk. Current ignore rules are corrected, but historical exposure remains until rotation and history rewrite are complete. One-time generated secrets no longer travel in URLs. Tokens are hashed at rest; sessions are encrypted/authenticated; Cryptbin uses wrapped DEKs. Logs and audit metadata should be continuously checked to ensure bearer tokens, authorization codes, enrollment links, key material, and decrypted content are never recorded.

## 12. Authentication and Authorisation Review

WebAuthn verification, active-user checks, project membership, role capabilities, CSRF controls, PKCE, exact redirect URIs, nonce handling, token revocation, and scoped admin views were reviewed. No direct SQL injection or obvious cross-project IDOR was confirmed in assessed paths. Open issues are advisory token scopes and unsigned SAML requests. OIDC `id_token_hint` and `max_age` are documented as not enforced; these are conformance and session-assurance gaps that should be completed.

## 13. Input Validation and Output Encoding Review

Parameterized SQL and `html/template` provide strong baseline injection resistance. The unused `safeHTML` escape hatch was removed. URL, app-origin, webhook, SAML ACS, Terraform host, request-body, SCIM, and Cryptbin verifier validation were hardened. Generic 5xx errors now prevent internal-detail leakage. Continue replacing ignored `Scan`, `Exec`, JSON marshal/unmarshal, and response-write errors in security-sensitive paths with explicit handling.

## 14. Frontend HTML/JavaScript Robustness Review

Embedded templates parse successfully in tests and no confirmed DOM-XSS sink was found. The frontend relies heavily on inline JavaScript/styles and externally hosted Bootstrap, preventing a strict CSP. Runtime browser automation was not available, so form submission, modal behavior, WebAuthn flows, console errors, and CDN failure fallbacks require manual or Playwright validation.

## 15. Infrastructure and Deployment Review

The server now sets header/body/time limits and validates production `app_url` as HTTPS. The container runs as a non-root user, which is positive. Compose remains development-grade: static credentials, broad port binding, no resource/capability/filesystem limits, floating image patches, and no app health check. Apache should terminate TLS, preserve trusted proxy semantics, and keep its request limit aligned with the application.

## 16. Logging, Monitoring, and Error Handling Review

Audit logging is broad and includes integrity-chain support. Detailed 5xx errors are now logged rather than returned. Add correlation IDs to generic client errors, metrics for rate-limit DB failures, rejected oversized requests, SSRF blocks, webhook failures, and signup volume. Several code paths still discard database and response-write errors; these can hide partial state and should be addressed transactionally.

## 17. Test Coverage and Security Regression Gaps

New tests cover body limits, session flash secrecy, SCIM omitted-`active` behavior, SAML inflation/ACS URLs, webhook targets/redirects, Cryptbin Argon2 bounds, error redaction, configuration origins, Terraform URL validation, and response caps. Missing high-value coverage includes MySQL-backed authorization/transaction tests, concurrent rate limiting, full OAuth/OIDC conformance, signed SAML requests/replay, browser E2E tests, webhook DNS rebinding integration, deployment smoke tests, and load tests.

## 18. Prioritised Remediation Plan

- **Immediate:** rotate every secret from `prod.config.yaml`; invalidate sessions/tokens; purge Git history; deploy the fixed build; verify production config and TLS.
- **Short-term:** enforce admin token scopes with migration; gate/verify public signup; make rate-limit counters atomic; add container limits and health/readiness checks.
- **Medium-term:** self-host frontend assets and deploy strict nonce/hash CSP; implement signed SAML request verification; complete `max_age` and `id_token_hint`; remove ignored DB errors and add transactions.
- **Long-term:** egress proxy/allow-list for webhooks, formal key rotation/rewrap procedures, browser and protocol conformance suites, SBOM/provenance, and sustained load/abuse testing.

## 19. False Positives / Needs Manual Verification

- Determine whether historical production credentials are still active and where repository copies exist.
- Confirm public organization signup is intended and what anti-abuse controls exist outside the application.
- Verify reverse-proxy trusted-header configuration and whether Compose is ever used beyond local development.
- Validate CDN/CSP behavior, JavaScript console health, WebAuthn, OAuth, SAML, and Cryptbin flows in a real browser.
- Confirm webhook DNS behavior and egress filtering in the production network.

## 20. Final Notes

This audit was source- and local-test-based and did not perform destructive testing, production access, live secret use, external scanning, or browser automation. The deleted legacy PHP implementation was excluded by user instruction. The current Go code passes unit/race tests, vet, builds, and reachable-vulnerability scans, but the system remains at critical residual risk until exposed production secrets are rotated and removed from all Git history and clones.
