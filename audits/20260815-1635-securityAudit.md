# Security Audit Report

## 1. Executive Summary

Blackwall's new project-licence design has a strong cryptographic core. It uses a
dedicated Ed25519 key, signs a canonical and bounded envelope, derives the key ID
from the public key, binds exact hostnames and project identity, anchors the exact
signed bytes in MySQL, and makes revocation, project state, key-compromise state,
issuer and time part of authoritative verification. The OAuth favicon feature
also treats the registered redirect site as hostile: it permits only HTTPS port
443, rejects IP literals and non-public DNS results, pins resolved addresses,
disables redirects and proxies, bounds time and bytes, and serves only sniffed
passive image formats.

Production deployment is nevertheless blocked by one critical pre-existing
condition. Six production secrets previously committed in Git remain byte-for-byte
unchanged in both the ignored workspace configuration and the configuration
mounted into the running container. They include the database password, session
and CSRF secrets, Cryptbin KEK, metrics token, and audit-export signing key. No
secret value is reproduced in this report. Rotating the Cryptbin KEK without a
transactional re-wrapping migration could make existing encrypted items
unreadable, so an automatic restart or blind rotation is not safe.

Other open risks are unenforced admin-token scopes, non-atomic rate limiting,
public creation of active tenants, a permissive Content Security Policy, and
production key/configuration hardening. No reachable Go vulnerability was found
in either Go module; RustSec found no advisory in the Rust example lockfile; all
Go tests and race tests passed; and the PHP, Go, Rust and Java examples passed
their available syntax/compile checks.

## 2. Scope Reviewed

- Go server code under `cmd/` and `internal/`, including handlers, services,
  repositories, models, middleware, migrations, tests and embedded templates.
- Project-licence issuance, download, verification, revocation, canonicalisation,
  hostname policy, key registration/rotation, public endpoints and admin scope.
- OAuth favicon retrieval, DNS/IP policy, TLS transport, caching, response serving
  and consent-page fallback behaviour.
- Existing WebAuthn, OAuth/OIDC, SAML, SCIM, admin API, sessions, Cryptbin,
  webhooks, audit, rate limiting and organisation-sign-up boundaries.
- Root and Terraform-provider Go modules; PHP, Go, Rust and Java licence examples.
- `Dockerfile`, Compose, build script, sample proxy/supervisor files, the running
  production container's non-secret runtime controls and production TLS health.
- Git history and production-secret rotation status, compared without printing
  or copying secret values.

## 3. Methodology

The audit used two-pass adversarial mapping and code validation, manual data-flow
tracing, role/scope and state-transition review, cryptographic protocol review,
SSRF and DNS-rebinding analysis, secrets-lifecycle review, bounded-resource and
DoS analysis, template/JavaScript review, deployment inspection, and local safe
negative tests. Automated evidence included `go test`, `go test -race`, `go vet`,
`govulncheck`, `gosec`, RustSec `cargo-audit`, PHP lint, Cargo check/format, Maven
Java 17 compilation, Git integrity checks, and live HTTPS/discovery probes.

## 4. Risk Rating Method

Severity combines attacker prerequisites, reachability, confidentiality,
integrity and availability impact, tenant blast radius, and recoverability.
Confidence reflects direct code, configuration, runtime or scanner evidence.
Scanner output was manually triaged: for example, binary licence and favicon
responses reported as XSS are not findings because they use fixed/sniffed content
types with `nosniff`, while dynamic SQL made only from constant fragments and
parameter placeholders is not treated as injection.

## 5. Attack Surface Map

- **Unauthenticated Internet:** home, discovery/JWKS, OAuth authorisation/login,
  SAML metadata/SSO, organisation signup, enrolment, Cryptbin, licence keys and
  authoritative licence verification, favicon proxy and metrics policy.
- **Authenticated user:** portal, OAuth consent, project assignment checks,
  passkey management and WebAuthn-gated Cryptbin access.
- **Administrative browser:** organisation/project/user/client management,
  approvals, licence register/issue/download/revoke, key-state visibility,
  maintenance, audit and documentation.
- **Machine clients:** OAuth token endpoints, admin API/SCIM bearer tokens,
  Terraform provider, SAML service providers and licence consumers.
- **Outbound boundary:** webhooks, event-metrics destination, registered OAuth
  redirect hosts used for favicons, MySQL and third-party browser assets.
- **Sensitive stores:** MySQL identity/token/licence/audit rows, encrypted session
  cookies, Cryptbin ciphertext/metadata, JWT/SAML/licence signing keys, KEK and
  production configuration.
- **Attacker starts:** unauthenticated remote user, malicious tenant/operator,
  stolen admin token, leaked Git history, compromised backup, local read access,
  malicious OAuth redirect host, compromised dependency or patched licensee
  binary.

## 6. Findings Summary Table

| ID | Severity | Confidence | Title | Component | Status |
|---|---|---|---|---|---|
| BWA-001 | Critical | High | Exposed production secrets remain active | Git history and production configuration | Open |
| BWA-002 | Medium | High | Admin API token scopes are descriptive only | Admin API and SCIM bearer authentication | Open |
| BWA-003 | Medium | High | Rate-limit updates lose increments under concurrency | Public and administrative throttling | Open |
| BWA-004 | Medium | High | Public signup creates active tenant state | `/organisations/signup` | Open |
| BWA-005 | Medium | High | CSP allows inline and third-party code | Browser templates and security middleware | Open |
| BWA-006 | Medium | High | Production secret and licence-key deployment is incomplete | Container/runtime configuration | Open |
| BWA-007 | Low | High | SAML AuthnRequests are accepted unsigned | SAML IdP | Open |
| BWA-008 | Low | High | Hostname/instance licensing remains patchable client policy | Licence consumer boundary | Open |
| BWA-009 | Low | Medium | Licence private-key loading leaves avoidable memory and TOCTOU exposure | `loadLicencePrivateKey` | Open |
| BWA-010 | Low | Medium | Oversized unsigned COSE algorithm integers wrap | WebAuthn COSE parser | Open |
| BWA-011 | High | High | Production configuration entered Docker build context | Container build | Fixed after audit |

## 7. Detailed Findings

### Finding ID: BWA-001

#### Title

Exposed production secrets remain active

#### Severity

Critical

#### Confidence

High

#### Affected Files / Components

Git history containing `prod.config.yaml`; ignored `prod.config.yaml`;
`/opt/blackwall/config.yaml`; database, sessions, CSRF, Cryptbin, metrics and
audit-export trust boundaries.

#### Description

The earlier audit identified production credentials in Git history. A
value-blind comparison on 15 August 2026 found the relevant configuration lines
unchanged in both the current local production file and the file mounted into
the running `blackwall` container.

#### Evidence

The database password, session secret, CSRF secret, Cryptbin KEK, metrics token
and audit-export signing key each produced `RAW_LINE_UNCHANGED` when compared
with commit `42a48ca`. `docker inspect` confirmed the running container mounts
`/opt/blackwall/config.yaml` read-only. Values were neither displayed nor copied.

#### Attack Scenario

An attacker with any historic clone, CI artefact, cache or repository-history
access uses the still-active material to connect to reachable infrastructure,
forge or decrypt state, access metrics, verify/forge audit exports, or unwrap a
copied Cryptbin DEK when ciphertext/metadata is obtained.

#### Impact

Potential authentication compromise, data disclosure, audit-integrity loss and
production infrastructure access. The exact blast radius depends on network and
data-store access, but treating the values as uncompromised is unsafe.

#### Recommendation

Do not deploy or restart as a security-approved release until there is a
sequenced rotation runbook. Rotate DB, session, CSRF/error-trace, metrics and
audit-export keys; invalidate sessions/tokens; implement a transactional
Cryptbin KEK re-wrap with old/new key IDs and rollback; then purge the file from
all Git refs and require affected clone owners to re-clone. Preserve old audit
verification material offline if historic exports must remain verifiable.

#### Safer Example

Use a versioned KEK ring for read, a single active KEK for new writes, and an
idempotent migration that unwraps each DEK with the old key and re-wraps it with
the new key before retiring the old key.

#### Suggested Tests

Dry-run the rotation on a restored production backup; prove every Cryptbin item
opens before and after; prove old sessions and tokens fail; test rollback; and
run secret scanning over every Git ref.

#### References

CWE-798; CWE-312; OWASP ASVS V6 and V14; OWASP A02:2021.

#### Assumptions / Limitations

The audit did not attempt to use any credential. Network reachability and prior
unauthorised use were not tested.

### Finding ID: BWA-002

#### Title

Admin API token scopes are descriptive only

#### Severity

Medium

#### Confidence

High

#### Affected Files / Components

`internal/service/admin_tokens.go:17-20,57-71`;
`internal/handler/admin_api.go:20-79`; admin API and SCIM routes.

#### Description

Tokens store and expose scopes such as `scim:read`, but middleware only validates
the token and current owning-user role. It attaches `TokenScope` to context and
no route enforces it. A nominally read-only or SCIM-only token inherits all
current capabilities of its owner.

#### Evidence

`AdminAPIBearerAuth` copies `t.Scopes` into `AdminAPIActor` and immediately calls
the next handler. Repository search found no scope-check helper or route guard.

#### Attack Scenario

A narrowly labelled automation token leaks. The holder invokes project, OAuth
client, webhook or SAML mutations that the owner can perform, despite the token
being presented to operators as constrained.

#### Impact

Privilege expansion relative to operator intent and a larger automation-secret
blast radius.

#### Recommendation

Define a closed scope-to-method/route matrix, reject unknown scopes at creation,
enforce required scopes after role/scope checks, and make `admin:full` explicit
rather than an implicit empty default.

#### Safer Example

Require both `security.HasCapability(actor.AdminRole, capability)` and
`actor.HasTokenScope("projects:write")` for a project mutation.

#### Suggested Tests

Table-test every route with full, matching narrow, wrong narrow, unknown,
revoked and expired scopes; include SCIM read/write separation.

#### References

CWE-862; OWASP ASVS V4; OWASP API5:2023.

#### Assumptions / Limitations

Owning-user project and organisation scope is enforced separately and reduces
cross-tenant blast radius.

### Finding ID: BWA-003

#### Title

Rate-limit updates lose increments under concurrency

#### Severity

Medium

#### Confidence

High

#### Affected Files / Components

`internal/security/rate_limit.go:38-84`; OAuth, WebAuthn, signup, licence
verification, favicon and admin-mutation limits.

#### Description

The existing-row path reads `attempts`, increments it in Go, then writes an
absolute value without a transaction, row lock or conditional compare. Parallel
requests can read the same count and overwrite one another, allowing more work
than configured. The path is fail-closed on database errors, which is a positive
control, but does not repair the lost-update race.

#### Evidence

Lines 38-47 select without `FOR UPDATE`; lines 73-84 calculate and store
`attempts=?`. Only the initial insert uses atomic `attempts=attempts+1`.

#### Attack Scenario

An attacker sends parallel licence signature checks or authentication attempts
from one address. Many workers observe the same count and record only one
increment, increasing expensive database/cryptographic work and weakening brute
force throttling.

#### Impact

Control bypass and CPU/database amplification. Reverse-proxy and host resource
limits constrain, but do not eliminate, availability impact.

#### Recommendation

Use one atomic upsert/update that increments and calculates block state in the
database, or a short transaction with `SELECT ... FOR UPDATE`. Add concurrency
and multi-process tests.

#### Safer Example

Increment with `attempts=attempts+1` and make the allow/deny decision from the
same locked row/returned value, never from a stale application-side count.

#### Suggested Tests

Launch at least 100 simultaneous calls against a small threshold and assert no
more than the threshold succeeds; repeat across two limiter instances.

#### References

CWE-362; CWE-400; OWASP ASVS V11.

#### Assumptions / Limitations

MySQL isolation and scheduling affect the practical overrun, not the existence
of the lost-update pattern.

### Finding ID: BWA-004

#### Title

Public signup creates active tenant state

#### Severity

Medium

#### Confidence

High

#### Affected Files / Components

`cmd/blackwall/main.go` public routes; `internal/handler/bootstrap.go:356-431`.

#### Description

Any visitor with a session CSRF token can create an active organisation and
active admin user. A five-per-hour IP limit is the only admission control, and
the limiter itself is affected by BWA-003.

#### Evidence

The public POST inserts `organizations.status='active'` and
`users.status='active'` before issuing an enrolment link. No invitation,
administrative approval, e-mail/domain proof or deployment switch is required.

#### Attack Scenario

A distributed bot creates tenant records and enrolment state, exhausting table
growth and namespace availability or creating unwanted active principals.

#### Impact

Database growth, operational noise, name squatting and unauthorised tenancy.

#### Recommendation

Default production signup to disabled or invite-only, create `pending` records,
require an approval/proof step, and add global and identity-based quotas.

#### Safer Example

Gate routes behind `organisation_signup_enabled`; default false in production;
activate only after a one-use server-generated invitation is consumed.

#### Suggested Tests

Test production-disabled, invitation replay, expiry, pending cleanup, concurrent
slug creation and distributed-rate-limit behaviour.

#### References

CWE-799; CWE-841; OWASP API6:2023.

#### Assumptions / Limitations

If public self-service tenancy is an explicit product decision, the residual
abuse risk still requires quotas and verification.

### Finding ID: BWA-005

#### Title

CSP allows inline and third-party code

#### Severity

Medium

#### Confidence

High

#### Affected Files / Components

`internal/middleware/middleware.go:146-172`; embedded HTML templates loading
jsDelivr and Google Fonts; inline WebAuthn, admin and Cryptbin scripts.

#### Description

`script-src 'unsafe-inline' https://cdn.jsdelivr.net` permits any injected inline
script and delegates authentication-page code execution to an external CDN.
There are no nonces/hashes or Subresource Integrity values. This weakens CSP's
ability to contain a future template/DOM injection or CDN compromise.

#### Evidence

The middleware emits `unsafe-inline`; repository search found multiple inline
scripts and third-party Bootstrap script tags. No current exploitable reflected
or stored XSS was confirmed; Go templates escape ordinary data.

#### Attack Scenario

A future escaping error, compromised CDN asset or hostile supply-chain update
executes in the Blackwall origin and can invoke authenticated same-origin APIs or
interfere with WebAuthn flows.

#### Impact

Session-riding administrative actions, UI deception and sensitive response
access within the user's browser.

#### Recommendation

Self-host pinned assets, move inline scripts to embedded files, use per-response
nonces or static hashes, and remove `unsafe-inline` and unnecessary remote
origins.

#### Safer Example

Use `script-src 'self' 'nonce-<random>'` with the same unpredictable nonce on
each intentional script block and response header.

#### Suggested Tests

Browser-test every WebAuthn, consent, Cryptbin and admin interaction under the
strict policy; fail CI on unexpected external/inline execution.

#### References

CWE-79; OWASP ASVS V14.4; OWASP A03:2021.

#### Assumptions / Limitations

This is defence in depth; no concrete XSS payload was demonstrated.

### Finding ID: BWA-006

#### Title

Production secret and licence-key deployment is incomplete

#### Severity

Medium

#### Confidence

High

#### Affected Files / Components

Running `blackwall:latest` container; `/opt/blackwall/config.yaml`; systemd and
supervisor launch definitions; `docker-compose.yml`; new licence service.

#### Description

Production has useful memory, CPU, PID, loopback-port and read-only-config
controls, and the application runs as user `blackwall`. However the root
filesystem is writable, no capability/no-new-privileges controls are declared,
two divergent host launch definitions exist, and no dedicated licence key is
configured or mounted. Therefore verification can start after migration but
issuance remains disabled. Compose also contains fixed demonstration database
passwords and publishes the application on all interfaces.

#### Evidence

`docker inspect` reported 512 MiB, one CPU, 256 PIDs, loopback port binding,
`user=blackwall`, `readonly_rootfs=false`, and no licence-key mount. Both checked
production configurations omit `licence_signing_key_file`. Systemd and
supervisor files specify different resource options.

#### Attack Scenario

An operator starts the stale supervisor definition and silently loses resource
limits, or deploys Compose defaults. A container compromise can modify its
writable layer. Licence issuance is expected operationally but remains disabled,
leading to unsafe ad-hoc key placement during an incident.

#### Impact

Configuration drift, weaker containment, accidental weak credentials and an
incomplete licensed-product rollout.

#### Recommendation

Choose one authoritative unit; mount a new dedicated key from a separate
mode-0700 host secret directory as read-only; use read-only rootfs, tmpfs where
needed, `no-new-privileges`, dropped capabilities and explicit resources; never
use Compose defaults in production. Address BWA-001 before restarting.

#### Safer Example

Mount `/opt/blackwall/secrets/licence-ed25519.pem` to
`/run/secrets/blackwall_licence_ed25519.pem:ro` and configure only the container
path, while keeping Cryptbin storage on its separate writable volume.

#### Suggested Tests

Validate the exact systemd unit, inspect the resulting container, confirm the
private key is unreadable on the host to unrelated users and absent from image
layers/backups, and exercise issue/verify/revoke after migration.

#### References

CWE-250; CWE-798; OWASP ASVS V14.

#### Assumptions / Limitations

Host firewall, Docker daemon policy and filesystem ACLs were not fully audited.

### Finding ID: BWA-007

#### Title

SAML AuthnRequests are accepted unsigned

#### Severity

Low

#### Confidence

High

#### Affected Files / Components

`internal/handler/saml.go:19-31,58-126`;
`internal/service/saml.go` metadata advertises `WantAuthnRequestsSigned=false`.

#### Description

The IdP accepts unsigned requests for compatibility. Registered entity ID and
ACS equality, project assignment, session state and signed responses provide
important protection, but origin/authenticity of a request is not established.

#### Evidence

The handler comment and metadata explicitly state unsigned requests are allowed;
no request-signature verification path exists.

#### Attack Scenario

An attacker able to cause a browser to visit a crafted request initiates an IdP
flow for a known SP. Fixed ACS prevents response theft, but login CSRF/confusion
or unwanted authentication traffic remains possible.

#### Impact

Constrained login-flow abuse and reduced SAML assurance.

#### Recommendation

Add a per-SP `require_signed_authn_requests` option and verify Redirect/POST
signatures against registered SP certificates when enabled.

#### Safer Example

Require signed requests for high-assurance SPs while retaining an explicit,
audited compatibility exception for legacy SPs.

#### Suggested Tests

Valid/invalid signatures, algorithm downgrade, duplicate parameters, certificate
rotation, replay, unsigned-required rejection and ACS mismatch.

#### References

CWE-347; OWASP ASVS V7.

#### Assumptions / Limitations

This finding does not imply Blackwall's signed SAML responses can be forged.

### Finding ID: BWA-008

#### Title

Hostname and instance licensing remains patchable client policy

#### Severity

Low

#### Confidence

High

#### Affected Files / Components

`docs/licensing/VERIFYING_LICENCES.md:12-38`; public verification request;
all consumer examples and integrating applications.

#### Description

Blackwall can prove what it issued and whether that record remains valid, but it
cannot independently observe the hostname or instance count of arbitrary
customer software. The caller supplies `expected_hostname`; a hostile operator
can pass an allowed value, patch the check, replay a recent success, or remove
client-side enforcement. This is a fundamental trust-boundary limit, not an
Ed25519 weakness.

#### Evidence

The API request contains caller-supplied `expected_hostname`. The guide correctly
says applications must enforce features/instances and must derive trusted policy
locally, but does not yet state plainly that hostile binaries remain patchable.

#### Attack Scenario

A licensee runs on an unlicensed host but invokes the verifier using a hostname
from the signed allow-list, or modifies its local application to ignore a failed
response.

#### Impact

Commercial entitlement bypass in fully customer-controlled deployments; signed
claims themselves cannot be altered or minted without the private key.

#### Recommendation

Document this limit explicitly. Derive host identity from trusted application
configuration, bind cached online results to licence/project/host, protect
rollback state, and enforce high-value entitlements server-side where Blackwall
or another trusted service controls the execution boundary. Consider per-instance
activation identities with rate/lease controls as an additional, not absolute,
barrier.

#### Safer Example

For a hosted API, check entitlement on the vendor-controlled server using the
authenticated customer/project identity rather than trusting a customer binary's
boolean licence result.

#### Suggested Tests

Patched-client threat modelling, cached-result rollback, copied state between
hosts, clock rollback, cloned activation identity and offline-grace exhaustion.

#### References

CWE-602; OWASP ASVS V1.2.

#### Assumptions / Limitations

No purely client-side licensing scheme can make software controlled by a hostile
administrator unpatchable.

### Finding ID: BWA-009

#### Title

Licence private-key loading leaves avoidable memory and TOCTOU exposure

#### Severity

Low

#### Confidence

Medium

#### Affected Files / Components

`internal/service/licence.go:662-694`; process memory and configured key path.

#### Description

The loader checks a path with `os.Stat` and then opens it separately with
`os.ReadFile`, allowing a local actor with directory-write access to swap the
entry between operations. It wipes the PEM input buffer best-effort, but not the
separately decoded `pem.Block.Bytes`. The live Ed25519 private key necessarily
remains in Go heap memory for issuance and cannot be reliably zeroised after GC
copies.

#### Evidence

The stat/read operations are separate. The deferred loop clears `data`; there is
no wipe of `block.Bytes`, process dump policy, or hardware-backed signer.

#### Attack Scenario

A local attacker who can modify the key directory wins the stat/read race, or a
core/heap disclosure yields lingering decoded/live key bytes. Such access is
already powerful, so this is defence in depth.

#### Impact

Licence-signing key theft enables offline signature forgery; online anchoring
still prevents invented records from passing the authoritative endpoint unless
the database is also compromised.

#### Recommendation

Open once with no-follow semantics where supported, validate with `File.Stat`,
wipe decoded buffers, keep the directory root-owned and non-writable, disable
core dumps, and prefer a KMS/HSM signer interface for mature deployments.

#### Safer Example

Open the configured file once, validate its descriptor is a regular tightly
permissioned file, read from that descriptor, and clear all temporary mutable
buffers after parsing.

#### Suggested Tests

Symlink/replacement race harness, owner/mode checks, decoded-buffer wipe test
where observable, core-dump policy verification and KMS signing contract tests.

#### References

CWE-367; CWE-316; OWASP ASVS V6.4.

#### Assumptions / Limitations

Go cannot guarantee zeroisation of garbage-collected copies. No local
unprivileged access to the planned secret directory was demonstrated.

### Finding ID: BWA-010

#### Title

Oversized unsigned COSE algorithm integers wrap

#### Severity

Low

#### Confidence

Medium

#### Affected Files / Components

`internal/service/webauthn.go:316-343`.

#### Description

When CBOR decodes the COSE algorithm as `uint64`, the verifier casts it to
`int64` without checking `math.MaxInt64`. Values near `2^64` wrap to negative
registered algorithm identifiers. Signature verification still has to succeed
with the corresponding ES256/RS256 key, so no authentication bypass was
demonstrated, but non-canonical input reaches an unintended branch.

#### Evidence

`gosec` G115 identified line 331. The switch accepts `-7` and `-257`, values
obtainable by wrapping specially chosen `uint64` inputs.

#### Attack Scenario

A crafted stored COSE key encodes a huge unsigned algorithm value that wraps to
an accepted signed value. It still requires a valid signature and stored
credential, limiting practical exploitation.

#### Impact

Parser ambiguity and future-maintenance risk at a security boundary.

#### Recommendation

Reject unsigned algorithm values above `math.MaxInt64`, or accept only the
expected signed CBOR type/registered values during enrolment and verification.

#### Safer Example

Before conversion, return false when `v > math.MaxInt64`.

#### Suggested Tests

CBOR keys with `MaxInt64`, `MaxInt64+1`, `2^64-7`, `2^64-257`, wrong types and
normal ES256/RS256 values.

#### References

CWE-190; WebAuthn/COSE algorithm registry.

#### Assumptions / Limitations

The audit did not demonstrate a valid-signature bypass; severity is based on
strict-parser hygiene.

### Finding ID: BWA-011

#### Title

Production configuration entered Docker build context

#### Severity

High

#### Confidence

High

#### Affected Files / Components

Docker build context, builder cache and the previously missing `.dockerignore`.

#### Description

`prod.config.yaml` is ignored by Git but, before this release, no `.dockerignore`
existed. `COPY . .` therefore sent the local production configuration and any
other matching local secrets to the Docker daemon and copied them into an
intermediate builder layer. The multi-stage runtime image copies only the binary,
so the file was not found in the final image, but builder cache/history remains a
separate exposure surface.

#### Evidence

The repository had no `.dockerignore` immediately before the production build.
The release added explicit exclusions for local/production configuration,
environment files, PEM/key files, generated artefacts, storage, caches and logs
before rebuilding.

#### Attack Scenario

An attacker or operator with Docker daemon/cache/export access inspects an old
builder layer or build context and recovers production credentials even though
the final runtime filesystem does not contain the configuration.

#### Impact

Credential disclosure with the same downstream classes of impact as BWA-001.

#### Recommendation

Retain the strict `.dockerignore`, prune historic builder cache after credential
rotation, and use BuildKit secret mounts if a future build genuinely needs a
secret. Never pass secrets through `ARG`, `ENV` or ordinary `COPY`.

#### Safer Example

Only source, module manifests and intentionally embedded assets should enter the
builder; runtime configuration must be mounted after image creation.

#### Suggested Tests

Inspect the effective build context in CI, fail if secret/config patterns are
present, scan all final layers, and verify an exported builder cache after the
rotation/cache-prune runbook.

#### References

CWE-200; CWE-798; OWASP ASVS V14.1.

#### Assumptions / Limitations

Historic Docker cache access and retention were not enumerated. Treat old caches
as potentially containing the already-exposed values.

## 8. Blackhat-Style Abuse Paths

1. **Historic clone to production trust:** obtain the old configuration from a
   clone or CI cache, test still-active credentials against reachable services,
   then use session/DB/KEK material to widen access. Breakpoints: immediate
   rotation, history purge, network ACLs, session invalidation and KEK re-wrap.
2. **Narrow automation token to broad API mutation:** steal a token labelled
   `scim:read`, rely on absent scope enforcement, and invoke any owner-authorised
   admin route. Breakpoints: route scope matrix, short expiry, vaulting and audit
   alerting.
3. **Distributed signup plus limiter race:** obtain CSRF sessions, submit parallel
   and distributed signups, and create active tenants despite per-IP limits.
   Breakpoints: invite-only default, pending state, atomic/global quotas.
4. **Malicious OAuth client favicon:** register a hostile public host and attempt
   SSRF or active content. Current breakpoints are strong: exact registered URI,
   HTTPS/443 only, DNS public-address rejection and pinning, no redirects/proxy,
   time/size/cache limits, raster/icon sniffing, SVG rejection and `nosniff`.
5. **Stolen licence key alone:** mint a correctly signed token. Online verification
   still returns `not_recorded`; database anchoring breaks the chain. A combined
   key and DB compromise remains able to forge rows, so separation, auditing and
   external signing are the next defence.
6. **Patched customer binary:** bypass local hostname/instance enforcement or
   supply an allowed hostname. Cryptography cannot break this path; vendor-side
   entitlement enforcement or leased activation raises the cost.

## 9. Denial-of-Service and Resource Exhaustion Review

- Global request bodies, licence requests, SAML inflation, Cryptbin objects,
  favicon images/responses, webhook responses and provider responses are bounded.
- HTTP read/write/idle/header timeouts and MySQL pool limits are configured.
- Licence parsing verifies 16 KiB/8 KiB/64-byte bounds before expensive work,
  and public verification is rate-limited before signature/database checks.
- Favicon retrieval has 2-second DNS/dial/TLS/header controls, a 4-second total,
  a 128 KiB cap, 256-entry LRU-style bound, negative caching and same-host
  request coalescing. Distributed requests across many active clients can still
  create outbound work; egress and host limits are recommended.
- Confirmed weakness BWA-003 permits same-key parallel rate-limit overrun.
- Licence admin listing is capped at 1,000 rows but has no pagination; this is a
  functionality/operability gap rather than an unbounded request.
- Webhook queue/retry controls and container CPU/memory/PID limits reduce blast
  radius. Load testing remains absent.

## 10. Cryptography and Key Management Review

- **Clean:** Licence Ed25519 uses Go's standard implementation, CSPRNG UUIDs,
  key-derived `kid`, exact signed transport bytes and canonical JSON validation.
  Unknown/trailing/non-canonical fields, signature length and payload sizes are
  rejected. Public keys only are stored in MySQL.
- **Clean:** Online verification checks signature before policy use, then issuer,
  audience, project, hostname, timestamps, key state, exact database bytes,
  revocation and project state. Constant-time `hmac.Equal` compares anchored
  payload/signature bytes.
- **Clean:** Existing encryption uses authenticated XChaCha20-Poly1305/AES-GCM
  paths and CSPRNG material; JWT algorithm selection is fixed rather than taken
  from untrusted headers. No MD5, SHA-1 security use, DES, RC4, ECB, unauthenticated
  CBC or disabled TLS verification was found.
- **Key lifecycle:** Rotation retains retired public keys and makes compromised
  keys fail verification/export/reactivation. BWA-009 records local-memory/file
  hardening; BWA-006 records missing production provisioning.
- **Post-quantum:** Ed25519 and RSA signatures are classically secure but not
  post-quantum. Licences may remain valid for years, so a future versioned hybrid
  Ed25519 + ML-DSA transition is reasonable once stable ecosystem support exists.
  Do not invent a bespoke hybrid or break version-1 verification prematurely.
  Harvest-now-decrypt-later matters more for long-lived Cryptbin confidentiality;
  transport TLS interoperability currently constrains PQ deployment.

## 11. Secrets Lifecycle and In-Memory Credential Review

- BWA-001 is the dominant at-rest and lifecycle failure. The ignored file and
  read-only mount do not remediate values already in history.
- Licence private material is file-only, mode-checked, never put in MySQL, logs,
  UI, tokens or scanner metadata. Temporary PEM input is wiped best-effort;
  BWA-009 covers decoded/live heap copies and dump policy.
- Licence tokens are not bearer login credentials but contain entity data; list
  views avoid loading token bodies, downloads are capability/project scoped and
  `no-store`, and audits omit entity names/token content.
- Admin/OAuth/enrolment plaintext tokens are generated with `crypto/rand`, stored
  hashed where applicable and one-time values use encrypted session flash rather
  than URLs.
- DB/session/CSRF/KEK values remain long-lived Go strings and configuration-global
  memory. Managed runtimes cannot guarantee wiping; rotation, minimal process
  access, disabled dumps and secret-manager/file delivery are primary controls.
- No pprof/heapdump/debug listener was found. `APP_DEBUG` must remain false;
  WebAuthn debug logging would otherwise include sensitive assertion/key data.

## 12. Memory and Resource Safety Review

The server is pure Go with `CGO_ENABLED=0` in the supported build; there is no
project-owned C/C++/Rust `unsafe` or FFI memory-safety surface. Go's runtime and
standard-library native internals remain supply-chain surfaces and are covered
by toolchain updates. Attacker-influenced buffers are generally bounded before
allocation/processing. The favicon cache and coalescing maps are bounded/cleared,
and race tests passed. BWA-010 is the confirmed integer-conversion edge case.

## 13. Dependency and Supply-Chain Review

- Root `govulncheck`: zero reachable or imported-package vulnerabilities; one
  module-level no-fix OpenPGP advisory is not imported or called.
- Terraform provider tests/vet and `govulncheck`: no vulnerabilities.
- Rust example: `cargo check --locked`, format check and RustSec scan passed for
  145 locked dependencies with no advisory reported.
- Java example compiled under Java 17/Maven with Jackson 2.22.0. Maven does not
  have a committed lockfile, so recurring dependency scanning is still needed.
- PHP lint and Go example tests passed; neither adds third-party dependencies.
- Gosec produced many expected taint/unchecked-error warnings; confirmed items
  are captured above. Binary image/token writes, registered OAuth redirects and
  constant-fragment SQL were manually rejected as false positives.
- Docker base image is supported and upgraded during build. Final-image scanning
  should remain a release gate tied to an immutable digest and signed provenance.

## 14. Authentication and Authorisation Review

- WebAuthn challenges are session/CSRF bound, expire, are consumed, verify origin
  and RP ID, and regenerate session IDs after authentication. User/project active
  state is rechecked in OAuth flows.
- OAuth uses exact registered redirect URI matching, authorisation code + S256
  PKCE, OIDC nonce/audience/issuer/time checks, scoped project roles and token
  revocation/rotation controls. Scanner open-redirect warnings were false
  positives because redirects occur only after exact client registration checks.
- Licence UI routes require admin authentication, explicit capabilities and
  project scope. Only super-admin has `manage_licences`; operators can view within
  existing scope. Issue/revoke use CSRF and rate controls and emit non-PII audit
  events.
- BWA-002, BWA-004 and BWA-007 remain. Existing scope and capability checks do
  not compensate for token-scope semantics or public tenant admission.

## 15. Input Validation and Output Encoding Review

- SQL uses driver parameters for attacker values. Dynamic fragments reviewed are
  assembled from constant allow-lists or internally generated placeholders.
- Go `html/template` escapes normal output. Licence entity/reason/hostname/feature
  fields have UTF-8, control, length and grammar checks.
- Licence JSON and public verify JSON reject unknown and trailing fields; strict
  base64url, canonical re-marshalling and exact field shapes reduce parser
  differential attacks.
- Favicon content is sniffed from bytes, SVG/HTML/octet-stream rejected, and the
  response uses `nosniff` plus same-origin resource policy. The gosec XSS report
  on the binary write was not reproducible as active content.
- Build/status values are authenticated-admin-only, bounded and template-escaped;
  no dependency names are exposed. Scan metadata is operator-supplied provenance,
  not cryptographic proof of a scan.

## 16. Frontend HTML/JavaScript Robustness Review

- Embedded templates parse in tests. The consent favicon loads asynchronously;
  `onload` hides the initial and `onerror` hides the image, preserving a usable
  fallback without blocking authorisation.
- Favicon alt text is empty because the adjacent client name conveys identity;
  CSS bounds and contains the remote image.
- WebAuthn async paths catch errors and re-enable controls. No secrets were found
  in `localStorage`/`sessionStorage`, and no unsafe `innerHTML`, `eval` or
  `postMessage` path was found.
- BWA-005 remains. No full browser automation or accessibility audit was run;
  CSP/network console behaviour should be covered by Playwright or equivalent.

## 17. Infrastructure and Deployment Review

- Positive live controls: HTTPS on `blackwall.cx` verifies; discovery returns
  200; HSTS, CSP, frame, type, referrer and permissions headers are present;
  container is unprivileged, bound to loopback, health-checked, and limited to
  512 MiB/one CPU/256 PIDs.
- The stale `v2.blackwall.cx` example host currently presents a certificate not
  valid for that name. It is not the configured issuer, but stale DNS/vhost
  references should be removed or corrected to avoid user confusion.
- BWA-001 and BWA-006 prevent a security-approved restart. The new schema
  migration is additive and forward-only, but a database backup/restore test is
  still required before production migration.
- No licence signing key is presently configured, so a deployed binary would
  expose verification/key endpoints but correctly refuse issuance.

## 18. Logging, Monitoring, and Error Handling Review

- Licence failures return stable low-detail codes; private parser/DB errors,
  tokens and entity details are not logged. Admin issue/revoke actions are audited
  with actor/project/licence IDs.
- Favicon failures return a generic 404 and are deliberately not audited per
  page load, avoiding target and authentication noise.
- Correlation IDs, audit chain/checkpoints, rate-limit events and scoped audit
  views are present. Some existing ignored database/session write errors can
  cause misleading success UI/audits; this is a maintainability backlog item.
- The build panel records scan time/reference only when both are syntactically
  supplied; it does not verify an attestation. Release automation should bind
  scan evidence to image digest and commit.

## 19. Test Coverage and Security Regression Gaps

- Strong new licence tests cover signing, tampering, wrong key, non-canonical and
  unknown claims, exact host policy, time/project policy and key-file permissions.
- Favicon tests cover URL eligibility, special/reserved IP ranges, MIME allow-list,
  SVG rejection and race-free cache code. Missing: controlled DNS/dial pinning,
  mixed DNS answers, TLS failure, redirect, byte cap, coalescing and handler DB
  authorisation integration tests.
- Missing licence integration tests: real MySQL issue/list/download/revoke,
  concurrent key rotation/compromise, key registry endpoint and cross-tenant UI
  denial. Existing service logic was manually traced.
- Missing full browser/E2E coverage for OAuth consent favicon and licence admin UI.
- Missing concurrency/load tests for BWA-003 and production restore/migration.

## 20. Prioritised Remediation Plan

- **Immediate:** freeze production restart; inventory historic secret exposure;
  implement/test Cryptbin KEK re-wrap; rotate all exposed secrets; purge Git
  history; invalidate sessions/tokens; inspect logs for misuse.
- **Short-term:** enforce admin-token scopes; make rate limiting atomic; make
  production signup invite-only; provision the dedicated licence key through one
  hardened authoritative unit; add MySQL and browser integration tests.
- **Medium-term:** self-host frontend assets and deploy nonce/hash CSP; add optional
  signed SAML requests; implement a KMS/HSM licence signer; add activation leases
  if the product threat model requires them.
- **Long-term:** signed image/SBOM/provenance and scan attestations; PQ migration
  planning; egress proxy/allow-list; scheduled restore, key-rotation and incident
  exercises.

## 21. False Positives / Needs Manual Verification

- Gosec SQL warnings require no attacker-controlled SQL fragment in reviewed
  paths; placeholders/columns/filters come from bounded constants.
- Gosec XSS warnings on SAML XML, ciphertext, `.bwlic` attachments and sniffed
  favicon bytes are content-type-specific writes, not HTML interpolation.
- OAuth redirect warnings are guarded by exact registered redirect URI checks.
- `math/rand` chooses probabilistic cleanup timing only; it does not generate a
  token or security decision. The actual rate-limit race is BWA-003.
- Confirm historical credential misuse, host filesystem ACLs, Docker capability
  defaults, backup encryption, MySQL TLS/network ACLs and core-dump policy
  manually.
- Confirm browser flows, Java Windows classpath instructions and example runtime
  behaviour against a newly issued production licence after safe deployment.

## 22. Final Notes

The new features do not introduce a demonstrated licence-signature spoofing or
favicon SSRF path. The most serious risk is operational and already active:
known-exposed production secrets have not been rotated. A push of source commits
is safe; representing a new production restart as secure is not. The audit is a
point-in-time review and does not replace recurring scans, external penetration
testing, incident review, restore tests or cryptographic key ceremonies.
