# Security Audit Report

## 1. Executive Summary

This focused follow-up reviewed BlackWall's dependency and container exposure in response to the repository's Dependabot alerts. The reachable findings identified by Go's official vulnerability scanner were remediated in four independent commits: the Go toolchain, server dependencies, Terraform provider dependencies, and container runtime. The completed container image reports zero fixed vulnerabilities across Alpine packages and the compiled Go binary.

One advisory remains visible to `govulncheck` at module level: the deprecated `golang.org/x/crypto/openpgp` package has no upstream fix. BlackWall does not import that package, so the scanner found no affected package or reachable call path. The maintained `golang.org/x/crypto` packages that BlackWall does use were updated.

The GitHub Dependabot API could not be queried because the local GitHub CLI has no authenticated account. Consequently, this review reconstructed the actionable alert set from `go.mod`, `go.sum`, the Dockerfile, `govulncheck`, Alpine support data, and Trivy. GitHub may need time to rescan the pushed commits before its alert count changes.

## 2. Scope Reviewed

- Root Go module and compiled BlackWall server.
- Nested Go module under `tools/terraform-provider-blackwall`.
- Docker builder and Alpine runtime stages.
- Dependency-update coverage for both modules and Docker.
- The application security findings in `20260609-1705-securityAudit.md` were not re-audited except where dependency updates intersected them.

## 3. Methodology

The review used module-manifest inspection, official Go vulnerability analysis with `govulncheck`, full tests in both Go modules, a clean Docker build with current base layers, and a Trivy scan of the completed image. Findings were matched to imported packages and reachable symbols so module-only advisories were distinguished from exploitable application paths. Each remediation category was committed independently for review and rollback.

## 4. Risk Rating Method

Severity reflects remote reachability, required privileges, likely confidentiality/integrity/availability impact, and deployment exposure. Confidence is based on scanner evidence plus package and call-path analysis. A module-level alert without an imported affected package is recorded but not treated as a reachable application vulnerability.

## 5. Attack Surface Map

- **Public HTTP server:** request parsing, TLS clients, URL handling, HTML templates, XML and ASN.1 parsing, and Chi middleware.
- **Identity protocols:** OAuth/OIDC, SAML, SCIM, WebAuthn, and administrative APIs.
- **Terraform provider:** gRPC/plugin transport, text processing, HTTP clients, and provider configuration.
- **Container supply chain:** Go compiler and standard library, Alpine runtime packages, certificates, and timezone data.
- **Update automation:** root module, nested provider module, and Dockerfile.

## 6. Findings Summary Table

| ID | Severity | Confidence | Title | Component | Status |
|---|---|---|---|---|---|
| DEP-001 | High | High | Reachable Go standard-library vulnerabilities | Server and provider toolchains | Fixed |
| DEP-002 | High | High | Chi trusted spoofable forwarding headers | HTTP middleware | Fixed |
| DEP-003 | Medium | High | Outdated server cryptography dependencies | Root Go module | Fixed |
| DEP-004 | High | High | Reachable gRPC and text-processing vulnerabilities | Terraform provider | Fixed |
| DEP-005 | High | High | Unsupported Alpine runtime and outdated OpenSSL packages | Container image | Fixed |
| DEP-006 | Informational | High | Deprecated OpenPGP package exists in required module | Unused `x/crypto/openpgp` package | Not Reachable; No Upstream Fix |
| DEP-007 | Low | High | Incomplete automated dependency-update coverage | Repository configuration | Fixed |

## 7. Detailed Findings

### Finding ID: DEP-001

#### Title
Reachable Go standard-library vulnerabilities

#### Severity
High

#### Confidence
High

#### Affected Files / Components
Root and Terraform provider `go.mod` files; Docker builder image; URL, template, TLS, HTTP, XML, and ASN.1 call paths.

#### Description
Go 1.26.4 contained several security defects reachable from BlackWall, including denial-of-service conditions and incorrect security-sensitive parsing or validation behavior. The official scanner reported fixes in Go 1.26.5 or 1.26.6.

#### Evidence
The toolchain directives and Docker builder now use Go 1.26.6. A post-update `govulncheck ./...` reports no affected vulnerabilities in either module.

#### Attack Scenario
An unauthenticated or protocol-level attacker supplies crafted URLs, HTTP traffic, templates/data, TLS behavior, XML, or ASN.1 input to trigger excessive resource consumption or incorrect validation.

#### Impact
Depending on the call path, service degradation, request-handling failure, or security-control bypass.

#### Recommendation
Keep the application and container builder on supported Go patch releases and block releases when `govulncheck` identifies reachable findings.

#### Safer Example
Use a current patch-level `toolchain` directive and matching `golang:<version>-alpine` builder image.

#### Suggested Tests
Run root and nested-module tests plus `govulncheck ./...` after every toolchain update.

#### References
Go vulnerability database advisories GO-2026-6218, GO-2026-6091, GO-2026-6090, GO-2026-6089, GO-2026-6088, GO-2026-5972, GO-2026-5856, and GO-2026-5026.

#### Assumptions / Limitations
Scanner reachability is static and cannot model every runtime configuration, but all identified fixes were applied regardless.

### Finding ID: DEP-002

#### Title
Chi trusted spoofable forwarding headers

#### Severity
High

#### Confidence
High

#### Affected Files / Components
`github.com/go-chi/chi/v5` middleware and any IP-dependent request controls.

#### Description
Chi 5.2.2 contained multiple `RealIP` parsing issues that could allow attacker-controlled forwarding values to be interpreted as the client address. A separate redirect middleware issue was also present in the installed version.

#### Evidence
The root module now requires Chi 5.3.1, above the fixed versions reported for GO-2026-5777, GO-2026-5775, GO-2026-5774, and GO-2026-4316. Root tests and `govulncheck` pass.

#### Attack Scenario
An attacker crafts forwarding headers to influence IP-based auditing, limiting, or policy decisions when traffic reaches the middleware through a permissive proxy chain.

#### Impact
Incorrect attribution and possible bypass of IP-based controls.

#### Recommendation
Retain the upgraded dependency and ensure the reverse proxy overwrites, rather than appends untrusted, forwarding headers.

#### Safer Example
Trust forwarding headers only from a controlled proxy and use the current Chi release.

#### Suggested Tests
Exercise direct and proxied requests containing conflicting `Forwarded` and `X-Forwarded-For` values.

#### References
Go vulnerability database advisories GO-2026-5777, GO-2026-5775, GO-2026-5774, and GO-2026-4316.

#### Assumptions / Limitations
Deployment-specific proxy behavior was not tested in this dependency-focused review.

### Finding ID: DEP-003

#### Title
Outdated server cryptography dependencies

#### Severity
Medium

#### Confidence
High

#### Affected Files / Components
`golang.org/x/crypto`, `filippo.io/edwards25519`, and transitive system packages in the root module.

#### Description
The server required versions covered by cryptography and SSH-family advisories. The affected SSH and agent packages were not called by BlackWall, while the Edwards25519 advisory was present in an imported package without an observed vulnerable call.

#### Evidence
The root module now uses `golang.org/x/crypto` 0.55.0 and `filippo.io/edwards25519` 1.2.0. Current scanning reports no reachable or imported-package vulnerability.

#### Attack Scenario
Future code could make a currently dormant advisory reachable, or a transitive package could invoke affected behavior not captured by the present static call graph.

#### Impact
Preventive reduction of cryptographic and protocol risk.

#### Recommendation
Keep direct cryptographic dependencies current and review new imports for package-specific advisories.

#### Safer Example
Prefer maintained primitives such as the currently used Argon2 and ChaCha20-Poly1305 packages over deprecated composite APIs.

#### Suggested Tests
Retain cryptographic round-trip, corruption, and boundary tests when updating these modules.

#### References
GO-2026-4503 and the GO-2026-50xx `x/crypto/ssh` advisory family.

#### Assumptions / Limitations
This severity is preventive because the vulnerable functions were not reachable in the scanned build.

### Finding ID: DEP-004

#### Title
Reachable gRPC and text-processing vulnerabilities in the Terraform provider

#### Severity
High

#### Confidence
High

#### Affected Files / Components
`tools/terraform-provider-blackwall`; gRPC, `x/text`, `x/net`, protobuf, and related transitive modules.

#### Description
The provider included a reachable gRPC advisory and a reachable Unicode/text-processing advisory, with another imported networking advisory identified without a vulnerable call.

#### Evidence
The provider now uses gRPC 1.83.0, `x/text` 0.41.0, and `x/net` 0.58.0. Its complete test suite and `govulncheck ./...` pass.

#### Attack Scenario
Crafted protocol or text input reaches vulnerable parsing behavior during provider execution or plugin communication.

#### Impact
Provider process denial of service or incorrect text handling.

#### Recommendation
Maintain and scan the nested module independently; root-module scans do not cover it.

#### Safer Example
Run Go tests and `govulncheck` from both module directories in CI.

#### Suggested Tests
Add automated nested-module scanning and representative provider protocol integration tests.

#### References
GO-2026-6061, GO-2026-5970, and GO-2026-5942.

#### Assumptions / Limitations
No live Terraform CLI compatibility test was run; compilation and provider unit tests passed.

### Finding ID: DEP-005

#### Title
Unsupported Alpine runtime and outdated OpenSSL packages

#### Severity
High

#### Confidence
High

#### Affected Files / Components
Runtime stage in `Dockerfile`.

#### Description
The image used Alpine 3.20 after its support end date. Moving to Alpine 3.23.4 alone still inherited OpenSSL 3.5.6 packages with fixed vulnerabilities because the tagged base layer lagged the package repository.

#### Evidence
The runtime now uses Alpine 3.23.4 and performs `apk upgrade --no-cache` before installing runtime packages. The rebuilt image upgraded to Alpine release 3.23.5 packages and OpenSSL 3.5.7. Trivy reports zero vulnerabilities with available fixes in both the Alpine filesystem and Go binary.

#### Attack Scenario
An attacker reaches a vulnerable TLS or cryptographic behavior through outbound connections or certificate processing in the deployed container.

#### Impact
Cryptographic failure, denial of service, or other advisory-specific impact; continued use of an unsupported distribution also prevents reliable security maintenance.

#### Recommendation
Rebuild regularly even when source is unchanged, keep the runtime on a supported Alpine branch, and scan the final image rather than only its manifests.

#### Safer Example
Upgrade runtime packages during the image build and verify the exact resulting image with an OS-aware vulnerability scanner.

#### Suggested Tests
Build with fresh base layers, run the image as the unprivileged `blackwall` user, and scan both OS packages and embedded Go modules.

#### References
Alpine Linux release lifecycle; CVE records supplied by the Alpine security database and Trivy.

#### Assumptions / Limitations
The scan used the vulnerability database available on 2026-08-15 and excluded advisories without any published fix.

### Finding ID: DEP-006

#### Title
Deprecated OpenPGP package exists in a required module

#### Severity
Informational

#### Confidence
High

#### Affected Files / Components
The `golang.org/x/crypto` module contains `openpgp`, but BlackWall does not import it.

#### Description
GO-2026-5932 marks the OpenPGP implementation as unmaintained and provides no fixed module version. Go modules are versioned as a whole, so the advisory can be associated with the required module even when the affected package is absent from the application call graph.

#### Evidence
Post-remediation `govulncheck` reports zero vulnerabilities affecting BlackWall, zero in imported packages, and one in a required module whose affected package is not called. Repository search and the scanner call graph show no OpenPGP import.

#### Attack Scenario
There is no current application path. Risk would arise if future code imported `golang.org/x/crypto/openpgp`.

#### Impact
No demonstrated current impact.

#### Recommendation
Do not import `x/crypto/openpgp`; use a maintained OpenPGP implementation if the feature is ever required. Document this scanner exception instead of suppressing all `x/crypto` advisories.

#### Safer Example
Use narrow imports for the maintained `x/crypto` primitives already required by BlackWall.

#### Suggested Tests
Add a dependency-policy check that fails if an `openpgp` package appears in `go list -deps`.

#### References
GO-2026-5932.

#### Assumptions / Limitations
GitHub may continue to display a module-level alert because no patched upstream version exists.

### Finding ID: DEP-007

#### Title
Incomplete automated dependency-update coverage

#### Severity
Low

#### Confidence
High

#### Affected Files / Components
Repository automation configuration.

#### Description
There was no repository-local Dependabot update configuration covering the two independent Go modules and Dockerfile.

#### Evidence
`.github/dependabot.yml` now schedules weekly checks for the root Go module, nested provider module, and Docker ecosystem.

#### Attack Scenario
Security patches remain unnoticed or are applied inconsistently because one dependency ecosystem is omitted from routine updates.

#### Impact
Longer exposure window and recurring dependency drift.

#### Recommendation
Enable Dependabot security updates in repository settings and require tests/scans for generated pull requests.

#### Safer Example
Treat each Go module as a separate ecosystem entry and scan the built container after Docker updates.

#### Suggested Tests
Confirm GitHub recognizes all three entries after push and that update pull requests trigger required checks.

#### References
GitHub Dependabot configuration documentation.

#### Assumptions / Limitations
Repository settings were not accessible from the unauthenticated local GitHub CLI.

## 8. Cryptography and Key-Management Review

This pass did not redesign application cryptography or secret storage. It verified that maintained versions of the used cryptographic primitives are selected and that the deprecated OpenPGP package is not imported. No private keys, credentials, or token values were printed or added to the reports. The broader key-lifecycle findings and recommendations from the June 2026 audit remain applicable.

## 9. Denial-of-Service and Resource-Exhaustion Review

Several remediated Go, Chi, gRPC, XML, ASN.1, TLS, HTTP, and text-processing advisories included denial-of-service behavior. Static reachability analysis and final binary scanning now report no affected calls. Existing application request-size, decompression, timeout, and rate-limit controls were not comprehensively re-tested in this focused review.

## 10. Frontend and Browser Robustness Review

No package-manager-controlled frontend dependencies were found in scope. Embedded templates compile as part of the Go test/build path. The CSP and externally hosted asset recommendations from the previous full audit remain open and were not altered here.

## 11. Verification Performed

- Root module: complete `go test ./...` passed under Go 1.26.6.
- Terraform provider: complete `go test ./...` passed under Go 1.26.6.
- Root module: `govulncheck ./...` reports zero affected vulnerabilities and zero vulnerable imported packages.
- Terraform provider: `govulncheck ./...` reports no vulnerabilities.
- Container: clean build from current base layers completed.
- Container: Trivy reported zero fixed vulnerabilities at Critical, High, Medium, or Low severity for both Alpine packages and the Go binary.
- Container: runtime user remained `blackwall`.

## 12. Residual Risk and Limitations

- GitHub's exact alert list and closure state could not be read without a GitHub CLI login.
- GO-2026-5932 has no fixed upstream version, though its affected package is not imported.
- Vulnerability databases evolve after an image is built; recurring scans are still required.
- The updates passed tests but should also be observed after production deployment, particularly identity flows and Terraform provider interoperability.
- This was a dependency-focused follow-up, not a replacement for the full application audit.
