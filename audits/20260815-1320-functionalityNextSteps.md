# Functionality and Next Steps Report

## 1. Executive Summary

The dependency remediation leaves BlackWall, its Terraform provider, and the production container build free of known reachable vulnerabilities reported by the scanners used on 2026-08-15. The next practical step is to make that result repeatable in CI and production rather than relying on periodic manual review.

## 2. Current Functional Risks

- GitHub's alert status was not directly verified because the local GitHub CLI is unauthenticated.
- A newly disclosed vulnerability can affect a previously built image even when source files have not changed.
- Root-module tooling does not automatically inspect the independent Terraform provider module.
- The no-fix OpenPGP advisory can remain visible at module level and needs a documented, narrow exception based on package reachability.
- Dependency updates have unit coverage but no automated end-to-end identity-protocol or Terraform CLI compatibility gate.

## 3. Code Quality Improvements

1. Centralize the supported Go, Alpine, and scanner versions used by local builds and CI to prevent drift.
2. Add a repository script that runs tests and `govulncheck` in every Go module discovered in the tree.
3. Record scanner versions and vulnerability database timestamps in release evidence.
4. Keep dependency-only commits isolated by ecosystem, as in this remediation, to simplify review and rollback.
5. Add a policy check preventing imports of `golang.org/x/crypto/openpgp`.

## 4. Frontend Interaction and Error-Handling Improvements

There were no JavaScript package-manager dependencies in this alert set. Continue compiling embedded templates in tests, add browser coverage for login and admin flows after framework/toolchain updates, and retain the prior recommendation to self-host browser assets under a strict Content Security Policy.

## 5. Testing Roadmap

- **Every change:** run root and provider tests.
- **Dependency changes:** run `govulncheck` separately in both modules.
- **Container changes:** build with fresh base layers and scan the final image's OS and Go binary contents.
- **Release candidates:** exercise WebAuthn, OAuth/OIDC, SAML, SCIM, Cryptbin, admin, and Terraform provider smoke paths.
- **Scheduled:** rebuild and rescan the unchanged source weekly so base-image and database changes are detected.

## 6. Recommended New Functionality

- Add required CI jobs for root tests/scanning, provider tests/scanning, and final-image scanning.
- Generate CycloneDX or SPDX SBOMs for release images and retain them with build provenance.
- Sign release images and verify signatures during deployment.
- Publish a dependency-support policy covering Go and Alpine patch cadence.
- Add a small admin-facing build/security status panel showing application version, commit, build time, and last successful vulnerability scan metadata without exposing internal package details.

## 7. Next-Level Opportunities

- Use digest-pinned base images with an automated update mechanism so builds are reproducible while still receiving reviewed refreshes.
- Add SLSA-compatible provenance for server binaries, provider artifacts, and images.
- Export dependency inventory and scan outcomes to the operational monitoring system.
- Gate production rollout on an image digest that has passed the exact scanner policy used in CI.

## 8. Prioritised Action Plan

- **Immediate:** push the isolated commits, let GitHub rescan, and verify which Dependabot alerts close or remain.
- **Short-term:** add required CI vulnerability checks for both Go modules and the final container image.
- **Medium-term:** add SBOMs, signed artifacts, protocol smoke tests, and scheduled clean rebuilds.
- **Long-term:** integrate build provenance and scan attestations into deployment policy.

## 9. Caveats and Validation Needed

The review used locally available source, module metadata, the official Go vulnerability database, Alpine package metadata, and Trivy. It did not access the private GitHub Dependabot dashboard, run a live Terraform CLI session, or execute full browser/protocol integration suites. GitHub repository owners should confirm that security updates are enabled and inspect any residual alert after the platform finishes rescanning.
