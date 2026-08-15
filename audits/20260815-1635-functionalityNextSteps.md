# Functionality and Next Steps Report

## 1. Executive Summary

The requested build/security panel, managed project licences, four integration
examples and OAuth client favicons are functionally complete in source. The
highest-impact next step is not another UI feature: it is a safe production
secret-rotation programme, including a Cryptbin KEK re-wrapping migration. Until
that is complete, the new licence signer should not be provisioned into the same
release restart.

After that blocker, the most valuable improvements are pagination and automation
for licences, KMS/HSM signing, activation leases for stronger commercial
enforcement, atomic distributed rate limiting, and end-to-end browser/protocol
tests.

## 2. Current Functional Risks

- Production secrets known to Git history are unchanged; blind KEK rotation can
  break existing Cryptbin items.
- Production has no mounted/configured licence signing key, so issuance will
  remain intentionally disabled after a binary-only rollout.
- Admin-token scope labels do not alter behaviour, which can surprise automation
  owners and expand incidents.
- Project licence lists stop at 1,000 without pagination or a visible truncation
  notice.
- Authoritative verification depends on a shared per-IP limit, which can affect
  many installations behind one NAT and can overrun under concurrency.
- Favicon retrieval intentionally supports only conventional `/favicon.ico`
  without redirects; some sites using only HTML `<link rel=icon>` or CDN redirects
  will show the initial fallback.
- Java example build instructions use a Unix classpath separator; Windows users
  need `;` rather than `:`.

## 3. Code Quality Improvements

1. Split the large admin and OAuth handler files by bounded domain to make scope,
   CSRF and error-handling invariants easier to review.
2. Replace ignored mutation/query/session errors on security-relevant paths with
   explicit failure responses and audit outcomes.
3. Centralise exact hostname normalisation test vectors and publish them as
   cross-language fixtures so PHP/Go/Rust/Java cannot drift.
4. Extract a signer interface from `LicenceService`; keep the file signer as one
   implementation and add KMS/HSM implementations without changing claims.
5. Open/stat/read key files through one descriptor and isolate secret-memory
   handling in a small package.
6. Replace dynamic rate-limit read/modify/write code with one transactional
   repository operation.
7. Represent build scan status as a signed release-attestation reference tied to
   image digest, not just free build arguments.

## 4. Frontend Interaction and Error-Handling Improvements

- Add a visible, accessible tooltip when the client favicon is unavailable, while
  keeping the initial fallback and avoiding remote error details.
- Add pagination, search by licence ID/entity/hostname, status filters and a clear
  “showing first 1,000” state to the licence register.
- Confirm destructive revoke intent in an accessible modal and prevent duplicate
  submissions while the request is in flight.
- Provide copy buttons for licence ID, key ID and verification endpoint with
  non-sensitive success feedback.
- Self-host Bootstrap/fonts, move inline scripts into embedded assets, and adopt a
  nonce/hash CSP before adding more client-side behaviour.
- Log only safe `console.warn` context for favicon/UI failures; never include
  licence tokens, entity data, session data or WebAuthn assertion bytes.

## 5. Testing Roadmap

- **Unit:** shared canonical licence fixtures, maximum/minimum timestamps,
  duplicates, Unicode/control text, instance/feature boundaries, COSE overflow,
  favicon mixed DNS/special ranges and cache eviction.
- **Database integration:** migrate from v5 to v6, issue/list/download/revoke,
  cross-project IDOR denial, disabled project, retired/compromised key, concurrent
  rotation and exact byte-anchor mismatch.
- **HTTP integration:** strict verifier JSON/body/rate responses, public key cache
  headers, favicon exact-client/redirect checks, ETag/304, redirect rejection and
  TLS/MIME/size failures.
- **Browser:** WebAuthn login, consent favicon load/error fallback, licence form,
  revoke collapse/confirmation, scoped operator versus super-admin behaviour and
  CSP console cleanliness.
- **Cross-language contract:** issue one deterministic fixture and run PHP, Go,
  Rust and Java accepted/rejected vectors in CI.
- **Load/abuse:** concurrent atomic rate-limit proof, verification load, favicon
  distinct-host pressure, large licence register and webhook retry contention.
- **Operations:** backup/restore, schema migration, key rotation/compromise,
  Cryptbin KEK re-wrap and full rollback drills.

## 6. Recommended New Functionality

- A licence activation/lease API using a generated installation public key,
  bounded active installations and signed short-lived leases. This raises the
  cost of copying but must not be marketed as unpatchable client enforcement.
- Per-project licence policies: permitted validity, required online interval,
  allowed features, instance ceiling and approval requirement.
- Bulk CSV/JSON metadata export without signed tokens or unnecessary PII.
- Expiry/online-check/key-compromise alerts and webhook events with privacy-safe
  identifiers.
- Managed key rotation UI backed by KMS/HSM, dual-control approval and a ceremony
  audit record; never upload raw private keys through the browser.
- Licence usage telemetry only as explicit opt-in, data-minimised and documented.
- A release-evidence page linking version/commit/image digest to scan attestation,
  SBOM and deployment time without exposing package inventory publicly.

## 7. Next-Level Opportunities

- Move licence signing into a network-isolated signer with a narrow sign-only API,
  workload identity, rate controls and immutable key audit trail.
- Publish official verifier libraries/packages for PHP Composer, Go, Rust Cargo
  and Java Maven, generated from shared vectors and versioned independently.
- Add image signing, SBOMs, SLSA-style provenance and deployment verification of
  the scanned digest.
- Introduce a durable, atomic distributed rate-limit backend or well-tested MySQL
  stored operation with visibility into saturation and false positives.
- Add accessibility testing and progressive enhancement for all admin controls.
- Plan a versioned hybrid post-quantum licence signature only when maintained
  interoperable libraries are available; preserve version-1 verification during
  migration.

## 8. Prioritised Action Plan

- **Immediate:** design/test the KEK re-wrap, rotate all exposed production
  material, invalidate sessions/tokens, purge history and inspect access logs.
- **Short-term:** deploy the additive migration and features with a separately
  mounted licence key; enforce admin-token scopes; fix rate-limit atomicity; add
  licence/favicons HTTP and MySQL integration tests.
- **Medium-term:** pagination/search, activation leases, KMS signer, expiry alerts,
  self-hosted frontend assets and strict CSP.
- **Long-term:** official verifier packages, signed release evidence, recurring
  restore/key ceremonies, PQ transition plan and external penetration testing.

## 9. Caveats and Validation Needed

No private production credential was used or printed. The exact data affected by
the historic exposure, prior access, backup copies, Git hosting visibility and
Cryptbin item count require owner/incident review. No live production migration,
licence issue or restart was performed because the secret-rotation blocker is
unresolved. Browser interactions were statically reviewed and template-tested,
not exercised with a real passkey in an automated browser. Licence enforcement
inside software fully controlled by a hostile customer remains patchable by
design; activation and server-side entitlement checks can raise assurance but
cannot repeal that boundary.

