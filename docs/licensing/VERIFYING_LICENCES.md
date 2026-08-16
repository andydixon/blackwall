# Verifying Blackwall Project Licences

This document is the normative integration guide for project licences issued by
Blackwall. Examples use the production issuer `https://blackwall.cx`; replace it
only when your licence was issued by a separately operated Blackwall instance.

Blackwall uses **Ed25519 digital signatures**, not an X.509 certificate. Adding a
self-signed certificate would not create trust: a verifier would still need to
pin its issuer. Ed25519 gives a small, deterministic, modern signature while the
fixed HTTPS issuer and published key fingerprint provide the trust anchor.

## Security contract

A licence is accepted only when every one of these conditions holds:

1. The envelope is exactly `BWLIC1.<payload-base64url>.<signature-base64url>` and
   stays within the documented size limits.
2. The Ed25519 signature verifies over the ASCII bytes
   `BWLIC1.<payload-base64url>` using the key identified by the signed `kid`.
3. The key ID is itself derived from that public key, and the key registry does
   not mark it `compromised`.
4. The signed `v`, `iss`, `aud`, `project_uuid`, `iat`, `nbf`, and `exp` claims
   have their expected values.
5. The runtime hostname, after lower-casing and removal of one terminal dot, is
   an exact member of `hostnames`. Wildcards, URLs, ports, user information,
   paths, and Unicode DNS input are rejected. International names must be passed
   as their ASCII punycode form.
6. `max_instances` and every requested feature are enforced by the licensed
   application. A signature verifies what Blackwall issued; it cannot count
   application instances on its own.
7. The authoritative online endpoint confirms that the exact signed bytes are
   recorded, the project remains active, the signing key is not compromised,
   and the licence has not been revoked.

Do not decode the JSON and trust it before verifying the signature. Do not
accept a licence after a network or parser error. Do not let an environment
variable, request header, or the licence itself replace the expected issuer,
project UUID, or runtime hostname.

## Signed claim set

The payload is canonical UTF-8 JSON with this version-1 shape:

```json
{
  "v": 1,
  "licence_id": "38a46ec2-7f4d-4a77-99dc-2298b16acb08",
  "iss": "https://blackwall.cx",
  "aud": "blackwall-licence",
  "project_uuid": "aa88643b-889d-4ce7-a96d-4a562065c880",
  "entity": {
    "type": "business",
    "name": "Example Limited",
    "reference": "CUS-42"
  },
  "hostnames": ["app.example.com"],
  "features": ["api", "reports"],
  "max_instances": 2,
  "iat": 1786795200,
  "nbf": 1786795200,
  "exp": 1818331200,
  "kid": "bwlic_...",
  "status_url": "https://blackwall.cx/licences/v1/verify",
  "online_check_seconds": 86400
}
```

Timestamps are Unix seconds in UTC. `features` is an allow-list of entitlement
identifiers. An empty feature list means that the licence itself imposes no
feature restriction; it does not grant features that the application lacks.

## Authoritative online verification

Send a JSON `POST` to the fixed issuer endpoint. The request must not be cached:

```http
POST /licences/v1/verify HTTP/1.1
Host: blackwall.cx
Content-Type: application/json

{
  "licence": "BWLIC1.eyJ2Ijox...",
  "expected_hostname": "app.example.com",
  "project_uuid": "aa88643b-889d-4ce7-a96d-4a562065c880"
}
```

A successful check returns HTTP 200:

```json
{
  "valid": true,
  "code": "valid",
  "checked_at": "2026-08-15T12:00:00Z",
  "claims": { "v": 1, "licence_id": "..." }
}
```

HTTP 200 with `valid: false` is a completed rejection. HTTP 400 means the
request itself was invalid; HTTP 429 means the caller is rate-limited; HTTP 5xx
means verification is unavailable. Every non-valid outcome must fail closed.

Stable rejection codes include `invalid_licence`, `issuer_mismatch`,
`project_mismatch`, `hostname_mismatch`, `not_yet_valid`, `expired`, `revoked`,
`project_disabled`, `key_compromised`, `not_recorded`, and `record_mismatch`.
Treat codes as diagnostic values, not as permission to bypass a failed check.

The four examples below use this authoritative endpoint, retain normal TLS
certificate and hostname validation, pin the endpoint in source, require a
fresh `checked_at`, and re-check the echoed claims:

- [PHP example](examples/php/verify.php)
- [Go example](examples/go/main.go)
- [Rust example](examples/rust/src/main.rs)
- [Java example](examples/java/src/main/java/cx/blackwall/examples/VerifyLicence.java)

Each program reads the licence from a file instead of a command-line argument,
because command-line arguments are commonly visible in process listings and
diagnostic captures.

Run them as follows:

```bash
# PHP 8.1+ with cURL
php docs/licensing/examples/php/verify.php licence.bwlic app.example.com "$PROJECT_UUID"

# Go 1.22+
(cd docs/licensing/examples/go && go run . ../../../../licence.bwlic app.example.com "$PROJECT_UUID")

# Rust (dependencies are pinned in Cargo.lock)
(cd docs/licensing/examples/rust && cargo run -- ../../../../licence.bwlic app.example.com "$PROJECT_UUID")

# Java 17+ with Maven
cd docs/licensing/examples/java
mvn -q compile dependency:copy-dependencies
java -cp 'target/classes:target/dependency/*' \
  cx.blackwall.examples.VerifyLicence ../../../../licence.bwlic app.example.com "$PROJECT_UUID"
```

The Java example deliberately accepts DNS hostnames only; use the server-side
verifier directly or extend its normaliser with a non-resolving IP parser when a
licence is intentionally bound to an IP literal.

## Offline signature verification

Offline checks are useful during a short issuer outage, but cannot discover a
revocation made after the last online check. A production verifier should cache
the last successful online result for no longer than the signed
`online_check_seconds`; after that deadline it must fail closed or enter an
explicit, tightly bounded operator-approved grace mode.

1. Fetch `https://blackwall.cx/.well-known/blackwall-licence-keys.json` over
   verified HTTPS during deployment and at least every five minutes while
   online.
2. Pin the expected `fingerprint_sha256` in application configuration or a
   signed deployment artefact. Do not accept a new key merely because an
   untrusted licence names it.
3. Split the token into exactly three non-empty segments. Require `BWLIC1` and
   reject input above 16 KiB.
4. Decode unpadded base64url strictly. Require a payload of at most 8 KiB, a
   64-byte signature, and a 32-byte Ed25519 public key.
5. Parse JSON with duplicate and unknown fields rejected. The signed payload is
   the original base64url segment; never parse and reserialise before signature
   verification.
6. Find the key whose `kid` equals the signed `kid`. Recalculate the key ID as
   `"bwlic_" + base64url(SHA-256(public_key)[0:18])` and compare it too.
7. Reject `compromised`; accept `active` and `retired` for signatures made before
   rotation. Verify the Ed25519 signature over the exact ASCII prefix and payload
   segment.
8. Apply the issuer, audience, version, project, exact-hostname, time, feature,
   and instance checks in the security contract above.
9. Require an online result again before the signed check interval expires.

Never ship a private signing key, a symmetric “licence secret”, or code that can
mint licences inside the licensed application. Only public verification keys
belong there.

## Issuer key setup and rotation

Generate a PKCS#8 Ed25519 key on the Blackwall host or, preferably, inside the
secret-management system that will mount it:

```bash
umask 077
openssl genpkey -algorithm Ed25519 \
  -out /run/secrets/blackwall_licence_ed25519.pem
chmod 0600 /run/secrets/blackwall_licence_ed25519.pem
```

Configure only the path:

```yaml
licence_signing_key_file: "/run/secrets/blackwall_licence_ed25519.pem"
licence_max_validity_days: 365
licence_clock_skew_seconds: 120
licence_online_check_seconds: 86400
```

The service refuses non-regular files, loose file permissions, non-PKCS#8 PEM,
and non-Ed25519 keys. It stores only public keys. Replacing the mounted key and
restarting registers the new public key as active and retires the previous key;
existing licences remain verifiable.

If a key may have been exposed:

1. Stop issuance and preserve logs.
2. Mark its row `compromised` in `licence_signing_keys`; online verification and
   export then reject every licence under that key, and Blackwall refuses to
   reactivate it.
3. Install a new key, restart, and reissue affected licences after validating
   the entities and hostnames independently.
4. Revoke the old licence rows with an incident reference and notify every
   verifier to refresh the key registry immediately.

Marking a key compromised is intentionally disruptive. Do not change it back to
`active`; create a new key instead.

## Operational checks

- Alert when the admin dashboard has no successful vulnerability-scan metadata.
- Alert on repeated `hostname_mismatch`, `invalid_licence`, or `key_compromised`
  results without logging the licence token or entity details.
- Keep system clocks synchronised. Never “fix” clock errors by increasing skew
  beyond the configured ten-minute hard limit.
- Back up licence rows and the public key registry with the database. Back up
  the private key separately through the secret manager; never in the same
  archive.
- Enable the independently configured renewal reminder worker where required;
  see [Project Licence Renewal Reminders](RENEWAL_REMINDERS.md). Reminder email
  is an operational courtesy and never replaces fail-closed expiry enforcement.
- Test tampered payloads, tampered signatures, wrong projects, wrong hostnames,
  expiry, future `nbf`, revocation, disabled projects, retired keys, compromised
  keys, timeouts, malformed JSON, and oversized input before release.
