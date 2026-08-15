# BlackWall

OAuth 2.1 + OpenID Connect authorisation server with WebAuthn (passkey)
authentication. Single static binary, no external runtime dependencies.

## What it does

- **OAuth 2.1 / OIDC** — Authorisation Code + PKCE (S256), refresh tokens
  (single-use with token-family revocation), token revocation (RFC 7009),
  introspection (RFC 7662), discovery, JWKS, ID tokens with `at_hash` and
  `auth_time`, `max_age` reauthentication enforcement, UserInfo.
- **WebAuthn** — passwordless authentication via passkeys (ES256 / RS256).
  Sign-counter regression detection, mandatory User Verification (UV), full
  CBOR / COSE attestation parsing.
- **Custom OIDC claims** — per-user and per-user-per-project key/value pairs
  merged into every issued ID token and `/oauth/userinfo` response. Reserved
  JWT / OIDC claim names are blocked at write time and re-blocked at signing
  time (defence in depth).
- **Admin panel** — full RBAC (`super_admin` / `operator` / `auditor`),
  approval workflow for sensitive mutations, scope-aware visibility for
  organisations and projects, integrity-chained audit log with HMAC-signed
  CSV export, in-app documentation guide.
- **CryptBin** — end-to-end encrypted blob storage. Client-side AES-256-GCM
  on payloads; server-side XChaCha20-Poly1305 wraps the per-item DEK with
  AAD bound to the blob ID. Optional per-item WebAuthn binding.
- **Portal** — self-service for end users to manage their passkeys.
- **Metrics** — Prometheus-compatible `/metrics` plus optional outbound push
  of every audit event to vmagent / VictoriaMetrics.
- **Auto-migrating schema** — forward-only, idempotent migrations applied
  on every startup; tracked in `schema_migrations`.

## Requirements

- Go 1.25+ (for compiling from source)
- MySQL 8.0+
- Docker + Docker Compose for the supported deployment path
- `supervisord` on the host if you want process supervision (sample unit included)

## Build

The `build.sh` script handles compile + container build + tag in one go.

```bash
cd blackwall-go
./build.sh                 # compile binary AND build blackwall:<version> + :latest
./build.sh --binary-only   # just produce dist/blackwall
./build.sh --image-only    # just build the Docker image
./build.sh --image my.registry/blackwall --push   # tag for a private registry and push
./build.sh --no-latest     # release builds: don't move :latest
```

Cross-compile for a different target by setting `GOOS` / `GOARCH`:

```bash
GOOS=linux GOARCH=arm64 ./build.sh --binary-only
```

Override the auto-detected version (defaults to `git describe`):

```bash
VERSION=1.4.0 ./build.sh
```

Release pipelines should also pass the completion time and opaque report or
pipeline reference for the most recent successful vulnerability scan. BlackWall
shows these values to authenticated administrators, but deliberately does not
embed affected package names or findings in the binary:

```bash
VULNERABILITY_SCAN_DATE=2026-08-15T12:30:00Z \
VULNERABILITY_SCAN_REFERENCE=ci/security/1842 \
./build.sh
```

If either value is missing or the time is not RFC 3339, the admin dashboard
reports that scan metadata is absent rather than implying that a scan passed.

## Run with Docker

The image runs the `blackwall` binary directly as PID 1 under an
unprivileged user. Persist the CryptBin storage volume; mount your config
read-only.

```bash
docker run -d --name blackwall \
    -p 8080:8080 \
    -v /etc/blackwall/config.yaml:/etc/blackwall/config.yaml:ro \
    -v blackwall-cryptbin:/var/lib/blackwall/cryptbin \
    blackwall:latest
```

Or use the bundled `docker-compose.yml` which also stands up MySQL.

## Run behind Apache 2

A reference reverse-proxy unit is at `docker/blackwall.apache.conf`. It does
HTTPS termination, redirects HTTP → HTTPS, propagates the real client IP
via `mod_remoteip`, sets `X-Forwarded-Proto` / `X-Forwarded-Host` so
Blackwall builds correct OIDC issuer URLs, and bumps `LimitRequestBody` to
8 MiB so CryptBin uploads aren't truncated at the proxy layer.

You also need to flip two settings in BlackWall's config so it actually
trusts the forwarded headers:

```yaml
trust_proxy: true
trusted_proxies: "127.0.0.1, ::1"   # add any other Apache hosts
```

Without those, `audit_log.ip_address` will read `127.0.0.1` for every
request, the per-IP rate limits stop working, and HSTS won't be emitted.

## Run with supervisord on the host

A sample supervisor unit is at `docker/blackwall.supervisor.conf`. It runs
`docker run --rm` so supervisord (not Docker's `--restart` flag) owns the
process lifecycle — that gives you exponential-backoff retries and a clean
single-source-of-truth config file for all the environment variables.

```bash
sudo cp docker/blackwall.supervisor.conf /etc/supervisor/conf.d/blackwall.conf
# edit the env vars + image tag
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl status blackwall
```

## Configuration

See `config.example.yaml` for every setting with comments explaining what it
controls. All keys can be overridden by the equivalent `UPPER_CASE`
environment variable.

The application refuses to start if any of these are wrong:

- `app_url`, `db_*` empty
- `session_secret` shorter than 32 characters
- `csrf_secret` shorter than 32 characters
- `session_secret` equal to `csrf_secret`

Generate strong values with:

```bash
openssl rand -hex 32       # session_secret, csrf_secret, audit_export_signing_key
openssl rand -base64 32    # cryptbin_kek_base64
```

## Schema migrations

On startup, the binary applies any pending migrations from
`internal/db/migrations.go`, tracked in a `schema_migrations` table.
First-run on an empty database is fine — the application assumes the base
BlackWall schema already exists, plus this binary's own incremental
migrations on top.

## Bootstrap

On first run with no super-admin yet:

1. Visit `/bootstrap?token=<bootstrap_token>` to register the first
   WebAuthn credential against the seeded admin account. The bootstrap token
   lives in `system_config` (key `bootstrap_token`).
2. Visit `/organisations/signup` to self-register additional organisations.
   The first user becomes the org admin and receives a one-shot enrolment
   link.

Bootstrap is disabled automatically once a super-admin exists.

## Admin panel

Access at `/admin`. Roles and capabilities:

| Role          | Headline                                                                 |
|---------------|--------------------------------------------------------------------------|
| `super_admin` | Unrestricted scope, every capability, direct mutations.                  |
| `operator`    | Day-to-day administration scoped to organisations they own. Mutations route through approvals. |
| `auditor`     | Read-only: dashboard, audit log, scope debugger, error-trace decoder, docs. |

The complete capability matrix per role is visible at `/admin/roles` and
documented at `/admin/docs/access-model`.

## Custom OIDC claims

Set custom key/value pairs on a user — either user-wide or scoped to one
project — at `/admin/users/{userUuid}/claims`.

- **User-level claims** appear in every ID token and userinfo response for
  that user.
- **Project-scoped claims** only appear when the issued token is bound to
  that project, and override any user-level value with the same key.
- Values that parse as JSON literals (numbers, booleans, arrays, objects)
  are emitted with that JSON type; otherwise they're emitted as strings.
- Reserved JWT / OIDC claim names (`sub`, `iss`, `aud`, `exp`, `iat`,
  `nbf`, `nonce`, `at_hash`, `scope`, etc.) are rejected at write time.

## API endpoints

| Endpoint                                | Description                                |
|-----------------------------------------|--------------------------------------------|
| `GET /.well-known/openid-configuration` | OIDC discovery document                    |
| `GET /oauth/jwks`                       | JSON Web Key Set                           |
| `GET /oauth/authorize`                  | Authorisation endpoint                     |
| `POST /oauth/token`                     | Token endpoint                             |
| `POST /oauth/revoke`                    | Token revocation (RFC 7009)                |
| `POST /oauth/introspect`                | Token introspection (RFC 7662)             |
| `GET /oauth/userinfo`                   | UserInfo endpoint                          |
| `GET /metrics`                          | Prometheus-compatible metrics              |

Full reference inside the admin panel at `/admin/docs/reference`.

## Development

```bash
go test ./...               # template parse + service unit tests
go vet ./...
./build.sh --binary-only && ./dist/blackwall -config config.yaml
```

### Embedded assets

HTML templates and static assets are compiled into the binary via Go's
`embed` package. Sources live under `internal/templates/web/`. Recompile
after any template or asset change.

```
internal/templates/web/
├── static/                 # CSS, JS, SVG
└── templates/              # Go HTML templates
    ├── admin/
    ├── bootstrap/
    ├── cryptbin/
    ├── oauth/
    ├── organisations/
    └── portal/
```

## Architecture

```
cmd/blackwall/         entry point, router setup, graceful shutdown
internal/
  config/              YAML + env-var configuration with start-up validation
  db/                  MySQL pool + forward-only schema migrations
  handler/             HTTP handlers (admin, oauth, portal, cryptbin, bootstrap, metrics)
  middleware/          chi middleware (auth, rate limit, audit context, IP extraction)
  model/               shared data types
  repository/          database query layer
  security/            CSRF, sessions, capability matrix, mutation policy, PKCE, OAuth client auth
  service/             business logic (WebAuthn, CryptBin KEK / storage, audit logger,
                       approval, admin scope, OIDC claims, JWT, maintenance)
  templates/           embed wrappers + web assets + parse tests
docker/
  blackwall.supervisor.conf   sample host-side supervisord unit
```

## Security notes

- WebAuthn assertions verified server-side — CBOR / COSE parsed manually,
  ES256 and RS256 supported, both UP and UV flags required, sign-counter
  regression rejected.
- Client secrets stored as SHA-256 hashes; verified with constant-time
  comparison.
- Enrolment + bootstrap tokens stored as SHA-256 hashes (the URL carries
  the raw token, the database column never does).
- CSRF tokens are single-use HMAC-SHA-256 values stored in the encrypted
  session.
- Audit log entries are SHA-256 chained under a MySQL `GET_LOCK` so
  concurrent writes serialise correctly; tampering is detectable. Export
  CSV ends with an HMAC-signed manifest line.
- CryptBin blobs are encrypted client-side; the server only stores ciphertext
  and a wrapped DEK. Server-side wrapping uses XChaCha20-Poly1305-IETF
  (libsodium-compatible) with the blob ID bound via AAD.
- Sessions use `gorilla/securecookie` with AES-256 encryption and HMAC-SHA-256
  authentication; cookies are `HttpOnly`, `Secure`, `SameSite=Lax`.
- Admin scope is enforced on every per-resource handler — out-of-scope URLs
  return 403, not 404, so URL-guessing is a deliberate signal in the audit log.
- Mutations on users / projects / clients / assignments require a
  capability-gated `_direct` permission OR they route through the approval
  workflow.
