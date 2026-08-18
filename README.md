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
- **Project licences** — dedicated Ed25519-signed, exact-hostname-bound licence
  envelopes for a person or business, with feature and instance claims,
  scoped administration, key rotation, online verification, revocation, and
  durable renewal reminders at 30, 14, 7, 2, and 1 day remaining.
- **CryptBin** — end-to-end encrypted blob storage. Client-side AES-256-GCM
  on payloads; server-side XChaCha20-Poly1305 wraps the per-item DEK with
  AAD bound to the blob ID. Optional per-item WebAuthn binding.
- **Portal** — self-service for end users to manage their passkeys.
- **Metrics** — Prometheus-compatible `/metrics` plus optional outbound push
  of every audit event to vmagent / VictoriaMetrics.
- **Auto-migrating schema** — forward-only, idempotent migrations applied
  on every startup; tracked in `schema_migrations`.

## Documentation

- [BlackWall User Guide (PDF)](docs/user-guide/BlackWall-User-Guide.pdf) — the
  illustrated, all-audience publication by Andy Dixon.
- [Editable Scribus source](docs/user-guide/BlackWall-User-Guide.sla) and its
  [rebuild notes](docs/user-guide/README.md).
- [Complete repository manual](docs/MANUAL.md).
- [Normative project licence verification guide](docs/licensing/VERIFYING_LICENCES.md)
  with PHP, Go, Rust, and Java examples.
- [Licence renewal reminder operations guide](docs/licensing/RENEWAL_REMINDERS.md).

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

Or use the bundled `docker-compose.yml`, which also starts MySQL. The Compose
file does not seed Blackwall's historical base schema: restore that baseline
into the database volume before starting the application for the first time.

## Run behind a reverse proxy

A reference Apache 2 unit is at `docker/blackwall.apache.conf`. It does
HTTPS termination, redirects HTTP → HTTPS, propagates the real client IP
via `mod_remoteip`, sets `X-Forwarded-Proto` / `X-Forwarded-Host` so
Blackwall builds correct OIDC issuer URLs, and bumps `LimitRequestBody` to
8 MiB so CryptBin uploads aren't truncated at the proxy layer.

You also need to flip two settings in BlackWall's config so it actually
trusts the forwarded headers:

```yaml
trust_proxy: true
trusted_proxies: "127.0.0.1, ::1"   # add any other proxy hosts
```

Without those, `audit_log.ip_address` will read `127.0.0.1` for every
request, the per-IP rate limits stop working, and HSTS won't be emitted.

If you terminate with nginx instead, note that Blackwall's OAuth responses
carry large header blocks — signed session cookies plus the security header
set — which overflow nginx's default 4 KB `proxy_buffer_size` and surface as
`upstream sent too big header` 502s. Raise it:

```nginx
proxy_buffer_size       16k;
proxy_buffers           8 16k;
proxy_busy_buffers_size 32k;
```

### Publish the admin console on its own hostname

`docker/admin.blackwall.cx.nginx.conf` is a working nginx vhost that maps
`admin.example.com/foo` onto Blackwall's `/admin/foo`. Adapt the
`server_name`, certificate paths and upstream port.

It also needs the new hostname on the WebAuthn origin allow-list, or admin
sign-in fails with `origin_mismatch` — the browser reports its own origin,
not `app_url`:

```yaml
webauthn_extra_origins: "https://admin.example.com"
```

Existing passkeys keep working: they are scoped to `webauthn_rp_id`, which
the new hostname must sit under. See the reverse-proxy chapter of
`docs/MANUAL.md` for the full rationale and the caveats.

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
- `webauthn_extra_origins` holding an entry that is not a bare `https://host`
  sitting under `webauthn_rp_id`

Generate strong values with:

```bash
openssl rand -hex 32       # session_secret, csrf_secret, audit_export_signing_key
openssl rand -base64 32    # cryptbin_kek_base64
```

To enable project licence issuance, generate a separate Ed25519 PKCS#8 key and
mount it read-only. The application refuses loose permissions and never stores
the private key in MySQL:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out /run/secrets/blackwall_licence_ed25519.pem
chmod 0600 /run/secrets/blackwall_licence_ed25519.pem
```

Set `licence_signing_key_file` to that path. Leave it blank when the instance
must verify and revoke existing licences without issuing new ones. See the
[complete verification and key-rotation guide](docs/licensing/VERIFYING_LICENCES.md).

Renewal email is independently optional. It uses a duplicate-safe MySQL queue,
the active designated organisation administrator, and mandatory encrypted SMTP.
See the [renewal reminder operations guide](docs/licensing/RENEWAL_REMINDERS.md)
for configuration, recipient rules, retries, privacy, and monitoring.

## Schema migrations

On startup, the binary applies any pending migrations from
`internal/db/migrations.go`, tracked in a `schema_migrations` table.
The application assumes the established Blackwall base schema already exists;
this source tree does not include a fresh-install baseline SQL file. Restore
the correct baseline from an existing deployment or obtain the baseline for
your deployment before first start. An empty database will fail when the first
incremental migration refers to a base table such as `users` or `projects`.

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
| `GET /.well-known/blackwall-licence-keys.json` | Project licence public-key registry |
| `POST /licences/v1/verify`              | Authoritative licence and revocation check |
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
- Project licences use a dedicated Ed25519 key with a key-derived identifier.
  Online validation verifies the exact signed bytes against the database,
  rejects revoked/expired/hostname-mismatched licences and disabled projects,
  and refuses keys marked compromised. Exact hostnames are used instead of
  ambiguous wildcards. Private signing material is file-only and must be mode
  0600 or stricter.
