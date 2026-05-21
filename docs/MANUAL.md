# Blackwall User Manual

A complete reference and operations manual for the Blackwall identity platform. Covers concepts, day-to-day administration, OAuth 2.1 / OpenID Connect integration patterns for downstream websites and applications, enterprise federation (SAML and SCIM), automation, and operational practice.

This manual is written in British English. Spec-prescribed identifiers such as `authorization_code`, `authorize_endpoint`, and HTTP header names retain their original spelling.

---

## Table of Contents

**Part I — Introduction and Concepts**
- Chapter 1: What is Blackwall?
- Chapter 2: Architecture at a Glance
- Chapter 3: The Identity Model
- Chapter 4: Authentication Posture
- Chapter 5: The Authorisation Model

**Part II — Getting Started**
- Chapter 1: System Requirements
- Chapter 2: Installing Blackwall
- Chapter 3: Bootstrapping the First Administrator
- Chapter 4: Verifying Your Installation

**Part III — Administering the Platform**
- Chapter 1: The Admin Console
- Chapter 2: Managing Organisations
- Chapter 3: Managing Projects
- Chapter 4: Privilege Levels and Assignments
- Chapter 5: Users, Enrolment, and Authenticators
- Chapter 6: The Approval Workflow
- Chapter 7: Per-Project Feature Flags
- Chapter 8: Branding and Custom Domains

**Part IV — OAuth 2.1 and OpenID Connect**
- Chapter 1: Concepts and Terminology
- Chapter 2: Registering an OAuth Client
- Chapter 3: The Authorisation Code Flow with PKCE
- Chapter 4: Tokens — Lifecycle and Verification
- Chapter 5: The Userinfo Endpoint
- Chapter 6: Custom Claims and Provenance
- Chapter 7: Token Revocation and Introspection
- Chapter 8: The Authentication Sandbox

**Part V — Integrating Blackwall into Your Website**
- Chapter 1: Choosing an Integration Pattern
- Chapter 2: Server-Side Web Application (Authorisation Code + PKCE)
- Chapter 3: Single-Page Application (Public Client + PKCE)
- Chapter 4: Backend-for-Frontend Pattern
- Chapter 5: Worked Example — Node.js with Express
- Chapter 6: Worked Example — Python with Flask
- Chapter 7: Worked Example — PHP
- Chapter 8: Worked Example — Go
- Chapter 9: Worked Example — Single-Page App (Vanilla JavaScript)
- Chapter 10: Logout and Session Termination
- Chapter 11: Common Pitfalls and Debugging

**Part VI — Enterprise Federation**
- Chapter 1: The SAML 2.0 Identity Provider
- Chapter 2: SCIM 2.0 User Provisioning
- Chapter 3: Webhooks for Event-Driven Integration

**Part VII — Operations**
- Chapter 1: Server-Backed Sessions
- Chapter 2: The Audit Log
- Chapter 3: Tamper-Evident Chain Checkpoints
- Chapter 4: Metrics and Observability
- Chapter 5: Maintenance Jobs
- Chapter 6: Backup and Disaster Recovery
- Chapter 7: KMS-Pluggable Signing Keys
- Chapter 8: Troubleshooting

**Part VIII — Automation and Infrastructure-as-Code**
- Chapter 1: The Admin JSON API
- Chapter 2: Bearer Token Authentication
- Chapter 3: The Terraform Provider
- Chapter 4: CI/CD Patterns

**Part IX — OIDC Conformance and Standards Posture**
- Chapter 1: Specification Compliance Today
- Chapter 2: Known Gaps
- Chapter 3: Running the Conformance Suite
- Chapter 4: The Path to Certification

**Part X — Reference**
- Chapter 1: Configuration Reference
- Chapter 2: Endpoint Index
- Chapter 3: Capability Matrix
- Chapter 4: Audit Event Catalogue
- Chapter 5: Glossary

---

# Part I — Introduction and Concepts

## Chapter 1: What is Blackwall?

Blackwall is an OAuth 2.1 and OpenID Connect authentication service designed for organisations that need a single, auditable, passwordless identity surface for both staff and external integrations. It signs ID tokens with RS256, presents a JWKS endpoint, supports the standard authorisation code flow with mandatory PKCE, and authenticates every user with WebAuthn (passkeys). Passwords are never used and cannot be enabled.

What you can do with Blackwall:

- Define **organisations**, each with their own admin user and project portfolio.
- Run **projects** with bespoke privilege ladders and per-user assignments.
- Issue and revoke **OAuth clients** for downstream applications.
- Enrol users with one-time **WebAuthn credentials**.
- Apply **custom OIDC claims** at four merge layers (organisation, project, user, user × project).
- Act as a **SAML 2.0 Identity Provider** for legacy applications that cannot speak OIDC.
- Receive **SCIM 2.0** provisioning calls from upstream HRIS systems (Workday, Okta, Entra ID).
- Drive everything declaratively via a **JSON Admin API** or **Terraform provider**.
- Track everything through an integrity-chained **audit log** with signed exports.

Blackwall is a single statically-linked Go binary backed by MySQL. There is no microservice layout, no daemon mesh, and no scheduler service — background work runs in goroutines inside the same process as the HTTP server.

## Chapter 2: Architecture at a Glance

Blackwall is one process. It owns:

- An HTTP server on a port you configure (default 8080) that serves the admin console, the OAuth endpoints, the SAML endpoints, the SCIM endpoints, the JSON Admin API, and the user portal.
- A persistent connection pool to MySQL where all durable state lives.
- A goroutine-based maintenance loop that prunes expired material on a schedule.
- A goroutine-based webhook dispatcher that delivers outbound events to registered receivers with exponential backoff.
- An in-process JWT manager that signs access and ID tokens with an RSA private key stored in the database (or, optionally, an external KMS).

The deployment surface is therefore small: one binary, one database, optional Redis or external KMS if you wish to scale or harden further. Customer-facing TLS terminates at a reverse proxy you provide (nginx, Caddy, an ingress controller).

```
┌───────────────────────────────┐
│       Reverse proxy (TLS)     │
└──────────────┬────────────────┘
               │ HTTP
       ┌───────▼────────┐
       │   Blackwall    │  one Go binary, all roles
       └───┬───────┬────┘
           │       │
   MySQL ──┘       └── optional KMS / Vault
```

## Chapter 3: The Identity Model

Blackwall organises identities into a three-level hierarchy:

1. **Organisation** — the tenant boundary. Each organisation has its own users, projects, branding, custom domains, and default claim set. Two organisations cannot see each other's data unless an actor is a super-admin.
2. **Project** — the unit of OAuth client ownership and per-user access. A project lives inside one organisation, holds its own privilege ladder, and has its own set of OAuth clients, claim defaults, webhooks, and SAML service providers.
3. **User** — a person who can authenticate. A user belongs to one organisation but may be assigned to many projects within that organisation, each at a different privilege level.

A user without a project assignment can still sign into the portal but cannot complete an OAuth flow against any client.

## Chapter 4: Authentication Posture

Blackwall authenticates users exclusively with **WebAuthn**. Specifically:

- Every user registers one or more passkeys (platform authenticator, security key, or a synced passkey provider).
- Each authentication assertion requires both the User Present (UP) and User Verification (UV) flags. PIN-less or touch-less authenticators are rejected.
- Sign-counter regression is treated as a cloned-credential indicator and the assertion is refused.
- Passwords cannot be enabled.

The first user — the bootstrap super-administrator — is created at install time with a one-time enrolment link. All subsequent users follow the same enrolment process.

## Chapter 5: The Authorisation Model

Blackwall's authorisation model has three independent layers.

### Admin role

Every admin user holds one of three roles. Each role grants a fixed set of named capabilities.

| Role | Headline |
|---|---|
| `super_admin` | Unrestricted scope, every capability, including direct status changes and credential deletions. |
| `operator` | Day-to-day administration scoped to organisations they own. Most mutations route through approvals. |
| `auditor` | Read-only: audit log, dashboard, scope debugger, error-trace decoder, documentation. |

### Scope

For non-super-admins, scope is computed per-request from organisation memberships:

- If the user has the `super_admin` role they see everything.
- Otherwise, scope is the union of organisations where the user is the `admin_user_id`, plus all projects belonging to those organisations.

Scope is enforced at every list query and every per-resource detail or update handler. An out-of-scope URL returns HTTP 403, not 404, so URL guessing is a deliberate signal in the audit log.

### Approval gates

Capabilities ending in `_direct` let the actor mutate immediately. Without the matching `_direct` capability, the same mutation becomes an approval request:

- User status changes
- WebAuthn credential deletions
- Project name and status changes
- OAuth client settings and status changes
- Privilege-level deletions
- All assignment mutations

The full request → review → decision journey is end-to-end audited.

---

# Part II — Getting Started

## Chapter 1: System Requirements

Blackwall has minimal infrastructure requirements:

- **Operating system** — any 64-bit Linux distribution. Tested against Ubuntu 22.04 and 24.04.
- **Database** — MySQL 8.0 or compatible. The default `utf8mb4_unicode_ci` collation is used throughout.
- **Memory** — 256 MiB resident set size is plenty for moderate loads. Single-tenant deployments routinely use less.
- **TLS termination** — Blackwall serves plain HTTP. Put it behind nginx, Caddy, an AWS ALB, or any TLS-terminating reverse proxy.
- **Browser support for WebAuthn** — current Chrome, Firefox, Safari, and Edge. The user portal will refuse to function on browsers without WebAuthn support.

## Chapter 2: Installing Blackwall

### Step 1 — provision the database

Create an empty MySQL database and a dedicated user that owns it.

```sql
CREATE DATABASE blackwall CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'blackwall'@'%' IDENTIFIED BY 'long-random-string-here';
GRANT ALL PRIVILEGES ON blackwall.* TO 'blackwall'@'%';
FLUSH PRIVILEGES;
```

Blackwall will create every table it needs on first start. The base schema and the forward-only migrations are both applied automatically.

### Step 2 — install the binary

Either build from source:

```bash
go install github.com/andydixon/blackwall/cmd/blackwall@latest
```

…or fetch a release tarball and place the `blackwall` binary on the host. The binary is statically linked; no runtime dependencies beyond `libc`.

### Step 3 — generate secrets

Blackwall validates secrets at boot and refuses to start with weak material.

```bash
openssl rand -hex 32  # session_secret
openssl rand -hex 32  # csrf_secret — must differ from session_secret
openssl rand -base64 32  # cryptbin_kek_base64 (if you intend to use CryptBin)
openssl rand -hex 32  # error_trace_key (optional; falls back to csrf_secret)
```

### Step 4 — write the configuration file

Create `/etc/blackwall/config.yaml`:

```yaml
app_url: "https://auth.example.com"
db_host: "127.0.0.1"
db_port: "3306"
db_name: "blackwall"
db_user: "blackwall"
db_pass: "long-random-string-here"

session_secret: "your-64-character-hex-string-1"
csrf_secret: "your-64-character-hex-string-2"

server_addr: ":8080"

rate_limit_enabled: true
audit_retention_days: 180

# Optional: tighten the bootstrap path. Once the first admin exists this
# value matters less; before then anyone reaching /bootstrap can claim the
# super-admin role, so restrict at the proxy layer.
trust_proxy: true
trusted_proxies: "127.0.0.1, 10.0.0.0/8"
```

Every key in the configuration file can also be supplied via an environment variable in `SCREAMING_SNAKE_CASE` (for example `APP_URL`, `DB_PASS`, `SESSION_SECRET`).

### Step 5 — run the binary

```bash
/usr/local/bin/blackwall --config /etc/blackwall/config.yaml
```

On first start you will see `[migrate] applying 1: …` lines as Blackwall creates its tables. After migrations complete the server begins serving on the configured address.

### Step 6 — install as a systemd unit

```ini
# /etc/systemd/system/blackwall.service
[Unit]
Description=Blackwall identity service
After=network.target mysql.service

[Service]
Type=simple
ExecStart=/usr/local/bin/blackwall --config /etc/blackwall/config.yaml
Restart=on-failure
RestartSec=5
User=blackwall
Group=blackwall

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now blackwall
sudo journalctl -u blackwall -f
```

### Step 7 — terminate TLS at your reverse proxy

A minimal nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;
    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Chapter 3: Bootstrapping the First Administrator

The first time Blackwall starts with an empty database it exposes a bootstrap flow at `/bootstrap`. Anyone who reaches that page can claim the super-administrator account, so restrict access at the proxy layer until you have completed the bootstrap.

**Step 1.** Browse to `https://auth.example.com/bootstrap`. Choose a display label (typically your email) and submit.

**Step 2.** Blackwall generates a one-time enrolment URL containing a 32-byte token. **Save this URL** — it expires after 24 hours and cannot be regenerated for the bootstrap user.

**Step 3.** Open the enrolment URL in a WebAuthn-capable browser. Register your authenticator when prompted. Blackwall will refuse non-resident-key authenticators that lack User Verification.

**Step 4.** Sign in at `/admin/login` with your new passkey. You now hold the `super_admin` role with unrestricted scope.

**Step 5.** Close the `/bootstrap` route at the proxy layer (`location = /bootstrap { return 404; }`). The endpoint will refuse to create a second bootstrap user once one exists, but defence in depth is cheap.

## Chapter 4: Verifying Your Installation

Run through the following safety checks before exposing the service to real users.

| Check | How |
|---|---|
| Audit chain is being written | Open `/admin/audit`. Each row should carry a non-empty `chain_hash`. Empty hashes indicate database write failures. |
| HSTS is being emitted | `curl -sI https://auth.example.com/` and look for `Strict-Transport-Security`. |
| Rate limiting is on | `for i in $(seq 1 200); do curl -s -o /dev/null https://auth.example.com/oauth/authorize; done` should start returning HTTP 429 within a few seconds. |
| Maintenance jobs run cleanly | Visit `/admin/maintenance` and click **Run now**. All jobs should land at `success`. |
| The OIDC discovery doc is well-formed | `curl -s https://auth.example.com/.well-known/openid-configuration | jq` should return a populated JSON document. |
| JWKS is reachable | `curl -s https://auth.example.com/oauth/jwks | jq '.keys | length'` should return at least 1. |
| Backup of the MySQL database is scheduled | Confirm with your infrastructure team. The JWT signing keys live in the database. |

---

# Part III — Administering the Platform

## Chapter 1: The Admin Console

The admin console lives at `/admin`. The top navigation bar shows the surfaces the current admin role grants access to:

- **Dashboard** — at-a-glance counts, approval SLA indicators, recent activity.
- **Users** — user lifecycle and credential management.
- **Projects** — project lifecycle, OAuth clients, claim defaults, webhooks, SAML.
- **Audit** — the audit log with filters and CSV export.
- **Approvals** — pending mutations awaiting decision.
- **Roles** — admin role assignments (super-admin only).
- **Orgs** — organisations and branding (super-admin only).
- **CryptBin** — encrypted item management (super-admin only).
- **Maintenance** — background jobs and last-run history (super-admin only).
- **Chain** — audit chain checkpoints (super-admin only).
- **API tokens** — bearer tokens for the JSON Admin API (super-admin only).
- **Errors** — server error trace decoder (super-admin and auditor).
- **Scope** — debug your own scope (anyone).
- **Docs** — the in-app documentation (anyone).

Every page is protected by CSRF tokens. Mutations that arrive without a valid CSRF token are rejected with an audit log entry.

## Chapter 2: Managing Organisations

Organisations are the tenant boundary. Use them to keep one customer's data away from another's, to apply distinct branding, and to scope admin role assignments.

### Creating an organisation

1. Open `/admin/organisations`.
2. Click **Create organisation**.
3. Provide a name and a slug. The slug must be unique and is used in URL paths.
4. Choose the user who will be the organisation's administrator. This user gains scope over the new organisation when they sign in.

### Editing an organisation

The detail page at `/admin/organisations/{uuid}` carries six cards:

- **Counts** — users and projects.
- **Settings** — name and status (super-admin only).
- **Switch administrator** — transfer ownership to a different user.
- **Projects** and **Users** — quick listings.
- **Branding and login experience** — see Chapter 8 of this part.
- **Custom domains** — see Chapter 8 of this part.
- **Default OIDC claims** — see Part IV, Chapter 6.

### Disabling an organisation

Set the status to `disabled` from the settings card. Disabled organisations cannot mint new tokens; existing tokens remain valid until their natural expiry. To force immediate logout of every user in the organisation, revoke their sessions individually (see Part VII, Chapter 1).

## Chapter 3: Managing Projects

Projects sit one level below organisations. Each project has its own privilege ladder, OAuth client list, claim defaults, and feature flags.

### Creating a project

1. Open `/admin/projects/create`.
2. Choose the parent organisation from the dropdown. Only organisations in your scope appear.
3. Provide the project name.
4. Submit. Blackwall creates the project, seeds the default privilege ladder, and enables the modern feature defaults (webhooks, DB-backed sessions, custom branding on) for newly created projects.

### The project detail page

`/admin/projects/{uuid}` is the centre of project administration. From here you can:

- View the OAuth client count, assignment count, and privilege count.
- Open the **Auth sandbox** to preview userinfo responses (Part IV, Chapter 8).
- Open the **Webhooks** page (Part VI, Chapter 3).
- Open the **SAML** SP registry (Part VI, Chapter 1).
- Edit settings (name, status).
- Adjust feature flags (Chapter 7 of this part).
- Manage **Default OIDC claims** (Part IV, Chapter 6).

### Disabling a project

Set the status to `disabled` on the settings card. OAuth flows against any client in the project will fail with `invalid_request`. Existing tokens remain valid until they expire.

## Chapter 4: Privilege Levels and Assignments

Privilege levels are project-local. Each project ships with five default rungs:

| Level | Default name | Convention |
|---|---|---|
| 1 | Owner | Project lifecycle decisions. |
| 2 | Administrator | Full operations within the project. |
| 3 | Editor | Routine writes. |
| 4 | Member | Read with limited write. |
| 5 | Viewer | Read-only. |

**Lower numbers always carry more privilege.** Rename or add rungs as needed but keep the ordering invariant.

### Creating a privilege level

1. Open `/admin/projects/{uuid}/privileges`.
2. Click **Create level**.
3. Provide a numeric level, a name, and an optional description.

### Assigning a user to a project

1. Open `/admin/projects/{uuid}/assignments`.
2. Click **Create assignment**.
3. Select a user from the picker.
4. Select a privilege level.

Operators do not hold `assignment_mutations_direct` by default, so creating, updating, or removing assignments enqueues an approval request that a super-admin (or another operator with that capability) must decide.

### How privilege flows into tokens

- **JWT access tokens** carry `privilege_level` and `privilege_name` claims.
- **Opaque access tokens** carry the same fields in the database row; `/oauth/introspect` exposes them.

Downstream applications should authorise their own actions on the basis of these claims rather than blanket trust.

## Chapter 5: Users, Enrolment, and Authenticators

Users in Blackwall have no passwords. They authenticate exclusively with WebAuthn and are created in two stages: profile first, then a one-time enrolment link the user follows to register their first credential.

### Creating a user

1. Open `/admin/users/create`.
2. Provide:
   - **Display label** — usually the user's email address. This appears in tokens as `preferred_username` and `name` when the `profile` scope is requested.
   - **Organisation** — the user's home organisation.
   - **Status** — `active` (default), `inactive`, or `suspended`.
3. Submit. Blackwall generates a 32-byte enrolment token valid for 24 hours.

### Sending the enrolment link

The detail page at `/admin/users/{uuid}` shows the one-time enrolment URL after creation. Send it to the user out-of-band — email, Signal, in person. The token expires in 24 hours; after that you must regenerate.

### The enrolment experience

When the user opens the enrolment URL:

1. Blackwall serves a page that asks the browser to register a WebAuthn credential.
2. The browser walks the user through their authenticator (Touch ID, Windows Hello, a hardware key, a synced passkey).
3. Once registered, Blackwall stores the public key plus the credential ID. The private key never leaves the user's authenticator.
4. The user is redirected to `/portal/login` and immediately tested by signing in.

### When a user loses their authenticator

1. Open the user's detail page.
2. Delete the lost credential. Operators trigger an approval; super-admins delete directly.
3. Generate a fresh enrolment link from the same page.
4. Send the link out-of-band.
5. The user registers a replacement and is back in.

### Status meanings

- `active` — can sign in, holds tokens, appears in the portal.
- `inactive` — cannot sign in; existing tokens still work until they expire.
- `suspended` — cannot sign in; existing tokens are rejected at every validation point.

To force immediate logout for any status change, revoke the user's sessions explicitly (Part VII, Chapter 1).

### Removing access permanently

Set the user to `suspended` and delete every credential. The user record itself is preserved so audit history remains attributable. Hard-deleting a user is only available through manual SQL — by design, no admin button does that.

## Chapter 6: The Approval Workflow

The approval workflow is a deliberate friction layer for sensitive admin actions. When an actor without the matching `_direct` capability attempts a mutation, Blackwall persists an approval request instead of executing the change.

### Lifecycle of a request

1. Operator submits a mutation through a normal admin form.
2. Blackwall stores an `approval_requests` row with the full proposed change in `payload_json`, status `pending`.
3. An actor with `decide_approvals` reviews the request at `/admin/approvals`.
4. The decision updates the row and logs `admin.approval.decision.approved` or `admin.approval.decision.denied`.
5. **The original mutation must then be re-applied** by an actor with the corresponding `_direct` capability — approvals do not auto-apply changes.

### Cancellation

The original requester can cancel their own pending request from the approvals page. Cancellation is logged as `admin.approval.cancelled`.

### SLA monitoring

The dashboard surfaces:

- Today / 7-day / 30-day decision counts per status.
- Decision latency: median and P95 in seconds.
- Pending requests older than the warning threshold (`admin_approval_pending_warning_days`, default 3).

### Decision notes

When rejecting, fill in the short `failure_reason` field — it appears in the requester's view and helps operators self-serve fixes. Long-form context goes in the `note` field, which is visible to anyone reviewing the request.

## Chapter 7: Per-Project Feature Flags

Each project carries an independent set of feature toggles. Newly created projects start with the modern defaults turned **on**; projects that existed before the migration that introduced the flags start with everything **off**, so upgrading Blackwall never silently changes behaviour for an in-flight tenant.

### Where to edit

Open `/admin/projects/{uuid}` → **Feature flags** card. Requires `manage_projects`.

### The flags

| Flag | Effect |
|---|---|
| `webhooks_enabled` | Gates the outbound webhook dispatcher. Endpoints can be registered while off; nothing is delivered until on. |
| `db_sessions_enabled` | Records each authenticated session in `user_sessions` so it can be revoked server-side. |
| `max_concurrent_sessions` | When greater than zero and DB sessions are on, caps a user to N parallel sessions across this project. A login exceeding N revokes the oldest session first. Zero means unbounded. |
| `custom_branding_enabled` | Pulls the organisation's branding overlay onto login screens served for this project. |
| `step_up_required` | Reserved for the upcoming step-up auth surface (forces a fresh WebAuthn touch for high-impact actions). Off by default. |

## Chapter 8: Branding and Custom Domains

Per-organisation branding lets the login surface carry the customer's logo, colour, and a supporting message. Custom domains let the login URL itself live on the customer's own hostname.

### Branding fields

Open `/admin/organisations/{uuid}` and find the **Branding and login experience** card:

| Field | Notes |
|---|---|
| Logo URL | Absolute HTTPS URL. Host externally (S3, CDN); Blackwall does not host uploads. |
| Primary colour | `#RRGGBB` hex. Applied to primary buttons and the login card's accent line. |
| Support email | Rendered as a help link on the login card. |
| Login message | Up to 2 KiB of plain text shown above the WebAuthn prompt. |

Branding is only applied to projects whose `custom_branding_enabled` feature flag is on. Existing organisations without any branding configured continue to render the platform default UI.

### Custom domains

Mapping `login.customer.com → Blackwall` is a two-step process:

1. **DNS and TLS** — the customer (or operator) configures DNS to point at Blackwall and provisions a TLS certificate for the hostname. Blackwall does not provision certificates itself.
2. **Map** — in the **Custom domains** card on the org detail page, add the hostname. It starts unverified. Click **Verify** once DNS resolution is confirmed.

Once verified, inbound requests with that `Host` header automatically pick up the organisation's branding overlay. The OIDC issuer URL is unchanged — only the login UI is rebranded.

If a request arrives on a host that does not match any verified custom domain, the platform default branding is used.

---

# Part IV — OAuth 2.1 and OpenID Connect

## Chapter 1: Concepts and Terminology

Before configuring an OAuth client, ground yourself in the terminology.

| Term | Definition |
|---|---|
| Identity Provider (IdP) | The service that authenticates the user. Blackwall is the IdP. |
| Service Provider / Relying Party / Client | The downstream application that wants to know who the user is. Your website is the client. |
| Authorisation Code Flow | The OAuth 2.1 flow where the user is redirected to the IdP, signs in, and is sent back with a one-time code that the client exchanges for tokens. |
| PKCE | Proof Key for Code Exchange (RFC 7636). A code-verifier / code-challenge pair that prevents an interceptor stealing the authorisation code. Mandatory in Blackwall. |
| Access Token | A short-lived token the client sends to APIs to prove the user authenticated. JWT (default) or opaque. |
| ID Token | A signed JWT that asserts who the user is. Returned alongside the access token when the `openid` scope is requested. |
| Refresh Token | A long-lived token used to obtain a new access token without re-authenticating the user. Single-use; rotated on every exchange. |
| Userinfo Endpoint | The HTTP endpoint that returns the user's profile claims given a valid access token. |
| Discovery Document | A JSON document at `/.well-known/openid-configuration` advertising every endpoint, supported feature, and signing key URL. |
| JWKS | JSON Web Key Set. The public keys used to verify token signatures, served at `/oauth/jwks`. |

## Chapter 2: Registering an OAuth Client

### Choosing the client type

| Type | When to choose | Token endpoint authentication |
|---|---|---|
| Confidential | Server-side applications that can keep a secret (Go services, PHP backends, server-side rendered apps). | `client_secret_basic` or `client_secret_post`. |
| Public | Browser SPAs and native mobile/desktop apps that cannot keep a secret. | `none` — security comes entirely from PKCE. |

### Registering the client (admin UI)

1. Open `/admin/projects/{uuid}/clients/create`.
2. Provide:
   - **Name** — a human-readable identifier.
   - **Client type** — confidential (default) or public.
   - **Redirect URIs** — one per line. Exact-match including scheme, host, port, and path. Wildcards are not supported.
   - **Grants** — `authorization_code` and `refresh_token` are the defaults. Refresh tokens are only issued when the client also requests the `offline_access` scope.
   - **Scopes** — a whitelist of scopes this client may ask for. Any subset the client requests at `/oauth/authorize` is allowed; anything outside the list is rejected.
   - **Access token type** — `jwt` (default) or `opaque`.
   - **Access token lifetime** — seconds; default 3600.
   - **Refresh token lifetime** — seconds; default 2592000 (30 days).
   - **OIDC enabled** — turn on to issue ID tokens when the `openid` scope is requested.
3. Submit.

Blackwall generates a `client_id` (a UUID) and, for confidential clients, a `client_secret`. **The client secret is shown exactly once on the next page.** Copy it then.

### Registering the client (Terraform)

```hcl
resource "blackwall_oauth_client" "marketing_site" {
  project_uuid           = "11111111-2222-3333-4444-555555555555"
  name                   = "Marketing site"
  client_type            = "confidential"
  redirect_uris          = ["https://example.com/auth/callback"]
  grants                 = ["authorization_code", "refresh_token"]
  scopes                 = ["openid", "profile", "email", "offline_access"]
  access_token_type      = "jwt"
  access_token_lifetime  = 3600
  refresh_token_lifetime = 2592000
  oidc_enabled           = true
}

output "client_id" {
  value = blackwall_oauth_client.marketing_site.id
}

output "client_secret" {
  value     = blackwall_oauth_client.marketing_site.client_secret
  sensitive = true
}
```

### Registering the client (JSON Admin API)

```bash
curl -sX POST https://auth.example.com/api/v1/projects/$PROJECT_UUID/oauth_clients \
  -H "Authorization: Bearer $BW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Marketing site",
    "client_type": "confidential",
    "redirect_uris": ["https://example.com/auth/callback"],
    "grants": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "oidc_enabled": true
  }'
```

The response carries `client_id` and `client_secret`. The secret is not returned on any subsequent call.

## Chapter 3: The Authorisation Code Flow with PKCE

This is the only flow Blackwall supports. Read this chapter once carefully — every integration in Part V is a worked example of the same flow.

### The actors

- **User** — sitting in front of a browser.
- **Client** — your website. Has a `client_id`, possibly a `client_secret`, and one or more registered `redirect_uri` values.
- **Blackwall** — the IdP at `https://auth.example.com`.

### The full flow

1. **Client generates a PKCE pair.** It generates a high-entropy random string of 43 to 128 characters (the `code_verifier`) and a SHA-256 hash of it that is base64url-encoded without padding (the `code_challenge`).
2. **Client generates a CSRF token (`state`) and, for OIDC, a `nonce`.** Both are random strings the client remembers across the redirect.
3. **Client redirects the user to `/oauth/authorize`** with the following query parameters:
   - `response_type=code`
   - `client_id=…`
   - `redirect_uri=…` (exact match against a registered URI)
   - `scope=openid profile email` (space-separated; `openid` is required for OIDC)
   - `state=…`
   - `nonce=…` (required when `openid` is in scope)
   - `code_challenge=…`
   - `code_challenge_method=S256`
4. **Blackwall authenticates the user.** If they are not signed in, the WebAuthn login screen is shown. Once authenticated, Blackwall checks that the user is assigned to the project the client belongs to. If not, the redirect carries `error=access_denied`.
5. **Blackwall redirects the user back to the `redirect_uri`** with two query parameters:
   - `code=…` (a one-time authorisation code, valid for 10 minutes)
   - `state=…` (echoed back unchanged)
6. **Client verifies that `state` matches the value it sent.** If not, treat as a CSRF attempt and abort.
7. **Client POSTs to `/oauth/token`** to exchange the code for tokens:
   ```
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded
   Authorization: Basic <base64(client_id:client_secret)>   # confidential only

   grant_type=authorization_code
   &code=…
   &redirect_uri=…           # must match the one used at step 3
   &code_verifier=…          # the plaintext PKCE verifier
   &client_id=…              # required for public clients
   ```
8. **Blackwall returns tokens:**
   ```json
   {
     "access_token": "eyJhbGciOiJSUzI1NiIs…",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "rt_…",   // only if offline_access scope requested
     "id_token": "eyJhbGciOiJSUzI1NiIs…",
     "scope": "openid profile email offline_access"
   }
   ```
9. **Client verifies the ID token** (see Chapter 4) and extracts user identity claims.
10. **Client uses the access token** to call APIs or `/oauth/userinfo`.

### Worked PKCE example

Using OpenSSL on the command line:

```bash
# Generate a 32-byte verifier, base64url without padding
code_verifier=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-')
echo "verifier: $code_verifier"

# Compute the challenge
code_challenge=$(printf '%s' "$code_verifier" | openssl dgst -binary -sha256 | openssl base64 -A | tr -d '=' | tr '/+' '_-')
echo "challenge: $code_challenge"
```

Send the challenge in the redirect; remember the verifier; send the verifier in the token exchange.

### Where things go wrong

| Symptom | Cause |
|---|---|
| `error=invalid_request&error_description=Invalid+redirect_uri` | The redirect URI you sent does not exactly match a registered one. Trailing slashes count. |
| `error=invalid_request&error_description=code_challenge+is+required` | You forgot PKCE. Mandatory in Blackwall. |
| `error=access_denied&error_description=User+not+authorized+for+this+project` | The signed-in user is not assigned to the client's project. |
| `error=invalid_grant` at the token endpoint | The code is expired, already used, or the `code_verifier` does not match. |
| `error=invalid_client` at the token endpoint | The client secret is wrong, or you used `Authorization: Basic` for a public client. |

## Chapter 4: Tokens — Lifecycle and Verification

### Token types

| Token | Purpose | Format | Lifetime |
|---|---|---|---|
| Access token (JWT) | Sent to APIs in the `Authorization: Bearer` header. | Signed RS256 JWT with `sub`, `aud`, `scope`, `project_id`, `privilege_level`, `privilege_name`. | `access_token_lifetime` on the client, default 1 hour. |
| Access token (opaque) | Sent to APIs in the `Authorization: Bearer` header. | Random base64url string. Validation requires a round-trip to `/oauth/introspect`. | Same. |
| ID Token | Identifies the user to the client; verified once at sign-in. | Signed RS256 JWT with `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`, `auth_time`, plus profile/email claims when those scopes are requested, plus any custom claims. | 1 hour. |
| Refresh token | Used at the token endpoint to obtain a fresh access token. | Random base64url string, stored hashed. Single-use. | `refresh_token_lifetime` on the client, default 30 days. |

### Verifying a JWT access token or ID token (client-side)

Every Blackwall-issued JWT can be verified using the public keys at the JWKS endpoint.

1. Parse the JWT header. Read the `kid` (key ID).
2. Fetch `https://auth.example.com/oauth/jwks`. Cache for at least 5 minutes.
3. Find the key whose `kid` matches the one in the token header.
4. Verify the signature using RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
5. Verify the claims:
   - `iss` equals your Blackwall issuer URL.
   - `aud` contains your `client_id`.
   - `exp` is in the future.
   - `nbf` is in the past (if present).
   - For ID tokens, `nonce` equals the value you sent at `/oauth/authorize`.
   - For ID tokens with an `at_hash` claim, recompute the hash and compare (see below).

Most languages have a library that handles this end-to-end. Examples appear throughout Part V.

### Computing `at_hash`

Per OIDC Core §3.1.3.6 with RS256:

1. Take the ASCII bytes of the access token.
2. SHA-256 hash them.
3. Take the leftmost 128 bits (16 bytes).
4. Base64url-encode without padding.

The result should equal the `at_hash` claim in the ID token. A mismatch means the token pair was tampered with.

### Refresh tokens and rotation

When the client requests `offline_access` scope, Blackwall issues a refresh token alongside the access token. To use it:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=refresh_token&refresh_token=rt_…
```

The response carries a **new** access token and a **new** refresh token. The old refresh token is immediately revoked. Re-using a revoked refresh token triggers token-family revocation: every active access and refresh token for that user/project/client triple is revoked. This is the OAuth 2.1 best-practice that defeats stolen refresh tokens.

## Chapter 5: The Userinfo Endpoint

`/oauth/userinfo` returns the user's profile information given a valid access token.

```
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

The response is JSON. Which claims appear depends on the scopes the client requested:

| Scope | Claims emitted |
|---|---|
| `openid` (required) | `sub` |
| `profile` | adds `name`, `preferred_username` |
| `email` | adds `email`, `email_verified` (when the user's display label is email-shaped) |

Custom OIDC claims (see next chapter) are merged into the response on top of the standard set. Standard fields cannot be overridden by custom claims.

The endpoint is rate-limited per IP (120 requests per minute by default). The access token must carry the `openid` scope; otherwise the call fails with `insufficient_scope`.

## Chapter 6: Custom Claims and Provenance

Blackwall supports four merge layers for custom OIDC claims. From broadest to narrowest, each later layer overrides earlier layers with the same key:

1. **Organisation defaults** — set on the organisation, applied to every user in the org.
2. **Project defaults** — set on the project, applied when the token is bound to that project.
3. **User-level** — set on the user, applied across every project the user signs into.
4. **User × project** — set on a (user, project) pair, applied only when the token is bound to that project. The narrowest layer wins over everything else.

### Where to set them

| Layer | Surface |
|---|---|
| Org defaults | **Default OIDC claims** card on `/admin/organisations/{uuid}`. |
| Project defaults | **Default OIDC claims** card on `/admin/projects/{uuid}`. |
| User-level | `/admin/users/{uuid}/claims`. |
| User × project | The per-project section on the same user claims page. |

### Key rules

- Keys must match `[a-z][a-z0-9_]{0,79}` — lowercase letter first, then lowercase, digits, or underscore.
- Reserved JWT and OIDC names are rejected at write time and at signing time: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `nonce`, `at_hash`, `c_hash`, `auth_time`, `acr`, `amr`, `azp`, `scope`, `client_id`, `token_type`, `expires_in`, `project_id`.
- Values are capped at 4 KiB.

### Value types

A value that parses as a JSON literal is emitted in the token with that type:

| You enter | Token sees |
|---|---|
| `Engineering` | string `"Engineering"` |
| `"Engineering"` | string `"Engineering"` |
| `42` | number `42` |
| `true` | boolean `true` |
| `["eng","ops"]` | array `["eng","ops"]` |
| `{"role":"lead"}` | object `{"role":"lead"}` |

### Worked example: Grafana with groups

You want every user signing into Grafana via Blackwall to receive a `groups` array so Grafana's group-mapping rules can grant the right role.

1. On the Grafana project's detail page, open the **Default OIDC claims** card.
2. Add `preferred_username` = `"team-grafana"`.
3. Add `groups` = `["editors","viewers"]`.
4. To override for a specific user, open `/admin/users/{uuid}/claims` and set their `groups` directly. The user-level value wins over the project default.

## Chapter 7: Token Revocation and Introspection

### Revoking a token

```
POST /oauth/revoke
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh_token>&token_type_hint=access_token
```

The endpoint always returns HTTP 200 — per RFC 7009, it must not leak whether the token existed.

### Introspecting a token

```
POST /oauth/introspect
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

token=<access_token>
```

Response when the token is valid:

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "abc-…",
  "username": "alice@example.com",
  "exp": 1700000000,
  "sub": "user-uuid",
  "iss": "https://auth.example.com",
  "token_type": "Bearer"
}
```

Response when invalid:

```json
{ "active": false }
```

Use introspection when:

- You issue opaque tokens and need their claims server-side.
- You issue JWT tokens but need real-time revocation visibility (the JWT might be valid by signature but already revoked).

## Chapter 8: The Authentication Sandbox

The sandbox at `/admin/projects/{uuid}/test` lets you preview the exact `/oauth/userinfo` response Blackwall would emit for any assigned user under that project, with a per-claim source breakdown showing which of the four layers produced each value.

### Using the sandbox

1. Open the project's detail page.
2. Click **Auth sandbox** in the top-right corner.
3. Choose an assigned user from the dropdown.
4. Tick the scopes you want to simulate (`openid` is required for any userinfo to be returned at all).
5. Click **Run preview**.

The result page shows two cards:

- **`/oauth/userinfo` response** — pretty-printed JSON of what a downstream OIDC client would receive.
- **Source of each claim** — every claim in the response with a coloured badge identifying its source (`standard`, `org default`, `project default`, `user-level`, `user × project`) and a short note explaining standard fields.

The sandbox is read-only and does not issue real tokens. It bypasses WebAuthn so you can quickly verify precedence without going through the full login flow.

---

# Part V — Integrating Blackwall into Your Website

This is the heart of the manual for application developers. Read Chapter 1 first to choose the right pattern; then the language-specific chapter (5–9) to copy-paste your way to a working integration.

## Chapter 1: Choosing an Integration Pattern

There are three viable patterns for integrating Blackwall into a web application. Pick on the basis of where your code runs.

### Pattern A — Server-Side Web Application

Use when:

- Your application has a server-side component (Express, Flask, PHP, Go HTTP server, ASP.NET).
- You want the simplest, most secure path.

The server holds the `client_secret`, performs the token exchange, sets a session cookie, and shows authenticated pages directly. The browser never sees the access token. Most legitimate websites should use this pattern.

### Pattern B — Single-Page Application

Use when:

- Your application is a pure browser SPA (React, Vue, Svelte) with no server-side component you control.
- The user's browser is the only place your code runs.

You cannot keep a client secret. Use a **public** client type with PKCE. Store the access token in memory only (not localStorage, not cookies) and request a new token when the user reloads. Send the access token in `Authorization: Bearer` to your APIs.

### Pattern C — Backend-for-Frontend (BFF)

Use when:

- You have an SPA frontend but you also control a backend (e.g. a thin Node or Go service in front of microservices).
- You want the SPA's simplicity but the security of a confidential client.

The backend acts as a confidential client. It holds the secret, exchanges the code, and exposes a session cookie to the SPA. APIs the SPA calls are proxied through the BFF, which attaches the access token on the SPA's behalf. This is widely considered the modern best practice.

### Comparison

| Property | Pattern A | Pattern B | Pattern C |
|---|---|---|---|
| Client type | Confidential | Public | Confidential |
| Stores client secret | Yes | No | Yes |
| Browser sees access token | No | Yes | No |
| Where session lives | HTTP-only cookie | Memory | HTTP-only cookie on BFF |
| Suitable for SPAs | Only with server-rendered pages | Yes | Yes |
| Refresh token usable | Yes | No (per OAuth 2.1) | Yes |

## Chapter 2: Server-Side Web Application (Authorisation Code + PKCE)

Conceptual walkthrough. Worked language-specific code follows in chapters 5–8.

### High-level architecture

```
Browser  ────►  Your website  ────►  Blackwall
   │              │      ▲              │
   │              │      └── tokens ────┘
   │              ▼
   │           Session
   │           cookie
   └───── secured pages
```

### Endpoint responsibilities

Your website needs three endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /auth/login` | Generate PKCE pair + state + nonce; stash them in the session; redirect to `/oauth/authorize`. |
| `GET /auth/callback` | Verify state; exchange code for tokens; verify ID token; create a local session; redirect to the post-login page. |
| `POST /auth/logout` | Destroy the local session; optionally revoke the access token; redirect home. |

### State and nonce handling

- **`state`** — a random string the client generates and stores in the session before redirecting. After the callback, the client checks that the returned `state` matches. Defeats CSRF on the redirect.
- **`nonce`** — a random string included in the authorisation request and echoed in the ID token. After exchange, the client checks that the ID token's `nonce` claim matches. Defeats token-injection attacks where an attacker tries to splice their authorisation response into the victim's session.

Both must be at least 16 random bytes. Both must be remembered for the duration of the redirect (typically by storing in the user's pre-auth cookie session).

### What to store after login

Once you have verified the ID token, your application should establish its own session. Store:

- The user's `sub` (UUID) — your primary key for the user.
- The user's display name (`name` or `preferred_username`).
- The user's email if available.
- Any custom claims your application needs to authorise actions (e.g. `groups`).
- The access token, **if** you intend to call other APIs on the user's behalf. Otherwise discard it.
- The refresh token, **if** you requested `offline_access` and want long-lived sessions without re-authentication.

Do not store access or refresh tokens in places JavaScript can read.

## Chapter 3: Single-Page Application (Public Client + PKCE)

Use this only when you have no server-side component. The flow is the same as Pattern A but every step happens in the browser.

### Storage rules

- **Access token** — store in JavaScript memory only (a closure variable, or a service worker). When the user reloads the page, you lose it and must redirect for a fresh authorisation. This is correct.
- **Refresh tokens** — Blackwall issues these only when `offline_access` is requested. For SPAs, prefer to **not** request `offline_access` and instead use silent re-authentication via `prompt=none` to obtain new tokens when the access token expires. Refresh tokens in browser storage are an attractive target for XSS.
- **State and PKCE verifier** — store in `sessionStorage` for the duration of the redirect. They are not security-critical to hide; they only need to survive the redirect.

### Silent re-authentication

When the access token is about to expire:

1. Open a hidden iframe pointing at `/oauth/authorize?prompt=none&...`.
2. Blackwall returns the new code if the user is still signed into the portal, or `error=login_required` if not.
3. Exchange the code as normal.

### CORS

The `/oauth/token` endpoint accepts cross-origin requests from registered redirect URIs. No additional CORS configuration is required on Blackwall's side; your SPA's domain just needs to be listed as a redirect URI on the public client.

## Chapter 4: Backend-for-Frontend Pattern

The BFF pattern keeps the SPA's user experience but moves all OAuth handling to the server.

### Architecture

```
Browser SPA  ──►  Your BFF (confidential client) ──►  Blackwall
       │            │
       │       cookie session
       │            │
       └─►  APIs (called through BFF)
                    │
                    └─► attaches Bearer token
```

### What the BFF must do

1. Expose `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout` exactly as in Pattern A.
2. Maintain an HTTP-only, Secure, SameSite=Lax cookie session per user.
3. Expose `GET /api/me` so the SPA can ask "am I logged in, and as whom?".
4. Proxy every API call from the SPA: the SPA calls `/api/something`, the BFF resolves the user from the cookie, attaches the access token, and forwards to the upstream API.
5. Refresh tokens silently when they expire.

The SPA never knows the access token exists. From its perspective, authentication is entirely cookie-based, the way it was in 2008.

## Chapter 5: Worked Example — Node.js with Express

### Project setup

```bash
mkdir blackwall-demo && cd blackwall-demo
npm init -y
npm install express express-session openid-client@5
```

### Environment

```bash
export BW_ISSUER="https://auth.example.com"
export BW_CLIENT_ID="11111111-2222-3333-4444-555555555555"
export BW_CLIENT_SECRET="…"
export BW_REDIRECT_URI="https://app.example.com/auth/callback"
export SESSION_SECRET="$(openssl rand -hex 32)"
```

### Application

```javascript
// server.js
import express from 'express';
import session from 'express-session';
import { Issuer, generators } from 'openid-client';

const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax' },
}));

const issuer = await Issuer.discover(process.env.BW_ISSUER);
const client = new issuer.Client({
  client_id: process.env.BW_CLIENT_ID,
  client_secret: process.env.BW_CLIENT_SECRET,
  redirect_uris: [process.env.BW_REDIRECT_URI],
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic',
});

// Step 1 — redirect to Blackwall
app.get('/auth/login', (req, res) => {
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  const state = generators.state();
  const nonce = generators.nonce();

  req.session.code_verifier = code_verifier;
  req.session.state = state;
  req.session.nonce = nonce;

  const url = client.authorizationUrl({
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256',
  });
  res.redirect(url);
});

// Step 2 — handle the callback
app.get('/auth/callback', async (req, res, next) => {
  try {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
      process.env.BW_REDIRECT_URI,
      params,
      {
        code_verifier: req.session.code_verifier,
        state: req.session.state,
        nonce: req.session.nonce,
      },
    );
    const claims = tokenSet.claims();
    req.session.user = {
      sub: claims.sub,
      email: claims.email,
      name: claims.name,
      groups: claims.groups,
    };
    req.session.access_token = tokenSet.access_token;
    delete req.session.code_verifier;
    delete req.session.state;
    delete req.session.nonce;
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

// Step 3 — log out
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Protected page
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.send('<a href="/auth/login">Sign in</a>');
  }
  res.send(`<p>Hello, ${req.session.user.name}</p>
            <form method="POST" action="/auth/logout">
              <button>Sign out</button>
            </form>`);
});

app.listen(3000);
```

### What this does

- `openid-client` reads the discovery document automatically and configures itself.
- PKCE pair and state/nonce are generated per request and stored in the server-side session.
- Token exchange + ID token verification (signature, issuer, audience, expiry, nonce, at_hash) are handled by the library.
- The session cookie is HTTP-only and Secure; the browser never sees the tokens.

## Chapter 6: Worked Example — Python with Flask

### Project setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask Authlib
```

### Application

```python
# app.py
import os
from flask import Flask, redirect, session, url_for
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ['SESSION_SECRET']
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

oauth = OAuth(app)
oauth.register(
    name='blackwall',
    client_id=os.environ['BW_CLIENT_ID'],
    client_secret=os.environ['BW_CLIENT_SECRET'],
    server_metadata_url=f"{os.environ['BW_ISSUER']}/.well-known/openid-configuration",
    client_kwargs={
        'scope': 'openid profile email',
        'code_challenge_method': 'S256',
    },
)

@app.route('/auth/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return oauth.blackwall.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def callback():
    token = oauth.blackwall.authorize_access_token()
    user = token.get('userinfo')
    session['user'] = {
        'sub': user['sub'],
        'email': user.get('email'),
        'name': user.get('name'),
    }
    return redirect('/')

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/')
def home():
    user = session.get('user')
    if not user:
        return '<a href="/auth/login">Sign in</a>'
    return (f'<p>Hello, {user["name"]}</p>'
            '<form method="POST" action="/auth/logout">'
            '<button>Sign out</button></form>')
```

Authlib handles PKCE, state, nonce, the token exchange, and ID token verification automatically.

## Chapter 7: Worked Example — PHP

### Project setup

```bash
composer require league/oauth2-client
```

### Application

```php
<?php
// auth.php
session_start();
require __DIR__ . '/vendor/autoload.php';

$issuer = getenv('BW_ISSUER');
$clientId = getenv('BW_CLIENT_ID');
$clientSecret = getenv('BW_CLIENT_SECRET');
$redirectUri = getenv('BW_REDIRECT_URI');

function pkce_pair(): array {
    $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    return [$verifier, $challenge];
}

// Step 1 — redirect to Blackwall
if ($_SERVER['REQUEST_URI'] === '/auth/login') {
    [$verifier, $challenge] = pkce_pair();
    $state = bin2hex(random_bytes(16));
    $nonce = bin2hex(random_bytes(16));
    $_SESSION['pkce_verifier'] = $verifier;
    $_SESSION['oauth_state'] = $state;
    $_SESSION['oauth_nonce'] = $nonce;

    $url = $issuer . '/oauth/authorize?' . http_build_query([
        'response_type'         => 'code',
        'client_id'             => $clientId,
        'redirect_uri'          => $redirectUri,
        'scope'                 => 'openid profile email',
        'state'                 => $state,
        'nonce'                 => $nonce,
        'code_challenge'        => $challenge,
        'code_challenge_method' => 'S256',
    ]);
    header('Location: ' . $url);
    exit;
}

// Step 2 — handle the callback
if ($_SERVER['REQUEST_URI'] === '/auth/callback') {
    if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
        http_response_code(400);
        die('state mismatch');
    }

    $ch = curl_init($issuer . '/oauth/token');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Authorization: Basic ' . base64_encode("$clientId:$clientSecret")],
        CURLOPT_POSTFIELDS     => http_build_query([
            'grant_type'    => 'authorization_code',
            'code'          => $_GET['code'],
            'redirect_uri'  => $redirectUri,
            'code_verifier' => $_SESSION['pkce_verifier'],
        ]),
    ]);
    $resp = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http !== 200) {
        http_response_code(502);
        die('token exchange failed');
    }
    $tokens = json_decode($resp, true);

    // Fetch userinfo for simplicity. In production, verify the ID token
    // signature locally against /oauth/jwks and check the nonce.
    $ch = curl_init($issuer . '/oauth/userinfo');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $tokens['access_token']],
    ]);
    $user = json_decode(curl_exec($ch), true);
    curl_close($ch);

    $_SESSION['user'] = $user;
    unset($_SESSION['pkce_verifier'], $_SESSION['oauth_state'], $_SESSION['oauth_nonce']);
    header('Location: /');
    exit;
}
```

For production PHP code, prefer a library (`web-token/jwt-framework` or `firebase/php-jwt`) for ID token verification rather than the userinfo round-trip shown above.

## Chapter 8: Worked Example — Go

### Project setup

```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
```

### Application

```go
// main.go
package main

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"
    "os"

    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

var (
    provider *oidc.Provider
    config   oauth2.Config
    verifier *oidc.IDTokenVerifier
)

func init() {
    ctx := context.Background()
    var err error
    provider, err = oidc.NewProvider(ctx, os.Getenv("BW_ISSUER"))
    if err != nil {
        log.Fatal(err)
    }
    config = oauth2.Config{
        ClientID:     os.Getenv("BW_CLIENT_ID"),
        ClientSecret: os.Getenv("BW_CLIENT_SECRET"),
        RedirectURL:  os.Getenv("BW_REDIRECT_URI"),
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }
    verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})
}

func randStr(n int) string {
    b := make([]byte, n)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}

func login(w http.ResponseWriter, r *http.Request) {
    state := randStr(16)
    nonce := randStr(16)
    verifierStr := randStr(32)
    challenge := oauth2.S256ChallengeFromVerifier(verifierStr)

    http.SetCookie(w, &http.Cookie{Name: "state", Value: state, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/"})
    http.SetCookie(w, &http.Cookie{Name: "nonce", Value: nonce, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/"})
    http.SetCookie(w, &http.Cookie{Name: "verifier", Value: verifierStr, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/"})

    url := config.AuthCodeURL(state,
        oauth2.SetAuthURLParam("nonce", nonce),
        oauth2.SetAuthURLParam("code_challenge", challenge),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
    )
    http.Redirect(w, r, url, http.StatusFound)
}

func callback(w http.ResponseWriter, r *http.Request) {
    stateCookie, _ := r.Cookie("state")
    if r.URL.Query().Get("state") != stateCookie.Value {
        http.Error(w, "state mismatch", 400)
        return
    }
    verifierCookie, _ := r.Cookie("verifier")
    nonceCookie, _ := r.Cookie("nonce")

    token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"),
        oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value),
    )
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    rawIDToken, ok := token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "no id_token", 500)
        return
    }
    idToken, err := verifier.Verify(r.Context(), rawIDToken)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    if idToken.Nonce != nonceCookie.Value {
        http.Error(w, "nonce mismatch", 400)
        return
    }

    var claims struct {
        Sub    string   `json:"sub"`
        Email  string   `json:"email"`
        Name   string   `json:"name"`
        Groups []string `json:"groups"`
    }
    if err := idToken.Claims(&claims); err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    json.NewEncoder(w).Encode(claims)
}

func main() {
    http.HandleFunc("/auth/login", login)
    http.HandleFunc("/auth/callback", callback)
    log.Fatal(http.ListenAndServe(":3000", nil))
}
```

The `go-oidc` library handles JWKS fetching, signature verification, and standard claim validation. You still need to check `nonce` yourself because the library doesn't know what value you sent.

## Chapter 9: Worked Example — Single-Page App (Vanilla JavaScript)

### Configuration

Register a **public** OAuth client in Blackwall with:

- `redirect_uris` = `["https://app.example.com/auth/callback"]`
- `client_type` = `public`
- `grants` = `["authorization_code"]`
- `scopes` = `["openid", "profile", "email"]`

### Application

```html
<!-- index.html -->
<!DOCTYPE html>
<html>
<head><title>Blackwall SPA demo</title></head>
<body>
  <div id="app">Loading…</div>
  <script type="module" src="/app.js"></script>
</body>
</html>
```

```javascript
// app.js
const ISSUER     = "https://auth.example.com";
const CLIENT_ID  = "your-public-client-uuid";
const REDIRECT   = "https://app.example.com/auth/callback";
let   accessToken = null;

async function discovery() {
  if (!discovery.cache) {
    discovery.cache = await fetch(`${ISSUER}/.well-known/openid-configuration`).then(r => r.json());
  }
  return discovery.cache;
}

function base64url(arr) {
  return btoa(String.fromCharCode(...new Uint8Array(arr)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pkcePair() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const verifier = base64url(bytes);
  const challenge = base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  return { verifier, challenge };
}

async function login() {
  const { authorization_endpoint } = await discovery();
  const { verifier, challenge } = await pkcePair();
  const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("oauth_state", state);
  sessionStorage.setItem("oauth_nonce", nonce);
  const url = new URL(authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT);
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  location.assign(url.toString());
}

async function handleCallback() {
  const params = new URLSearchParams(location.search);
  if (params.get("state") !== sessionStorage.getItem("oauth_state")) {
    throw new Error("state mismatch");
  }
  const { token_endpoint } = await discovery();
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", params.get("code"));
  body.set("redirect_uri", REDIRECT);
  body.set("client_id", CLIENT_ID);
  body.set("code_verifier", sessionStorage.getItem("pkce_verifier"));
  const tokens = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  }).then(r => r.json());
  sessionStorage.removeItem("pkce_verifier");
  sessionStorage.removeItem("oauth_state");
  accessToken = tokens.access_token;
  // ID token verification omitted for brevity — use jose-browser-runtime
  // to verify nonce, signature, audience, issuer, and expiry in production.
  history.replaceState(null, "", "/");
  render();
}

async function render() {
  const app = document.getElementById("app");
  if (location.pathname === "/auth/callback") {
    await handleCallback();
    return;
  }
  if (!accessToken) {
    app.innerHTML = `<button id="login">Sign in</button>`;
    document.getElementById("login").onclick = login;
    return;
  }
  const { userinfo_endpoint } = await discovery();
  const user = await fetch(userinfo_endpoint, {
    headers: { "Authorization": `Bearer ${accessToken}` },
  }).then(r => r.json());
  app.innerHTML = `<p>Hello, ${user.name || user.sub}</p>
                   <button id="signout">Sign out</button>`;
  document.getElementById("signout").onclick = () => {
    accessToken = null;
    render();
  };
}

render();
```

**Important**: this example skips ID token signature verification for brevity. In production, use `jose-browser-runtime` to verify the `id_token` signature against the JWKS, confirm `nonce`, `aud`, `iss`, `exp`, and only then trust the user.

## Chapter 10: Logout and Session Termination

Blackwall does not yet expose an end-session endpoint for RP-initiated logout. Until it does, every integration handles logout locally:

### Local logout

1. Destroy the application's own session cookie.
2. Optionally revoke the access token at `/oauth/revoke` to invalidate it immediately.

### Full logout from Blackwall too

For an immediate full sign-out, a super-admin can revoke the user's Blackwall portal session from `/admin/users/{uuid}/sessions` (see Part VII, Chapter 1). End users cannot yet sign themselves out of Blackwall from a downstream RP; this is the most common missing piece our customers ask for and is on the roadmap.

### Backchannel logout

Not currently implemented. The webhook surface (Part VI, Chapter 3) is a reasonable substitute for now: register a webhook on `admin.session.revoke` and have your application destroy its local session in response.

## Chapter 11: Common Pitfalls and Debugging

| Symptom | Most likely cause |
|---|---|
| `redirect_uri_mismatch` | Trailing slash or scheme mismatch between what you registered and what you sent. |
| `invalid_grant` at token exchange | The authorisation code has been used already (codes are single-use) or has expired (10-minute window). |
| `invalid_request: code_challenge is required` | You forgot to send a PKCE pair. Mandatory in Blackwall. |
| ID token `nonce` does not match | You sent the wrong nonce, or your session was lost between authorize and callback (check cookie SameSite). |
| `access_denied: User not authorized for this project` | The user has a valid credential but is not assigned to the project. Assign them via `/admin/projects/{uuid}/assignments`. |
| `invalid_token` at userinfo | Token has expired, been revoked, or carries an audience that does not match any active client. Check the JWT's `exp` and `aud`. |
| `insufficient_scope` at userinfo | You requested userinfo without the `openid` scope. |
| Tokens verify locally but `/oauth/introspect` says `active: false` | The token was revoked. For real-time visibility, switch to opaque tokens or call introspect regularly. |
| Browser blocks the redirect | Pop-up blocker if you used `window.open`; or the `redirect_uri` is on a different effective top-level domain to the IdP and a strict SameSite policy ate the session. |
| `state mismatch` after callback | Your application's pre-auth session was lost (cookie expired, different domain, different browser tab). Use HTTP-only Secure cookies with SameSite=Lax. |

### Tracing what Blackwall thinks happened

Every OAuth-relevant event is logged. To trace a specific user's failed sign-in:

1. Note the approximate time and your IP.
2. Open `/admin/audit`.
3. Filter on `event_type` containing `oauth` and on your IP.
4. Look at `metadata_json` for the failure reason on `oauth.*.fail` rows.

### Using the auth sandbox during integration

The fastest way to confirm "what claims will my application actually see?" is the per-project sandbox at `/admin/projects/{uuid}/test`. Pick the user you intend to test as, pick your scopes, run the preview. The resulting JSON is byte-identical to what `/oauth/userinfo` would return in a real flow.

---

# Part VI — Enterprise Federation

## Chapter 1: The SAML 2.0 Identity Provider

Many enterprise SaaS applications cannot speak OIDC. Blackwall acts as a SAML 2.0 Identity Provider for these systems. The flow reuses the existing WebAuthn portal login so users never see a second authentication surface.

### Per-project SP registry

Each project has its own list of registered Service Providers, managed at `/admin/projects/{uuid}/saml`. Requires `view_projects` to see, `manage_projects` to register.

### IdP endpoints to give the SP

Once a project is configured, supply these to the SP-side configuration in the downstream application:

| Field | Value |
|---|---|
| Metadata URL | `https://auth.example.com/saml/projects/{uuid}/metadata` |
| SSO endpoint | `https://auth.example.com/saml/projects/{uuid}/sso` |
| Bindings | HTTP-Redirect and HTTP-POST (request); HTTP-POST (response) |
| Signature | RSA-SHA256 with exclusive XML canonicalisation; signs both Response and embedded Assertion |

### Registering an SP

1. Obtain the SP's **Entity ID** and **Assertion Consumer Service (ACS) URL** (sometimes called the "Consumer URL" or "Reply URL").
2. Open the project's **SAML** page and use the form at the bottom.
3. Choose a NameID format:
   - `emailAddress` (default) — most applications want this.
   - `persistent` — when the SP wants a stable opaque ID that does not change if the user's email changes.
   - `transient` / `unspecified` — rare.
4. Fill in the **Attribute map**. Each line is `saml_attr=source`. Sources can be:
   - `display_label` — the user's primary label (typically their email).
   - Any custom OIDC claim name — pulls from the merged claim store, so the four-layer claim system feeds straight into SAML attributes.
5. Optionally paste the SP's signing certificate PEM to enforce signed AuthnRequests. Most major SaaS apps do not sign theirs.

### The SP-initiated flow

1. Browser visits the SP. SP redirects to Blackwall's SSO endpoint with a `SAMLRequest`.
2. Blackwall parses the AuthnRequest, looks up the SP by Entity ID, and stashes the request ID and ACS URL in the user's session.
3. If not already signed in, the user is bounced through `/portal/login` for WebAuthn authentication and returned.
4. Blackwall mints a signed Response containing a signed Assertion, then renders an auto-submitting HTML form that POSTs the Response to the SP's ACS URL.

### Security properties

- The AuthnRequest's `AssertionConsumerServiceURL` (when present) must exactly match the registered ACS URL. This prevents an attacker from making us POST our signed assertion to their server.
- The `Audience` defaults to the SP's Entity ID, so the assertion cannot be replayed against a different SP.
- Subject confirmation has `NotOnOrAfter` of 5 minutes; Conditions has the same window.

### What is intentionally not supported

- Single Logout (SLO) — out of scope until a customer asks.
- IdP-initiated SSO — every modern SP supports SP-initiated, and the security model is cleaner.
- Encrypted assertions — TLS already protects in transit.
- HTTP-Artifact binding — vanishingly rare.

## Chapter 2: SCIM 2.0 User Provisioning

SCIM 2.0 (RFC 7643 + RFC 7644) is the standard upstream identity providers (Workday, Okta, Entra ID, Google Workspace, BambooHR, Rippling) use to push user-lifecycle changes into downstream applications. Blackwall exposes `/scim/v2/Users` so any of these can provision, update, and deprovision users without an operator copying them by hand.

### Base URL and authentication

| Item | Value |
|---|---|
| Base URL | `https://auth.example.com/scim/v2` |
| Auth | `Authorization: Bearer bw_admin_…` (Part VIII, Chapter 2) |
| Target project | `X-BlackWall-Project: <project-uuid>` header |

Every SCIM operation is scoped to one project; this is the project users are assigned to on create.

### Endpoint reference

| Method and path | Behaviour |
|---|---|
| `GET /Users` | List with optional `filter`, `startIndex`, `count`. |
| `POST /Users` | Create. Conflict on duplicate `externalId`. |
| `GET /Users/{id}` | Read by user UUID. |
| `PUT /Users/{id}` | Full replace. |
| `PATCH /Users/{id}` | Operations array (replace, add). |
| `DELETE /Users/{id}` | **Deactivates** — does not hard-delete. |
| `GET /ServiceProviderConfig` | Capability discovery. |
| `GET /ResourceTypes` | Lists supported resource types. |
| `GET /Schemas` | Lists supported schemas. |

### Supported filter operators

- `eq` — exact match (`userName eq "alice@example.com"`)
- `sw` — starts with (`userName sw "alice"`)
- `co` — contains (`userName co "@example.com"`)
- `pr` — present (`externalId pr`)
- `and` — joins clauses

Filterable attributes: `userName`, `externalId`, `id`, `active`. Disjunction (`or`) and bracketed grouping are not supported — every IdP we surveyed only emits conjunctions.

### Why DELETE does not delete

A runaway HRIS connector that bulk-fires DELETE should not be able to wipe an organisation's identity store. `DELETE /Users/{id}` sets the user's status to `disabled` — the row, audit lineage, and credentials remain. To actually remove a user, do it from the admin UI with the approval workflow.

### Configuring an upstream HRIS (Okta as an example)

1. In Blackwall, create an admin API token (`/admin/api-tokens`).
2. In Okta's admin console, create an "SCIM 2.0 Test App" pointing at:
   - **SCIM Base URL** — `https://auth.example.com/scim/v2`
   - **Auth header** — `Bearer bw_admin_…`
   - **Custom header** — `X-BlackWall-Project: <project-uuid>` (Okta calls this "Custom HTTP Headers").
3. Map Okta attributes:
   - `userName` → Okta primary email.
   - `externalId` → Okta user ID.
   - `active` → Okta lifecycle state.
4. Enable Push New Users and Push Profile Updates in Okta.
5. Run a test sync. Confirm the user appears at `/admin/users` in the target project's assignments.

### Smoke test

```bash
curl -sH "Authorization: Bearer bw_admin_…" \
     -H "X-BlackWall-Project: 11111111-2222-3333-4444-555555555555" \
     "https://auth.example.com/scim/v2/ServiceProviderConfig" | jq
```

## Chapter 3: Webhooks for Event-Driven Integration

Blackwall fans every project-scoped audit event out to registered webhook receivers. The dispatcher runs in the background; the originating HTTP request never blocks on a downstream callout.

### Where to manage them

`/admin/projects/{uuid}/webhooks`. Requires `view_projects` to see, `manage_projects` to register, edit, or delete. The project's `webhooks_enabled` feature flag must be on for the dispatcher to deliver.

### Delivery contract

- **Method and encoding** — `POST` with `Content-Type: application/json`.
- **Signature header** — `X-BlackWall-Signature: t=<unix-ts>,v1=<hex>` where `hex = HMAC-SHA256(secret, ts + "." + body)`.
- **Event identification** — `X-BlackWall-Event` (event type) and `X-BlackWall-Event-Id` (UUID, stable across retries).
- **Payload envelope** — `{ id, type, project_id, occurred_at, data, api_version: "2024-11" }`.

### Verifying signatures (receiver side, Node.js)

```javascript
import crypto from 'crypto';
import express from 'express';

const app = express();
app.use(express.raw({ type: 'application/json' }));

app.post('/blackwall-webhook', (req, res) => {
  const sigHeader = req.headers['x-blackwall-signature'];
  const [tsPart, sigPart] = sigHeader.split(',');
  const ts  = tsPart.split('=')[1];
  const sig = sigPart.split('=')[1];

  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(`${ts}.${req.body.toString()}`)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
    return res.status(400).send('bad signature');
  }
  if (Math.abs(Date.now() / 1000 - parseInt(ts, 10)) > 300) {
    return res.status(400).send('stale signature');
  }

  const event = JSON.parse(req.body.toString());
  console.log('received', event.type, event.data);
  res.sendStatus(200);
});
```

### Retry and backoff

Failed deliveries (transport error or non-2xx) re-queue with an exponential backoff: 30s → 5m → 30m → 6h → 24h, capped at 5 attempts before the row is marked `exhausted`. After 20 consecutive failures the **endpoint** is auto-disabled so we stop hammering a dead receiver.

### Inspecting deliveries

Each endpoint has a **Deliveries** link showing the last 100 attempts with status code, attempt count, and a 512-byte excerpt of the response body. Use this for debugging without log scraping.

### Common event types

| Event | Trigger |
|---|---|
| `admin.user.create` / `admin.user.update` | User CRUD via the admin UI or API. |
| `portal.login.success` / `portal.login.fail` | WebAuthn assertion result. |
| `oidc.userinfo.success` | A downstream OIDC client read userinfo. |
| `admin.client.create` / `admin.client.update` | OAuth client lifecycle. |
| `admin.claims.user.upsert` / `admin.claims.project_default.upsert` | Custom claim mutations. |
| `saml.response.issued` | SAML assertion sent to an SP. |
| `scim.user.create` / `.replace` / `.patch` / `.deactivate` | Upstream HRIS push. |

Use the per-endpoint **Events** filter (comma-separated) to subscribe to a subset, or `*` for everything.

---

# Part VII — Operations

## Chapter 1: Server-Backed Sessions

By default, Blackwall sessions are encrypted cookies — fast, scalable, but invisible to the server until they expire naturally. When a project enables **db_sessions_enabled**, each login additionally writes a `user_sessions` row that can be listed, revoked instantly, and counted against a per-user cap.

### Where to manage them

- **Admin view** — `/admin/users/{uuid}/sessions` — see, revoke one, or revoke all sessions for a user. Requires `manage_users`.
- **End-user view** — the user's own portal at `/portal` will show their active sessions in a future release.

### Concurrent-session cap

When the cap is set to *N > 0*, a fresh login that would push the user above N revokes the oldest active session first. Useful for licence-style "single active device" controls.

### What revocation actually does

1. The `user_sessions` row's `revoked_at` is set to NOW.
2. On the user's next request, the auth middleware looks up the row and refuses the request because it is revoked.
3. The session cookie remains in the user's browser until it naturally expires, but it carries no authority.

### What revocation does not do

- It does not kill OAuth tokens issued during that session — those have their own lifecycles. To kill those, revoke them via `/oauth/revoke`.
- It does not log the user out of other projects unless you revoke their sessions there too.

### Forced sign-out everywhere

The **Revoke all** button on the per-user sessions page kills every active session for that user across all projects. Use it after a credential delete, a status change to `disabled`, or any other action that should require re-authentication.

## Chapter 2: The Audit Log

Every admin mutation, every OAuth flow, every WebAuthn assertion writes a row to `audit_log`. The chain is tamper-evident and the export is HMAC-signed.

### Chain integrity

Each row's `chain_hash` is `SHA-256(prev_chain_hash + "|" + canonical_payload_json)`, computed under a MySQL `GET_LOCK('blackwall:audit_chain', 2)` so concurrent writes serialise correctly. To verify a chain, walk forward from the first row and recompute each hash; mismatches mark the tampered row.

### What is recorded

- `event_type` — dotted action name (e.g. `oauth.authorize.approve`, `admin.user.update`).
- `outcome` — `success`, `fail`, or `info`.
- `correlation_id` — propagated from the `X-Correlation-Id` header so a single end-user request can be traced across services.
- `ip_address` + `user_agent` — derived from validated request headers.
- Actor / target identity columns: user UUID, project UUID, oauth client public ID, WebAuthn credential public ID, target type/id.
- `metadata_json` — free-form additional context.

### Search and filtering

The audit page supports filtering by event type (substring), outcome, actor UUID, project UUID, target type, correlation ID, and date range. Non-super-admins are scoped — they only see entries tied to a project they can access, plus system-wide entries with no `project_id`.

### Export with HMAC manifest

Export delivers CSV of the (filtered, scoped) rows followed by a manifest line:

```
# manifest: rows=<n> generated_at=<rfc3339> hmac_sha256=<hex>
```

The HMAC key is `audit_export_signing_key` from `config.yaml` (falling back to `csrf_secret` if unset). Verify the export by HMAC-SHA-256-ing all bytes *before* the manifest line under the same key and matching the result to the manifest.

### Security indicators on the dashboard

- `security.csrf.fail` spike → likely browser misbehaviour or active cross-site attack attempt.
- Repeated `security.ratelimit.hit` → either client misuse or brute-force attempt; correlate by `ip_address`.
- `oauth.authorize.fail` with `error_code=invalid_client` from one IP → enumeration attempt.
- Rising `fail`-outcome counts on the dashboard breakdown — investigate by event_type.

## Chapter 3: Tamper-Evident Chain Checkpoints

The per-row `chain_hash` makes it impossible to alter an old row without invalidating every later row's hash. What `chain_hash` alone does not catch is wholesale truncation or replacement of the entire table. **Audit chain checkpoints** close that gap.

A periodic job records the tip of the log as a signed triple `(last_audit_id, row_count, last_chain_hash)`, signed with the platform's active JWT key. Once published outside the database (S3 with versioning, a transparency log, your SIEM), any silent rewrite between checkpoints becomes detectable.

### Where to manage them

Super-admin only: open `/admin/audit/checkpoints` or click **Chain** in the navbar.

- **Create checkpoint now** forces a checkpoint outside the periodic schedule.
- **Verify** recomputes the tip and confirms the signature is still valid under a known signing key. Drift surfaces as a structured failure message.

### What verification proves

1. **Tip stability** — the row at `last_audit_id` still has the recorded `chain_hash`.
2. **Row count stability** — the number of rows up to and including the tip matches what was signed.
3. **Signature validity** — the recorded signature still validates against an active or retired signing key.

### Operational guidance

- Run the checkpoint job at least daily; hourly is fine.
- **Ship checkpoints off-host immediately.** A checkpoint in the same database it attests is only useful as a hint. Push to S3 (Object Lock and versioning), a transparency log, or your SIEM's WORM-style storage.
- If a verification fails, freeze further audit writes operationally and investigate. The first bad row's ID gives you the boundary.

## Chapter 4: Metrics and Observability

Blackwall exposes two metric surfaces: a Prometheus-compatible scrape endpoint and an optional outbound push of every audit event as a counter sample.

### /metrics scrape endpoint

Authenticated by bearer token (`metrics_token` in `config.yaml`) by default. Set `metrics_allow_unauthenticated: true` to drop the check — only do this if `/metrics` is otherwise network-isolated.

The endpoint emits gauges for: total user count, active user count, project count, active OAuth client count, registered WebAuthn credential count, audit events written today, active access tokens, pending approval count.

### Event push (vmagent / VictoriaMetrics)

If `event_metrics_push_enabled: true` and `event_metrics_push_url` is set, every audit event is also pushed asynchronously as a single counter sample to that URL. Format is Prometheus text exposition.

| Config key | Purpose |
|---|---|
| `event_metrics_push_metric_name` | Defaults to `blackwall_event`. |
| `event_metrics_push_include_outcome` | Adds `outcome="success|fail|info"` label. |
| `event_metrics_push_static_labels` | Comma-separated extra labels (e.g. `env="prod",region="eu-west"`). |
| `event_metrics_push_timeout_ms` | HTTP timeout per push, default 250ms. Pushes happen in goroutines so a slow endpoint does not block the audit write. |

## Chapter 5: Maintenance Jobs

Blackwall ships a set of background jobs that prune expired material. Super-admins can run them from `/admin/maintenance`.

| Job | What it cleans |
|---|---|
| `cleanup_expired_codes` | Authorisation codes past their expiry. |
| `cleanup_expired_tokens` | Access and refresh tokens whose `expires_at` has passed. |
| `cleanup_revoked_tokens` | Tokens revoked more than 24 hours ago. |
| `cleanup_expired_challenges` | Stale WebAuthn / portal challenge sessions. |
| `cleanup_expired_rate_limits` | Old rows in `rate_limits` past their window. |
| `cleanup_audit_retention` | Audit rows older than `audit_retention_days`. Set to 0 to disable. |
| `cleanup_expired_approvals` | Approval requests pending longer than `approval_pending_max_age_days`. |
| `cleanup_expired_cryptbin` | CryptBin items past their `expires_at`. |

Jobs run on the schedule defined in `config.yaml`. They can also be triggered manually from the maintenance page.

## Chapter 6: Backup and Disaster Recovery

| Asset | Backup expectation |
|---|---|
| MySQL database | Full nightly dump plus binlog shipping to a separate host. **Critical** — the JWT signing keys live in the database. A database loss without backup means every issued token becomes unverifiable. |
| CryptBin storage path | Same RPO as the database. Lose the blobs, lose the items: the database carries only metadata. |
| `config.yaml` | Back up. Without the original `session_secret`, `csrf_secret`, `cryptbin_kek_base64`, and `error_trace_key`, you cannot read existing sessions, validate existing CSRF tokens, decrypt CryptBin DEKs, or decode error traces. |
| Audit chain checkpoints | If exported off-host (recommended), they form their own backup record. Otherwise they are backed up as part of the database. |

### Recovery rehearsal

Twice yearly: restore the database, the CryptBin storage path, and `config.yaml` to a clean host, then attempt to:

1. Sign in as an existing user.
2. Read an existing CryptBin item.
3. Verify an existing token via `/oauth/introspect`.

If any of those fail, your backup set is incomplete.

## Chapter 7: KMS-Pluggable Signing Keys

By default, Blackwall stores its JWT signing key as an RSA private key in the `jwt_signing_keys` table. That is fine for development and most single-operator deployments, but it is a SOC 2 / FedRAMP / HIPAA finding waiting to happen: an attacker with database access can mint tokens that say anything.

The `Signer` interface in `internal/service/signer.go` abstracts the signing operation so the private key can live outside the process — in AWS KMS, GCP KMS, HashiCorp Vault, or any HSM with a SIGN/VERIFY profile.

### The interface

```go
type Signer interface {
    KeyID() string
    Algorithm() string                  // "RS256"
    PublicKey() *rsa.PublicKey          // for JWKS export
    Sign(data []byte) ([]byte, error)
    Verify(data, sig []byte) error
}
```

Today's implementations:

- `LocalDBSigner` — the existing path. Private key materialised into the process at boot.
- `kmsSignerStub` — placeholder that fails loudly if the operator selects a cloud backend in config but the matching build tag was not enabled.

### Adding a real backend

The pattern is intentionally similar across clouds. Each signer dispatches the SHA-256 digest of `data` and returns the cloud's signature bytes. Each implementation lives behind a Go build tag so the cloud SDK only inflates the binary for operators who actually need it.

#### AWS KMS

1. Create a KMS key with `KeySpec=RSA_2048`, `KeyUsage=SIGN_VERIFY`.
2. Implement `internal/service/signer_aws.go` behind `//go:build kms_aws`:
   - `Sign` — call `kms.Sign` with `SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`, `MessageType=DIGEST`, sending the local SHA-256 of `data`.
   - `PublicKey` — fetch `kms.GetPublicKey` once at boot and cache.
   - `KeyID` — the KMS key ARN or alias.
3. Build with `go build -tags kms_aws ./cmd/blackwall`.

#### GCP KMS

Same shape, behind `//go:build kms_gcp`. Use `cloudkms.AsymmetricSign` with `RSA_SIGN_PKCS1_2048_SHA256`.

#### HashiCorp Vault Transit

Behind `//go:build kms_vault`. Use the Transit engine's `sign` endpoint with `signature_algorithm=pkcs1v15` and `hash_algorithm=sha2-256`.

### What also moves with the signer

Because the audit chain checkpoint signature goes through the same `JWTManager.SignBytes`, switching JWT signing to KMS automatically moves checkpoint signing to KMS too. SAML metadata and assertion signing similarly use the JWT key, so the entire signing posture migrates together.

### Key rotation

KMS backends version their keys natively. Today Blackwall's JWKS endpoint reflects whatever the active `jwt_signing_keys` rows say — when you move to KMS, the KMS-backed signer should publish its current public key version into a row so the JWKS endpoint sees it. Plan to advertise **both the previous and the current public keys** during the overlap window so in-flight tokens continue to verify.

## Chapter 8: Troubleshooting

| Symptom | Diagnosis |
|---|---|
| Blackwall refuses to start with `config: session_secret must be at least 32 characters` | Generate proper secrets (`openssl rand -hex 32`). Refuses by design — running with weak material is worse than not running. |
| Login page shows but WebAuthn prompt never appears | Browser blocks WebAuthn outside HTTPS. Verify TLS at the proxy. Verify `webauthn_rp_id` matches the hostname. |
| Users sign in but immediately see `access_denied` at a downstream client | The user is not assigned to that project. Open `/admin/projects/{uuid}/assignments`. |
| ID tokens fail nonce check | Your application's pre-auth session is being lost between redirect and callback. Check cookie SameSite and the `Secure` attribute. |
| `/metrics` returns 401 | Set `metrics_token` in `config.yaml` and send `Authorization: Bearer <token>`. |
| Webhook receiver never sees deliveries | Confirm the project's `webhooks_enabled` flag is on. Check `/admin/projects/{uuid}/webhooks/{id}/deliveries` for failed attempts. If the endpoint is auto-disabled (20 consecutive failures), re-enable it. |
| Audit chain verify reports drift | Stop further writes operationally. The first bad row's ID is the boundary. Investigate from `git log` who last touched the database. |
| Tokens verify locally but `/oauth/introspect` says inactive | The token was revoked. JWT signature validity ≠ token validity. Add introspection to your verification loop, or switch to opaque tokens. |
| New project shows enterprise features off | Migration backfilled existing projects with everything off. Turn on the relevant flags on the project's detail page. |

---

# Part VIII — Automation and Infrastructure-as-Code

## Chapter 1: The Admin JSON API

`/api/v1/*` exposes the same operations as the admin UI in JSON form. Use it from your own scripts, CI pipelines, or anywhere you would otherwise click through the UI.

Every endpoint requires an `Authorization: Bearer bw_admin_…` header. The bearer token resolves to a user; that user's admin role and scope are applied to the request. There is no token-side capability escalation.

### Listing resources

```bash
curl -sH "Authorization: Bearer $BW" https://auth.example.com/api/v1/organizations
curl -sH "Authorization: Bearer $BW" https://auth.example.com/api/v1/projects
curl -sH "Authorization: Bearer $BW" https://auth.example.com/api/v1/projects/$UUID
curl -sH "Authorization: Bearer $BW" https://auth.example.com/api/v1/users
```

### Creating a project

```bash
curl -sX POST https://auth.example.com/api/v1/projects \
  -H "Authorization: Bearer $BW" \
  -H "Content-Type: application/json" \
  -d '{"name": "Marketing site", "organization_uuid": "..."}'
```

### Updating a project

```bash
curl -sX PATCH https://auth.example.com/api/v1/projects/$UUID \
  -H "Authorization: Bearer $BW" \
  -H "Content-Type: application/json" \
  -d '{"status": "disabled"}'
```

### Managing claim defaults

```bash
# Upsert
curl -sX PUT https://auth.example.com/api/v1/projects/$UUID/claim_defaults \
  -H "Authorization: Bearer $BW" \
  -H "Content-Type: application/json" \
  -d '{"key": "preferred_username", "value": "team-grafana"}'

# Delete
curl -sX DELETE "https://auth.example.com/api/v1/projects/$UUID/claim_defaults?key=preferred_username" \
  -H "Authorization: Bearer $BW"
```

### Endpoint summary

| Resource | Endpoints |
|---|---|
| Organisations | `GET /organizations` |
| Projects | `GET /projects`, `POST /projects`, `GET/PATCH/DELETE /projects/{uuid}` |
| OAuth clients | `GET /projects/{uuid}/oauth_clients`, `POST /projects/{uuid}/oauth_clients`, `GET/PATCH/DELETE /oauth_clients/{id}` |
| Claim defaults | `GET/PUT/DELETE /projects/{uuid}/claim_defaults` |
| Webhooks | `GET/POST /projects/{uuid}/webhooks`, `PATCH/DELETE /projects/{uuid}/webhooks/{id}` |
| SAML SPs | `GET/POST /projects/{uuid}/saml_service_providers`, `GET/DELETE /saml_service_providers/{id}` |
| Users | `GET /users` |

## Chapter 2: Bearer Token Authentication

Admin API tokens are bearer credentials for `/api/v1/*`, the SCIM 2.0 surface, and the Terraform provider.

### Format and storage

- Plaintext shape: `bw_admin_<32 base64url chars>`.
- The full plaintext is shown **once** at creation. The server stores only a SHA-256 hash plus a 12-character prefix for UI identification.
- Lost a token? Revoke and reissue — there is no recovery path.

### Minting a token

1. Open `/admin/api-tokens` (super-admin nav link **API tokens**).
2. Click **Create**.
3. Provide a name, optionally scopes (advisory today), optionally an expiry.
4. Copy the plaintext. It will not be shown again.

### Using a token

```bash
curl -H "Authorization: Bearer bw_admin_..." \
     https://auth.example.com/api/v1/projects
```

### Expiry and revocation

Without an expiry, the token lives until manually revoked or until the owning user is deleted. For automation we recommend short-lived rotated tokens; for one-off admin scripts, no expiry is fine.

Revoke from `/admin/api-tokens`. Revocation takes effect on the next request.

## Chapter 3: The Terraform Provider

The `terraform-provider-blackwall` module under `tools/terraform-provider-blackwall/` lets you manage Blackwall resources declaratively. It targets the same JSON admin API as everything else (`/api/v1/*`) so the security model is identical to a curl-based automation.

### Resources

- `blackwall_project` — full create / read / update / delete lifecycle.
- `blackwall_oauth_client` — full CRUD; `client_secret` returned once at create.
- `blackwall_claim_default` — per-project default OIDC claim.
- `blackwall_webhook_endpoint` — webhook receiver registration with HMAC secret.
- `blackwall_saml_service_provider` — SAML SP registry (create / read / delete; updates trigger recreate).

### Data sources

- `blackwall_organization` — slug → UUID lookup.

### Build and install

```bash
cd tools/terraform-provider-blackwall
go mod tidy
go build -o terraform-provider-blackwall .

PLUGIN_DIR="$HOME/.terraform.d/plugins/blackwall.io/identity/blackwall/0.1.0/$(go env GOOS)_$(go env GOARCH)"
mkdir -p "$PLUGIN_DIR"
cp terraform-provider-blackwall "$PLUGIN_DIR/"
```

### Configuration

```hcl
terraform {
  required_providers {
    blackwall = {
      source = "blackwall.io/identity/blackwall"
    }
  }
}

provider "blackwall" {
  host  = "https://auth.example.com"   # or env BLACKWALL_HOST
  token = "bw_admin_..."               # or env BLACKWALL_TOKEN
}
```

### Worked example — Grafana project

```hcl
data "blackwall_organization" "acme" {
  slug = "acme"
}

resource "blackwall_project" "grafana" {
  organization_uuid = data.blackwall_organization.acme.uuid
  name              = "Grafana"
}

resource "blackwall_oauth_client" "grafana_oidc" {
  project_uuid           = blackwall_project.grafana.uuid
  name                   = "Grafana OIDC"
  client_type            = "confidential"
  redirect_uris          = ["https://grafana.example.com/login/generic_oauth"]
  grants                 = ["authorization_code", "refresh_token"]
  scopes                 = ["openid", "profile", "email", "offline_access"]
  oidc_enabled           = true
  access_token_lifetime  = 3600
  refresh_token_lifetime = 2592000
}

resource "blackwall_claim_default" "grafana_groups" {
  project_uuid = blackwall_project.grafana.uuid
  key          = "groups"
  value        = jsonencode(["editors", "viewers"])
}

resource "blackwall_webhook_endpoint" "audit_sink" {
  project_uuid = blackwall_project.grafana.uuid
  target_url   = "https://audit.example.com/blackwall"
  description  = "Production audit sink"
  events       = ["*"]
}

output "grafana_client_id" {
  value = blackwall_oauth_client.grafana_oidc.id
}

output "grafana_client_secret" {
  value     = blackwall_oauth_client.grafana_oidc.client_secret
  sensitive = true
}

output "webhook_secret" {
  value     = blackwall_webhook_endpoint.audit_sink.secret
  sensitive = true
}
```

### State considerations

- The webhook `secret` field is computed and sensitive; Terraform state files must be encrypted at rest.
- Drift detection works on Read: if someone edits a claim default in the admin UI, the next `terraform plan` will detect the drift and offer to revert.

## Chapter 4: CI/CD Patterns

### Per-environment tokens

Mint one bearer token per environment (`dev`, `staging`, `prod`). Set short expiries (24 hours for build agents; longer for human-driven workflows). Store in your CI's secrets store.

### Plan/apply pipelines

```yaml
# .github/workflows/blackwall-config.yml
name: Apply Blackwall config
on:
  push:
    branches: [main]
    paths: ['infra/blackwall/**']
  pull_request:
    paths: ['infra/blackwall/**']

jobs:
  terraform:
    runs-on: ubuntu-latest
    env:
      BLACKWALL_HOST:  ${{ vars.BLACKWALL_HOST }}
      BLACKWALL_TOKEN: ${{ secrets.BLACKWALL_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
        working-directory: infra/blackwall
      - run: terraform plan -no-color
        working-directory: infra/blackwall
        if: github.event_name == 'pull_request'
      - run: terraform apply -auto-approve
        working-directory: infra/blackwall
        if: github.event_name == 'push'
```

---

# Part IX — OIDC Conformance and Standards Posture

## Chapter 1: Specification Compliance Today

Blackwall targets the OpenID Foundation's **Basic OP + PKCE** conformance profile. The following items are covered:

- **Discovery doc** at `/.well-known/openid-configuration` emitting issuer, every endpoint URL, supported response_types, grant_types, subject_types, signing algorithms, scopes, token endpoint auth methods, code_challenge_methods, claims, claim_types, plus explicit `false` values for unsupported features.
- **JWKS** at `/oauth/jwks` with stable `kid`.
- **response_type=code** with mandatory **PKCE S256**.
- **nonce** required on OIDC requests, echoed in the ID token.
- **at_hash** emitted in the ID token, computed per spec.
- **state** round-tripped through the redirect.
- **Error responses** redirected to the redirect_uri with `error` + `error_description` + `state`.
- **prompt=none** returns `login_required` when unauthenticated.
- **prompt=login** forces fresh WebAuthn authentication.
- **Reserved claim protection** — custom claims can never override `iss`, `sub`, `aud`, etc.
- **Userinfo endpoint** verifies `openid` scope and bearer-token freshness.
- **Token revocation** at `/oauth/revoke` and **introspection** at `/oauth/introspect`.
- **Confidential and public clients** with the corresponding auth methods.

## Chapter 2: Known Gaps

Items planned for the next conformance pass:

- **id_token_hint** evaluation when prompt=none arrives.
- **max_age** enforcement at `/oauth/authorize`.
- **acr_values** echo in the `acr` claim.
- **response_mode=form_post** — advertised in discovery but not implemented in the code-issuance path yet.
- **End-session endpoint** for RP-initiated logout.
- **Backchannel logout** — webhook fallback exists in the meantime.

## Chapter 3: Running the Conformance Suite

1. Clone: `git clone https://gitlab.com/openid/conformance-suite.git`. Build with `./run-tests.sh` per the suite's README.
2. Create a confidential OAuth client in Blackwall:
   - Grants: `authorization_code`, `refresh_token`
   - Redirect URIs: whatever the suite tells you when you start a test plan.
   - Scopes: `openid profile email offline_access`
   - OIDC enabled: yes
   - Access token type: jwt
3. In the suite's UI, configure the test plan with:
   - **Discovery URL** — `https://auth.example.com/.well-known/openid-configuration`
   - **Client ID and client_secret** from above
   - **PKCE method** — S256
4. Run the **Basic Certification Profile** test plan first. Each failing test points at a specific OIDC clause to fix.
5. Once green, re-run **OP+PKCE**. Address remaining failures, repeat.

## Chapter 4: The Path to Certification

Submit the green test log to the OpenID Foundation per [openid.net/certification](https://openid.net/certification). The certification mark carries real weight in enterprise security questionnaires.

---

# Part X — Reference

## Chapter 1: Configuration Reference

The main configuration file is `config.yaml`. Every key can also be supplied via an environment variable using its `SCREAMING_SNAKE_CASE` equivalent.

### Required

| Key | Purpose |
|---|---|
| `app_url` | Public-facing base URL (e.g. `https://auth.example.com`). Forms the `iss` claim. |
| `db_host`, `db_port`, `db_name`, `db_user`, `db_pass` | MySQL connection details. |
| `session_secret` | 32+ char hex. Encrypts the session cookie. |
| `csrf_secret` | 32+ char hex. HMAC key for CSRF tokens. Must differ from `session_secret`. |

### Session and security

| Key | Default | Purpose |
|---|---|---|
| `session_name` | `blackwall_session` | Cookie name. |
| `session_lifetime` | 7200 (s) | Max cookie age. |
| `session_idle_timeout` | 1800 (s) | Inactivity timeout. |
| `session_bind_user_agent` | true | Bind sessions to UA fingerprint. |
| `trust_proxy` | false | Honour `X-Forwarded-*` headers from `trusted_proxies`. |
| `trusted_proxies` | (empty) | CIDR list. |
| `rate_limit_enabled` | true | Master switch. |

### WebAuthn

| Key | Default | Purpose |
|---|---|---|
| `webauthn_rp_id` | derived from `app_url` | Relying party ID. Must match the public hostname. |
| `webauthn_rp_name` | `BlackWall OAuth` | Display name in WebAuthn prompts. |
| `min_webauthn_keys` | 1 | Minimum credentials a user must retain. |

### Audit and approvals

| Key | Default | Purpose |
|---|---|---|
| `audit_retention_days` | 180 | 0 disables cleanup. |
| `audit_export_signing_key` | (empty; falls back to `csrf_secret`) | HMAC key for export manifests. |
| `approval_pending_max_age_days` | 14 | Auto-reject after this many days. |
| `admin_approval_pending_warning_days` | 3 | Dashboard warning threshold. |

### Metrics

| Key | Default | Purpose |
|---|---|---|
| `metrics_token` | (empty) | Bearer token for `/metrics`. |
| `metrics_allow_unauthenticated` | false | Drop auth check (use only with network isolation). |
| `event_metrics_push_enabled` | false | Master switch. |
| `event_metrics_push_url` | (empty) | Push target. |
| `event_metrics_push_metric_name` | `blackwall_event` | Counter name. |
| `event_metrics_push_include_outcome` | true | Add `outcome=` label. |
| `event_metrics_push_static_labels` | (empty) | Comma-separated extra labels. |
| `event_metrics_push_timeout_ms` | 250 | HTTP timeout per push. |

### Server

| Key | Default | Purpose |
|---|---|---|
| `server_addr` | `:8080` | Listen address. |

## Chapter 2: Endpoint Index

### Public OAuth / OIDC

| Path | Method | Purpose |
|---|---|---|
| `/.well-known/openid-configuration` | GET | Discovery document. |
| `/oauth/jwks` | GET | JWKS for signature verification. |
| `/oauth/authorize` | GET, POST | Authorisation endpoint. |
| `/oauth/token` | POST | Token endpoint. |
| `/oauth/userinfo` | GET, POST | Userinfo endpoint. |
| `/oauth/revoke` | POST | RFC 7009 revocation. |
| `/oauth/introspect` | POST | RFC 7662 introspection. |

### SAML 2.0 IdP

| Path | Method | Purpose |
|---|---|---|
| `/saml/projects/{uuid}/metadata` | GET | IdP EntityDescriptor. |
| `/saml/projects/{uuid}/sso` | GET, POST | SP-initiated SSO entry point. |
| `/saml/projects/{uuid}/sso/continue` | GET | Post-login bounce target. |

### SCIM 2.0

| Path | Method | Purpose |
|---|---|---|
| `/scim/v2/ServiceProviderConfig` | GET | Capability discovery. |
| `/scim/v2/ResourceTypes` | GET | Supported resources. |
| `/scim/v2/Schemas` | GET | Supported schemas. |
| `/scim/v2/Users` | GET, POST | List and create. |
| `/scim/v2/Users/{id}` | GET, PUT, PATCH, DELETE | Read, replace, modify, deactivate. |

### JSON Admin API

(See Part VIII, Chapter 1.)

### User portal

| Path | Method | Purpose |
|---|---|---|
| `/portal/login` | GET, POST | WebAuthn login. |
| `/portal` | GET | User dashboard. |
| `/portal/keys/...` | POST | Self-service authenticator management. |
| `/portal/logout` | POST | Sign out. |

### Admin console

Everything under `/admin/*`. Specific paths appear throughout this manual.

## Chapter 3: Capability Matrix

The complete capability list per role is rendered at `/admin/roles`. The highlights:

| Capability | super_admin | operator | auditor |
|---|---|---|---|
| `view_audit` | ✓ | ✓ | ✓ |
| `view_users` / `view_projects` | ✓ | ✓ | ✓ |
| `manage_users` | ✓ | ✓ | — |
| `manage_projects` | ✓ | ✓ | — |
| `manage_clients` | ✓ | ✓ | — |
| `manage_organizations` | ✓ | — | — |
| `manage_roles` | ✓ | — | — |
| `decide_approvals` | ✓ | ✓ | — |
| `change_user_status_direct` | ✓ | — | — |
| `delete_credentials_direct` | ✓ | — | — |
| `assignment_mutations_direct` | ✓ | — | — |
| `update_client_settings_direct` | ✓ | — | — |
| `change_client_status_direct` | ✓ | — | — |
| `update_project_settings_direct` | ✓ | — | — |
| `change_project_status_direct` | ✓ | — | — |
| `switch_organization_admin` | ✓ | — | — |
| `view_docs` | ✓ | ✓ | ✓ |

## Chapter 4: Audit Event Catalogue

Selected events admins commonly filter on. The full list is observable by enumerating recent rows at `/admin/audit`.

### OAuth / OIDC

- `oauth.authorize.begin` — authorize endpoint accepted a valid request.
- `oauth.authorize.approve` — user consented (or trusted client auto-approved).
- `oauth.authorize.fail` — request rejected; reason in `metadata_json`.
- `oauth.token.exchange` — code exchanged for tokens.
- `oauth.token.refresh` — refresh used to mint new access token.
- `oauth.token.revoke` — token revoked via `/oauth/revoke`.
- `oauth.token.introspect` — introspection call.
- `oidc.userinfo.success` / `oidc.userinfo.fail` — userinfo result.
- `oidc.discovery` — discovery document fetched.
- `jwks.fetch` — JWKS fetched.

### Admin mutations

- `admin.user.create` / `update` / `status.change`
- `admin.project.create` / `update`
- `admin.client.create` / `update`
- `admin.claims.user.upsert` / `delete`
- `admin.claims.project_default.upsert` / `delete`
- `admin.claims.org.upsert` / `delete`
- `admin.webhook.create` / `update` / `delete`
- `admin.session.revoke` / `revoke_all`
- `admin.audit.checkpoint.create`
- `admin.token.create` / `revoke`
- `admin.saml.sp.create` / `delete`
- `admin.org.branding.update`
- `admin.org.domain.add` / `delete`

### Approvals

- `admin.approval.request` — operator submitted a mutation that needed approval.
- `admin.approval.decision.approved` / `denied` — reviewer decided.
- `admin.approval.cancelled` — requester cancelled.

### Federation

- `saml.response.issued` — SAML assertion sent.
- `scim.user.create` / `replace` / `patch` / `deactivate` — SCIM lifecycle events.

### API

- `api.project.create` / `update` / `disable`
- `api.client.create` / `update` / `disable`
- `api.claim_default.upsert` / `delete`
- `api.webhook.create` / `update` / `delete`
- `api.saml.sp.create` / `delete`

### Security

- `security.csrf.fail` — CSRF token validation failed.
- `security.ratelimit.hit` — rate limit hit.
- `portal.login.success` / `fail`
- `admin.login.success` / `fail`

## Chapter 5: Glossary

| Term | Definition |
|---|---|
| Assertion | The SAML XML element carrying authentication facts. Signed. |
| Authenticator | A device that holds WebAuthn private keys (Touch ID, Windows Hello, security key, synced passkey). |
| at_hash | The OIDC `at_hash` claim — leftmost 128 bits of SHA-256 of the access token, base64url-encoded. Binds the ID token to the access token. |
| Audit chain | The hash-linked sequence of audit log rows. |
| Bearer token | A credential that, by holding it, grants access. The opposite of proof-of-possession. |
| Capability | A named permission granted by an admin role. |
| Checkpoint | A signed snapshot of the audit log tip. |
| Client | An OAuth client. The downstream application. |
| code_challenge | The PKCE challenge value sent at `/oauth/authorize`. |
| code_verifier | The PKCE verifier value sent at `/oauth/token`. |
| Discovery document | The JSON at `/.well-known/openid-configuration`. |
| Issuer | The URL that identifies an OIDC provider. Blackwall's `app_url`. |
| JWKS | JSON Web Key Set. The public keys at `/oauth/jwks`. |
| Nonce | A one-shot random value sent with an OIDC request and echoed in the ID token. |
| Organisation | The tenant boundary. |
| PKCE | Proof Key for Code Exchange (RFC 7636). Mandatory in Blackwall. |
| Privilege level | A per-project rung used to authorise user actions. |
| Project | The unit of OAuth client ownership. |
| Relying Party (RP) | Same as Service Provider / OAuth client. |
| SAML | Security Assertion Markup Language. The XML federation protocol. |
| SCIM | System for Cross-domain Identity Management. The HRIS push protocol. |
| Scope | (1) The OAuth scope claim listing requested permissions. (2) An admin's set of accessible organisations and projects. |
| Service Provider (SP) | A SAML Relying Party — the downstream application. |
| State | The CSRF-protection random value sent at `/oauth/authorize` and echoed in the redirect. |
| Sub | The OAuth/OIDC `sub` claim — the user's stable UUID. |
| Userinfo | The `/oauth/userinfo` endpoint and its response. |
| Webhook | An outbound HTTP POST Blackwall sends when an event happens. |
| WebAuthn | The W3C standard for passwordless authentication using authenticators. The only authentication method Blackwall supports. |

---

*End of manual.*

*Copyright Andy Dixon. Distributed with the Blackwall source. Suggestions and corrections welcome via the project's GitHub repository.*
