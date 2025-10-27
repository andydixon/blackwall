# BlackWall OAuth 2.1 + OIDC Server - Project Summary

**Status**: ✅ Complete and Deployed
**Version**: 1.1
**Date**: 2026-02-06
**Domain**: https://blackwall.cx

---

## Executive Summary

BlackWall is a production-grade OAuth 2.1 + OpenID Connect (OIDC) authorization server built from scratch in PHP 8.2. It provides secure, WebAuthn-only authentication with multi-tenant project isolation and comprehensive audit logging.

### Key Differentiators

1. **WebAuthn-Only Authentication**: No passwords, no username-based login—only security keys and platform authenticators
2. **Multi-Tenant by Design**: Project-based isolation with UUID enforcement in every auth flow
3. **Named Privilege Levels**: Configurable per-project privilege hierarchies (Owner, Admin, User, custom)
4. **Token Assertions**: Every token includes project_id, privilege_level, and privilege_name
5. **Flexible Token Formats**: JWT (self-contained) or opaque (database-backed) tokens, client-selectable
6. **Comprehensive Audit Logging**: Every auth event, admin action, and security incident is logged with correlation IDs

---

## Technical Architecture

### Technology Stack

- **Language**: PHP 8.2 (PSR-12, PSR-4)
- **Framework**: Slim 4 (microframework)
- **Database**: MySQL 8.0 with utf8mb4 collation
- **Authentication**: WebAuthn (web-auth/webauthn-lib)
- **Token Signing**: JWT with RS256 (lcobucci/jwt)
- **UI**: Bootstrap 5 dark theme with charcoal (#1f232a) background
- **Security**: PKCE (S256), CSRF tokens, rate limiting, session fixation mitigation

### Core Components

**Controllers** (HTTP):
- `OAuthController`: OAuth 2.1 + OIDC endpoints
- `AdminController`: Admin panel (CRUD for users, projects, clients, privileges)
- `BootstrapController`: Initial system setup

**Services** (Business Logic):
- `OAuthService`: Authorization code, token issuance, introspection, revocation
- `WebAuthnService`: Credential registration and authentication
- `AuditLogger`: Event logging with searchable metadata

**Repositories** (Database):
- `UserRepository`, `ProjectRepository`, `OAuthClientRepository`, `PrivilegeLevelRepository`, etc.

**Security**:
- `JWTManager`: JWT signing, JWKS generation, key rotation
- `PKCEValidator`: OAuth 2.1 PKCE enforcement
- `RateLimiter`: Per-IP, per-action rate limiting
- `SessionManager`: Secure session handling
- `TokenHasher`: SHA-256 hashing for tokens and codes

**Middleware**:
- `CorrelationIdMiddleware`: UUID per request for tracing
- `IpAddressMiddleware`: Safe client IP extraction (proxy-aware)
- `AuditContextMiddleware`: Injects audit logger with request context

---

## OAuth 2.1 + OIDC Implementation

### Supported Flows

✅ **Authorization Code + PKCE** (S256 required for all clients)
✅ **Refresh Token**
✅ **Token Revocation** (RFC 7009)
✅ **Token Introspection** (RFC 7662)

### OIDC Features

✅ **Discovery**: `/.well-known/openid-configuration`
✅ **JWKS**: `/oauth/jwks`
✅ **ID Tokens**: Issued with `openid` scope
✅ **UserInfo**: `/oauth/userinfo`
✅ **Standard Scopes**: `openid`, `profile`, `email`, `offline_access`

### Token Formats

**JWT Access Tokens** (recommended):
- Self-contained, signed with RS256
- Include all claims: `project_id`, `privilege_level`, `privilege_name`, `sub`, `aud`, `iss`, `exp`, `scope`
- Clients validate locally without calling BlackWall
- Keys rotatable via JWKS

**Opaque Access Tokens**:
- Random 64-char strings, SHA-256 hashed in DB
- Validated via `/oauth/introspect`
- Real-time revocation checks
- Introspection response includes same claims as JWT

---

## Multi-Tenant Model

### Project Isolation

Every OAuth flow **requires** a `project_id` (UUID) parameter. BlackWall enforces:

1. Client belongs to the specified project
2. User is assigned to the specified project
3. Token assertions match the project

### Privilege Levels

Each project defines its own named privilege levels:

| Level | Name         | Description                |
|-------|--------------|----------------------------|
| 1     | Owner/Admin  | Full administrative access |
| 2     | User         | Standard user access       |
| 3+    | Custom       | Project-specific roles     |

Tokens always include:
- `privilege_level` (int): Numeric level (1=highest)
- `privilege_name` (string): Human-readable name (e.g., "Owner")

Client applications enforce authorization based on these claims.

---

## Security Hardening

### Authentication

- **WebAuthn-only**: No password hashes stored anywhere
- **Challenge-response**: Cryptographic proof of key possession
- **Replay protection**: Nonce handling for OIDC
- **Rate limiting**: 10 attempts/min per IP for WebAuthn

### Token Security

- **PKCE required**: All clients must use S256 code challenges
- **Exact redirect URI matching**: No wildcards or partial matches
- **Token hashing**: All codes and opaque tokens stored as SHA-256 hashes
- **Constant-time comparisons**: Prevents timing attacks
- **Short-lived auth codes**: 10-minute expiry

### Session Security

- **HTTPOnly cookies**: JavaScript cannot access session
- **Secure flag**: HTTPS-only transmission
- **SameSite=Lax**: CSRF protection
- **Session regeneration**: After login to prevent fixation

### Rate Limiting

- `/oauth/token`: 60 requests/min per IP
- `/oauth/authorize`: 30/min
- WebAuthn endpoints: 10/min
- Automatic blocking after threshold

### CSRF Protection

- Unique token per form
- Server-side validation
- Logged failures in audit log

---

## Audit Logging

### Scope

**Every** security-relevant event is logged:

- WebAuthn registration and authentication (success/fail)
- Admin logins (success/fail)
- Admin CRUD operations (users, projects, clients, privileges)
- OAuth authorization requests (begin, approve, deny, fail)
- Token issuance, refresh, revocation, introspection
- OIDC userinfo access
- Rate limit hits
- CSRF failures

### Data Captured

Each audit log entry includes:

- `event_type` (e.g., `oauth.token.issue`, `webauthn.authentication.fail`)
- `outcome` (success/fail/info)
- `message` (human-readable description)
- `correlation_id` (UUID for request tracing)
- `ip_address` (IPv4/IPv6)
- `user_agent`
- `actor_user_id` and `actor_user_uuid` (who performed the action)
- `project_id` and `project_uuid` (which project)
- `oauth_client_id` and `oauth_client_public_id` (which client)
- `webauthn_credential_id` and `webauthn_credential_public_id` (which key)
- `target_type` and `target_id` (what was affected)
- `metadata_json` (flexible data: scopes, errors, privilege info, etc.)

**Never logged**: Raw tokens, raw auth codes, WebAuthn challenges, private keys.

### Searchable Admin UI

Admin panel includes a powerful audit log search:

- Filter by date range, project, user, IP, client, event type, outcome, correlation ID
- Free text search over messages and metadata
- Paginated results with 50 per page
- CSV export (rate-limited, admin-only)
- **Clickable IP addresses** on dashboard link directly to filtered audit logs

### Indexes

Database includes indexes for fast searching:
- `(project_uuid, created_at)`
- `(ip_address, created_at)`
- `(oauth_client_public_id, created_at)`
- `(webauthn_credential_public_id, created_at)`
- Individual indexes on `correlation_id`, `event_type`, `outcome`, etc.

---

## Bootstrap Process

### CLI Bootstrap

```bash
php bin/blackwall
```

1. Creates "BlackWall Admin" project (if not exists)
2. Creates default privilege levels (1=Admin, 2=User)
3. Prompts for initial admin user display label
4. Generates bootstrap token and URL (30-minute expiry)
5. Prints URL for WebAuthn enrollment in browser

### Web Enrollment

1. Open bootstrap URL: `https://blackwall.cx/bootstrap?token=...`
2. Click "Register Security Key"
3. WebAuthn ceremony (browser prompts for authenticator)
4. Credential stored, bootstrap marked complete
5. Redirect to `/admin/login`

Bootstrap route **self-disables** once complete. If lost, manually reset:

```sql
DELETE FROM system_config WHERE config_key = 'bootstrap_complete';
```

Then re-run `php bin/blackwall`.

---

## Admin Panel Features

### Users Management

- **Create users** (UUID auto-generated)
- Set display label (optional, NOT used for auth)
- Enable/disable users
- **View user details** with comprehensive information:
  - All enrolled WebAuthn credentials with metadata
  - Project assignments and privilege levels
  - Account status and timestamps
- **Generate enrollment links** for WebAuthn key enrollment:
  - Secure token-based links (no user ID in URL)
  - 24-hour expiration
  - One-click copy functionality
- **Delete credentials** directly from user detail page
- Full audit trail of all user management actions

### Projects Management

- Create projects (UUID auto-generated)
- Set project name
- Assign owner (user)
- Enable/disable projects
- View project details

### Privilege Levels (per project)

- Create custom privilege levels
- Assign numeric level (1=highest) and human-readable name
- Cannot delete if in use by user assignments
- Default levels: 1=Admin, 2=User

### User-Project Assignments

- Assign users to projects
- Select privilege level by name (e.g., "Owner", "User")
- System stores numeric level, resolves name on display
- Update or remove assignments

### OAuth Clients (per project)

- Create OAuth clients for a project
- Configure:
  - Client name
  - Redirect URIs (exact match required)
  - Grants (authorization_code, refresh_token)
  - Scopes (openid, profile, email, offline_access, custom)
  - PKCE required (always on)
  - Token type (JWT or opaque)
  - Token lifetimes (access: 3600s, refresh: 30 days)
  - OIDC enabled (yes/no)
- Generate client_id and client_secret (if confidential)
- Enable/disable clients

### Audit Log Viewer

- Search by all indexed fields
- Filter by outcome (success/fail/info)
- Correlation ID lookup (trace entire request)
- View full metadata JSON for each event
- Pagination (50 per page)
- Export to CSV (admin-only, rate-limited)

---

## Client Integration

### Authorization Request

```
GET /oauth/authorize?
  client_id=CLIENT_ID&
  response_type=code&
  redirect_uri=https://client.com/callback&
  scope=openid%20profile%20email%20offline_access&
  code_challenge=BASE64URL(SHA256(code_verifier))&
  code_challenge_method=S256&
  project_id=PROJECT_UUID&
  state=RANDOM_STATE&
  nonce=RANDOM_NONCE
```

### Token Exchange

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://client.com/callback&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET&
code_verifier=CODE_VERIFIER
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "eyJ...",
  "scope": "openid profile email offline_access"
}
```

### JWT Claims

```json
{
  "iss": "https://blackwall.cx",
  "aud": "client_id",
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "openid profile email",
  "project_id": "project-uuid",
  "privilege_level": 1,
  "privilege_name": "Owner"
}
```

Clients **must** validate `project_id` matches their registered project and enforce authorization based on `privilege_level`.

---

## Deployment Artifacts

### Database Schema

- 14 tables with proper indexes and foreign keys
- utf8mb4 collation
- UTC timestamps
- Row-level locking for critical operations

### Documentation

- `README.md`: Full project documentation
- `docs/CLIENT_INTEGRATION.md`: Client integration guide with examples
- `docs/RUNBOOK.md`: Operational procedures and incident response
- `docs/DEPLOYMENT.md`: Complete file tree and deployment checklist
- `docs/apache-vhost.conf`: Apache virtual host example
- `.env.example`: Environment configuration template

### Code Quality

- PSR-12 compliant (run `make cs` to check)
- PSR-4 autoloading via Composer
- Type-safe (PHP 8.2 strict types)
- Comprehensive error handling
- No global state (dependency injection)

---

## Acceptance Tests (Validated)

✅ Bootstrap creates BlackWall Admin project  
✅ Bootstrap creates default privilege levels (1=Admin, 2=User)  
✅ Bootstrap creates initial admin user  
✅ WebAuthn enrollment works via bootstrap URL  
✅ Admin can log in with WebAuthn  
✅ Admin can create projects  
✅ Admin can create users  
✅ Admin can define custom privilege levels per project  
✅ Admin can assign users to projects with privilege levels  
✅ Admin can create OAuth clients per project  
✅ OAuth authorization flow works with PKCE  
✅ Tokens include project_id, privilege_level, privilege_name  
✅ OIDC discovery returns correct config  
✅ JWKS endpoint returns active public keys  
✅ JWT access tokens validate correctly  
✅ Opaque token introspection returns correct claims  
✅ Token revocation works  
✅ Audit log records all events  
✅ Audit log UI is searchable by all criteria  
✅ Unauthorised project_id is rejected  
✅ Rate limiting blocks excessive requests  
✅ CSRF protection blocks invalid tokens  

---

## Production Readiness

### Performance

- PDO prepared statements (SQL injection protection)
- Optimized Composer autoloader
- Database indexes on all search fields
- JWT validation is local (no database hit)
- Rate limit cleanup runs probabilistically (5% chance per request)

### Scalability

- Stateless JWT tokens enable horizontal scaling
- Database connection pooling compatible
- Session storage can be moved to Redis/Memcached
- JWKS caching reduces load on key endpoint

### Monitoring

- Health check endpoint: `/health`
- Apache access/error logs
- Application logs in `logs/`
- Audit log for security events
- Database slow query log (enable if needed)

### Security

- All secrets in .env (never committed)
- HTTPS required (WebAuthn constraint)
- HTTPOnly, Secure, SameSite cookies
- Content Security Policy ready
- Rate limiting on all sensitive endpoints
- Comprehensive audit trail
- No raw credentials stored (WebAuthn-only)

---

## Future Enhancements (Optional)

- [ ] Client credentials grant (for M2M)
- [ ] Device authorization grant (RFC 8628)
- [ ] JWT access token revocation lists
- [ ] Multi-factor enrollment (backup keys)
- [ ] Email notifications for security events
- [ ] Prometheus metrics endpoint
- [ ] GraphQL API for admin operations
- [ ] Two-person rule for privilege escalation
- [ ] IP allowlisting per OAuth client

---

## Maintenance

### Daily

- Review audit logs for anomalies
- Check rate limit hits
- Monitor disk space

### Weekly

- Clean up expired tokens
- Review OAuth client activity
- Check for disabled users with active tokens

### Monthly

- Rotate JWT signing keys
- Archive old audit logs (>90 days)
- Review privilege escalations
- Update dependencies (`composer update`)

### Quarterly

- Security audit
- Penetration testing
- Dependency vulnerability scan
- SSL certificate renewal (if manual)

---

## Support

- **Repository**: /home/andy/domains/blackwall.cx
- **Admin URL**: https://blackwall.cx/admin
- **Discovery**: https://blackwall.cx/.well-known/openid-configuration
- **Documentation**: See `docs/` directory

---

## Conclusion

BlackWall is a complete, production-ready OAuth 2.1 + OIDC authorization server that prioritizes security, auditability, and multi-tenancy. It replaces traditional password-based authentication with WebAuthn, provides flexible token formats, and ensures every authorization decision includes project and privilege context.

**Ready for immediate deployment and integration with your applications.**

✅ OAuth 2.1 compliant  
✅ OIDC certified patterns  
✅ WebAuthn-only authentication  
✅ Multi-tenant architecture  
✅ Comprehensive audit logging  
✅ Modern, maintainable codebase  

**BlackWall v1.0 - Built 2026-02-04**
