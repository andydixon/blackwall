# BlackWall OAuth 2.1 + OIDC Server - Complete File Tree

## Project Structure

```
blackwall.dixon.cx/
├── bin/
│   └── blackwall                    # Bootstrap CLI command (executable)
│
├── config/
│   ├── bootstrap.php                # Application initialization
│   └── routes.php                   # Route definitions
│
├── docs/
│   ├── apache-vhost.conf            # Apache virtual host example
│   ├── CLIENT_INTEGRATION.md        # Client integration guide
│   └── RUNBOOK.md                   # Operational procedures
│
├── migrations/
│   └── 001_initial_schema.sql       # Database schema with audit logging
│
├── public_html/                     # Document root (public web files)
│   ├── index.php                    # Entry point
│   ├── .htaccess                    # Apache rewrite rules
│   └── assets/
│       ├── css/
│       │   └── blackwall.css        # Dark theme styles
│       └── js/
│           └── blackwall.js         # JavaScript utilities
│
├── src/
│   ├── Config.php                   # Environment config loader
│   ├── Database.php                 # PDO database singleton
│   │
│   ├── Controller/
│   │   ├── AdminController.php      # Admin panel controller
│   │   ├── BootstrapController.php  # Bootstrap/enrollment controller
│   │   └── OAuthController.php      # OAuth 2.1 + OIDC endpoints
│   │
│   ├── Domain/
│   │   ├── PrivilegeLevel.php       # Privilege level value object
│   │   └── UserProjectRole.php      # User-project assignment
│   │
│   ├── Middleware/
│   │   ├── AuditContextMiddleware.php    # Audit logger injection
│   │   ├── CorrelationIdMiddleware.php   # Request correlation IDs
│   │   └── IpAddressMiddleware.php       # Client IP extraction
│   │
│   ├── Model/
│   │   ├── OAuthClient.php          # OAuth client entity
│   │   ├── Project.php              # Project entity
│   │   └── User.php                 # User entity
│   │
│   ├── Repository/
│   │   ├── OAuthClientRepository.php
│   │   ├── PrivilegeLevelRepository.php
│   │   ├── ProjectRepository.php
│   │   ├── UserProjectRoleRepository.php
│   │   └── UserRepository.php
│   │
│   ├── Security/
│   │   ├── CSRFProtection.php       # CSRF token management
│   │   ├── JWTManager.php           # JWT signing and JWKS
│   │   ├── PKCEValidator.php        # PKCE S256 validation
│   │   ├── RateLimiter.php          # Rate limiting
│   │   ├── SessionManager.php       # Secure session handling
│   │   └── TokenHasher.php          # Token hashing (SHA-256)
│   │
│   └── Service/
│       ├── AuditLogger.php          # Comprehensive audit logging
│       ├── OAuthService.php         # OAuth business logic
│       └── WebAuthnService.php      # WebAuthn credential management
│
├── templates/                       # PHP templates (Bootstrap 5 dark theme)
│   ├── _layout.php                  # Main layout template
│   │
│   ├── admin/
│   │   ├── login.php                # Admin WebAuthn login
│   │   ├── dashboard.php            # Admin dashboard
│   │   │
│   │   ├── users/
│   │   │   ├── list.php             # User listing
│   │   │   └── create.php           # User creation form
│   │   │
│   │   ├── projects/
│   │   │   ├── list.php             # Project listing
│   │   │   ├── create.php           # Project creation form
│   │   │   └── detail.php           # Project detail page
│   │   │
│   │   └── audit/
│   │       └── log.php              # Audit log search UI
│   │
│   ├── bootstrap/
│   │   └── enroll.php               # Bootstrap WebAuthn enrollment
│   │
│   └── oauth/
│       └── consent.php              # OAuth consent screen
│
├── vendor/                          # Composer dependencies (auto-generated)
├── logs/                            # Application logs
├── tmp/                             # Temporary files
│
├── .env                             # Environment configuration (NOT in git)
├── .env.example                     # Environment template
├── .gitignore                       # Git ignore rules
├── composer.json                    # PHP dependencies
├── composer.lock                    # Locked dependency versions
├── Makefile                         # Build and maintenance tasks
└── README.md                        # Project documentation
```

## Core Files Description

### Entry Points

- **public_html/index.php**: Front controller that loads config/bootstrap.php and runs Slim app
- **bin/blackwall**: CLI bootstrap command for initial setup

### Configuration

- **config/bootstrap.php**: Initializes Slim framework, loads environment, registers middleware
- **config/routes.php**: Defines all HTTP routes (OAuth, admin, bootstrap)
- **.env**: Environment-specific configuration (database, secrets, WebAuthn settings)

### Controllers

- **OAuthController**: Handles OAuth 2.1 + OIDC flows
  - `/oauth/authorize` - Authorization endpoint
  - `/oauth/token` - Token issuance
  - `/oauth/revoke` - Token revocation
  - `/oauth/introspect` - Token introspection
  - `/oauth/userinfo` - OIDC UserInfo
  - `/.well-known/openid-configuration` - OIDC discovery
  - `/oauth/jwks` - JSON Web Key Set

- **AdminController**: Admin panel operations
  - User management
  - Project management
  - Privilege level configuration
  - User-project assignments
  - OAuth client management
  - Audit log search

- **BootstrapController**: Initial system setup
  - WebAuthn credential enrollment
  - First admin user creation

### Services

- **OAuthService**: OAuth 2.1 business logic
  - Authorization code generation
  - Code-for-token exchange
  - PKCE validation
  - Token issuance (JWT or opaque)
  - Token introspection
  - Token revocation

- **AuditLogger**: Comprehensive audit logging
  - Tracks all auth and admin events
  - Searchable by project, user, IP, event type
  - Includes correlation IDs for request tracing

- **WebAuthnService**: WebAuthn credential management
  - Registration challenge generation
  - Authentication challenge generation
  - Credential storage and validation

### Security

- **JWTManager**: JWT token generation and validation
  - RSA key pair management
  - JWKS endpoint generation
  - Token signing and verification
  - Key rotation support

- **PKCEValidator**: OAuth 2.1 PKCE enforcement
  - S256 challenge validation
  - Code verifier verification

- **RateLimiter**: Rate limiting protection
  - Per-IP, per-action limits
  - Configurable thresholds
  - Automatic cleanup

- **SessionManager**: Secure session handling
  - HTTPOnly, Secure, SameSite cookies
  - Session fixation mitigation
  - Automatic regeneration

### Database Schema

- **users**: User accounts (WebAuthn-only)
- **webauthn_credentials**: Stored security keys
- **projects**: Multi-tenant projects
- **project_privilege_levels**: Named privilege levels per project
- **user_project_roles**: User-project assignments
- **oauth_clients**: OAuth client registrations
- **oauth_auth_codes**: Authorization codes (short-lived)
- **oauth_access_tokens**: Opaque access tokens
- **oauth_refresh_tokens**: Refresh tokens
- **oauth_scopes**: Available OAuth scopes
- **jwt_signing_keys**: RSA key pairs for JWT signing
- **audit_log**: Comprehensive audit trail (searchable, indexed)
- **rate_limits**: Rate limiting state
- **system_config**: Bootstrap and system state

## Key Features Implemented

### OAuth 2.1 Compliance
✅ Authorization Code with PKCE (required)
✅ Refresh Tokens
✅ Token Revocation (RFC 7009)
✅ Token Introspection (RFC 7662)
✅ Exact redirect URI matching
✅ Strong state handling

### OpenID Connect (OIDC)
✅ Discovery endpoint (/.well-known/openid-configuration)
✅ JWKS endpoint
✅ ID Token issuance
✅ UserInfo endpoint
✅ Standard scopes (openid, profile, email)
✅ Nonce handling

### Multi-Tenant Architecture
✅ Project-based isolation
✅ Project UUID enforcement in all flows
✅ Named privilege levels per project
✅ User-project role assignments
✅ Privilege assertions in tokens

### Token Formats
✅ JWT access tokens (self-contained, signed)
✅ Opaque access tokens (database-backed)
✅ Client-configurable token type
✅ Both include project_id, privilege_level, privilege_name

### Security
✅ WebAuthn-only authentication (no passwords)
✅ CSRF protection on all forms
✅ Rate limiting on sensitive endpoints
✅ Correlation ID tracking
✅ IP address logging
✅ Secure session management
✅ Token hashing (SHA-256)
✅ JWT key rotation support

### Audit Logging
✅ All auth events logged
✅ Admin actions logged
✅ Searchable by project, user, IP, event type
✅ Correlation IDs for request tracing
✅ Comprehensive metadata (scopes, errors, privilege info)
✅ NEVER logs secrets or raw tokens

### Admin UI
✅ Bootstrap 5 dark theme (#1f232a charcoal)
✅ User management
✅ Project management
✅ Privilege level configuration
✅ User-project assignments
✅ OAuth client management
✅ Audit log search with filters
✅ WebAuthn login

## Dependencies (composer.json)

- **slim/slim**: Microframework for HTTP routing
- **slim/psr7**: PSR-7 HTTP message implementation
- **vlucas/phpdotenv**: Environment variable loader
- **web-auth/webauthn-lib**: WebAuthn PHP library
- **ramsey/uuid**: UUID generation
- **lcobucci/jwt**: JWT creation and validation
- **paragonie/constant_time_encoding**: Secure encoding utilities
- **monolog/monolog**: Logging library

## Deployment Checklist

✅ MySQL database created and migrated
✅ .env file configured with secure secrets
✅ Composer dependencies installed
✅ Bootstrap CLI run to create initial admin
✅ Apache vhost configured with HTTPS
✅ WebAuthn credential enrolled
✅ Admin login functional
✅ Health check endpoint responding
✅ OIDC discovery working

## Quick Start

```bash
# Install dependencies
composer install

# Configure environment
cp .env.example .env
nano .env  # Edit database credentials and secrets

# Run migrations
mysql -u blackwall -p blackwall < migrations/001_initial_schema.sql

# Bootstrap system
php bin/blackwall

# Open bootstrap URL in browser to enroll WebAuthn key
# Then login at https://blackwall.dixon.cx/admin/login
```

## Testing OAuth Flow

```bash
# Check OIDC discovery
curl https://blackwall.dixon.cx/.well-known/openid-configuration | jq

# Check JWKS
curl https://blackwall.dixon.cx/oauth/jwks | jq

# Create a project and OAuth client in admin panel
# Then test authorization:
open "https://blackwall.dixon.cx/oauth/authorize?client_id=YOUR_CLIENT&response_type=code&redirect_uri=https://example.com/callback&scope=openid+profile+email&code_challenge=CHALLENGE&code_challenge_method=S256&project_id=PROJECT_UUID&state=STATE"
```

## Production Hardening

1. **Rotate database password** in .env
2. **Generate unique JWT_SIGNING_KEY and CSRF_SECRET**
3. **Enable HTTPS** (required for WebAuthn)
4. **Set APP_DEBUG=false** in production
5. **Configure reverse proxy** if behind Nginx/load balancer
6. **Set up automated backups** (database + .env)
7. **Configure monitoring** for audit log alerts
8. **Review and tune rate limits**
9. **Implement log rotation** for Apache and application logs
10. **Set up SSL certificate auto-renewal** (Let's Encrypt)

## Cryptbin Deployment Addendum

Cryptbin introduces filesystem-backed encrypted blob storage and KEK-wrapped DEKs.

Required environment:

- `CRYPTBIN_KEK_BASE64` (base64-encoded 32-byte key)

Recommended environment:

- `CRYPTBIN_STORAGE_PATH` (outside `public_html`)
- `CRYPTBIN_MAX_UPLOAD_BYTES`
- `CRYPTBIN_MAX_TEXT_BYTES`
- `CRYPTBIN_ALLOWED_MIME`
- `CRYPTBIN_DEFAULT_RETENTION_DAYS`
- `CRYPTBIN_KEK_VERSION`

Storage setup example:

```bash
sudo mkdir -p /var/lib/blackwall/cryptbin
sudo chown www-data:www-data /var/lib/blackwall/cryptbin
sudo chmod 700 /var/lib/blackwall/cryptbin
```

Generate KEK:

```bash
openssl rand -base64 32
```

See `docs/CRYPTBIN.md` for threat model and full crypto design details.

---

**BlackWall v1.0 - Complete and Ready for Production**

✅ OAuth 2.1 + OIDC compliant
✅ WebAuthn-only authentication
✅ Multi-tenant with project isolation
✅ Comprehensive audit logging
✅ Modern, secure, maintainable

Developed on 2026-02-04
