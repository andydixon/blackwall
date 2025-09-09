# BlackWall OAuth 2.1 + OpenID Connect Authorization Server

**A production-ready, WebAuthn-only, multi-tenant OAuth 2.1 + OIDC authorization server**

## Features

- ✅ OAuth 2.1 with PKCE (required for all clients)
- ✅ OpenID Connect (OIDC) with discovery, JWKS, ID tokens
- ✅ WebAuthn-only authentication (no passwords!)
- ✅ Multi-tenant by project
- ✅ Flexible token formats: JWT or opaque
- ✅ Named privilege levels per project
- ✅ Comprehensive audit logging with searchable UI
- ✅ Token introspection (RFC 7662) and revocation (RFC 7009)
- ✅ Rate limiting
- ✅ Dedicated OAuth login (separate from portal/admin)
- ✅ User portal for managing projects and security keys
- ✅ Cryptbin encrypted pastebin (filesystem-backed, no accounts)
- ✅ Bootstrap 5 dark UI with charcoal theme
- ✅ PSR-12 compliant PHP 8.2+

## Requirements

- PHP 8.2 or higher
- MySQL 5.7+ or MariaDB 10.3+
- Apache with mod_rewrite
- Composer
- HTTPS (required for WebAuthn)

## Installation

### 1. Clone and Install Dependencies

```bash
cd /home/andy/domains/blackwall.dixon.cx
composer install
```

### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

**Required settings:**

```ini
DB_HOST=localhost
DB_NAME=blackwall
DB_USER=blackwall
DB_PASS=YOUR_SECURE_PASSWORD

APP_URL=https://blackwall.dixon.cx
WEBAUTHN_RP_ID=blackwall.dixon.cx
WEBAUTHN_RP_NAME="BlackWall OAuth"

# Generate with: openssl rand -base64 32
JWT_SIGNING_KEY=GENERATE_RANDOM_KEY
CSRF_SECRET=GENERATE_RANDOM_KEY
CRYPTBIN_KEK_BASE64=GENERATE_RANDOM_KEY

# Cryptbin storage (outside public_html)
CRYPTBIN_STORAGE_PATH=/var/lib/blackwall/cryptbin
```

**⚠️ SECURITY: Rotate the provided password and never commit .env to version control!**

### 3. Create Database

```bash
mysql -u root -p
```

```sql
CREATE DATABASE blackwall CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'blackwall'@'localhost' IDENTIFIED BY 'YOUR_SECURE_PASSWORD';
GRANT ALL PRIVILEGES ON blackwall.* TO 'blackwall'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Run Migrations

```bash
make migrate
# Or manually:
mysql -u blackwall -p blackwall < migrations/001_initial_schema.sql
```

### 5. Bootstrap the System

```bash
make bootstrap
# Or:
php bin/blackwall
```

Follow the prompts to:
1. Create the "BlackWall Admin" project
2. Create the initial admin user
3. Get a bootstrap URL to enrol your WebAuthn credential

**Open the bootstrap URL in your browser and register your security key or platform authenticator.**

### 6. Verify Installation

```bash
make health
```

Visit:
- Homepage: https://blackwall.dixon.cx/
- Cryptbin: https://blackwall.dixon.cx/cryptbin
- User portal: https://blackwall.dixon.cx/portal
- Admin panel: https://blackwall.dixon.cx/admin/login
- OIDC discovery: https://blackwall.dixon.cx/.well-known/openid-configuration

Cryptbin design and deployment notes: `docs/CRYPTBIN.md`

## Architecture

```
blackwall.dixon.cx/
├── bin/               # CLI tools (bootstrap)
├── config/            # Application bootstrap and routes
├── migrations/        # Database schema
├── public_html/       # Web root (DocumentRoot)
│   ├── .htaccess
│   ├── index.php
│   └── assets/        # CSS/JS
├── src/
│   ├── Controller/    # HTTP controllers
│   ├── Service/       # Business logic
│   ├── Repository/    # Database access
│   ├── Model/         # Domain models
│   ├── Security/      # JWT, PKCE, hashing, rate limiting
│   ├── Middleware/    # Correlation ID, IP extraction, audit context
│   └── Domain/        # Value objects
├── templates/         # PHP templates (Bootstrap 5)
├── vendor/            # Composer dependencies
├── .env               # Environment config (NEVER commit)
└── composer.json
```

## Usage

### User Portal

Users can access their portal at `https://blackwall.dixon.cx/portal` to:
- View all projects they have access to
- See their privilege levels in each project
- Add new WebAuthn credentials (security keys)
- Remove unused security keys
- View account information

### Administrator Functions

### Create Users

1. Log in to https://blackwall.dixon.cx/admin
2. Navigate to **Users** → **Create User**
3. Enter display label (e.g., email address or name)
4. User is created without credentials
5. Click on the user to view their detail page
6. Click **Generate Enrollment Link** to create a secure enrollment URL
7. Send the link to the user (expires in 24 hours)
8. User visits the link and enrolls their WebAuthn security key

**Note**: Enrollment links contain only a secure token - no user ID is exposed in the URL.

### View User Details

1. Navigate to **Users** → [Select User]
2. View user information including:
   - UUID and display label
   - Account status (active/disabled)
   - All enrolled WebAuthn credentials
   - Project assignments and privilege levels
   - Timestamp information
3. Actions available:
   - Generate enrollment links for new security keys
   - Delete specific credentials
   - Enable/disable user account
   - View audit logs for the user

### Create a Project

1. Log in to https://blackwall.dixon.cx/admin
2. Navigate to **Projects** → **Create Project**
3. Enter project name (e.g., "My Application")
4. Note the **project UUID** - clients will need this

### Assign Users to Projects

1. **Projects** → [Your Project] → **User Assignments**
2. Add users and select their privilege level (1-10)

### Create an OAuth Client

1. **Projects** → [Your Project] → **OAuth Clients** → **Create**
2. Configure:
   - **Client Name**: "My App"
   - **Redirect URIs**: `https://myapp.example.com/callback` (one per line)
   - **Confidential Client**: Check if server-side app, uncheck for SPA/mobile (uses PKCE)

3. Save the **client_id** (and **client_secret** if confidential - shown only once!)

**Important**: The client_id associates the client with the project automatically.

## OAuth 2.1 Flow

### Authorization Code + PKCE

```
1. Client generates code_verifier and code_challenge (SHA256)

2. Redirect user to:
   GET /oauth/authorize?
       client_id=CLIENT_ID&
       response_type=code&
       redirect_uri=https://myapp.example.com/callback&
       scope=openid%20profile%20email&
       code_challenge=BASE64URL(SHA256(code_verifier))&
       code_challenge_method=S256&
       state=RANDOM_STATE

   Note: project_id is NOT required - it's derived from client_id

3. User sees dedicated OAuth login page (not portal/admin)
   - Shows application name
   - Authenticates with WebAuthn
   - Sees consent screen
   - Approves access

4. Redirect back to client:
   https://myapp.example.com/callback?code=AUTH_CODE&state=STATE

5. Exchange code for tokens:
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&
   code=AUTH_CODE&
   redirect_uri=https://myapp.example.com/callback&
   client_id=CLIENT_ID&
   client_secret=CLIENT_SECRET&  # if confidential
   code_verifier=CODE_VERIFIER

6. Response:
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "...",      # if offline_access requested
     "id_token": "...",           # if OIDC (openid scope)
     "scope": "openid profile email"
   }
```

## Token Claims

### Access Token (JWT format)

```json
{
  "iss": "https://blackwall.dixon.cx",
  "aud": "client_id",
  "sub": "user-uuid",
  "iat": 1234567890,
  "exp": 1234571490,
  "scope": "openid profile email",
  "project_id": "project-uuid",
  "privilege_level": 1
}
```

### ID Token (OIDC)

```json
{
  "iss": "https://blackwall.dixon.cx",
  "aud": "client_id",
  "sub": "user-uuid",
  "iat": 1234567890,
  "exp": 1234571490,
  "nonce": "client-nonce",
  "email": "user@example.com",  # if email scope
  "name": "User Name"            # if profile scope
}
```

### Opaque Token Introspection

```
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=OPAQUE_TOKEN&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET
```

Response:
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client_id",
  "sub": "user-uuid",
  "exp": 1234571490,
  "iss": "https://blackwall.dixon.cx",
  "aud": "client_id",
  "project_id": "project-uuid",
  "privilege_level": 1
}
```

## Client Integration

See `IMPLEMENTATION_PROMPT.md` for comprehensive integration guide.

## Audit Logging

All security and auth events are logged to the `audit_log` table.

### Search Audit Logs

Admin UI: **Audit Log** → Filter by:
- Date range
- Project UUID
- User UUID
- IP address (clickable from dashboard)
- Event type (e.g., `oauth.token.issue`, `webauthn.authentication.fail`)
- Outcome (success/fail/info)
- Correlation ID
**Dashboard Recent Activity**: Click any IP address to filter audit logs by that IP.


### Event Types Logged

- **WebAuthn**: `webauthn.registration.*`, `webauthn.authentication.*`
- **Admin**: `admin.login.*`, `admin.user.*`, `admin.project.*`, `admin.oauth_client.*`
- **Portal**: `portal.login.*`, `portal.key.*`
- **OAuth**: `oauth.authorize.*`, `oauth.token.*`, `oauth.revoke`, `oauth.introspect`
- **OIDC**: `oidc.discovery`, `oidc.userinfo`, `jwks.fetch`
- **Security**: `security.ratelimit.hit`, `security.csrf.fail`

Each log entry includes:
- Correlation ID (for request tracing)
- IP address
- User agent
- Actor (user performing action)
- Project and OAuth client (if applicable)
- WebAuthn credential (if applicable)
- Metadata JSON (scopes, errors, privilege info, etc.)

**Never logs**: raw tokens, raw auth codes, WebAuthn challenges, or private keys.

## Security

### WebAuthn Implementation

BlackWall uses **full COSE cryptographic signature verification**:
- ✅ Challenge validation (prevents replay attacks)
- ✅ Origin validation (prevents phishing)
- ✅ Cryptographic signature verification with COSE
- ✅ Sign counter tracking (detects cloned authenticators)
- ✅ Support for ES256 (ECDSA) and RS256 (RSA)

### Key Rotation

**JWT Signing Keys**: Generate new keys and mark old ones inactive:

```sql
INSERT INTO jwt_signing_keys (kid, private_key, public_key, algorithm, is_active)
VALUES ('new-kid', '...', '...', 'RS256', 1);

UPDATE jwt_signing_keys SET is_active = 0 WHERE kid = 'old-kid';
```

Clients will automatically fetch the new key from `/oauth/jwks`.

### Rate Limiting

Configured in `.env`:
```ini
RATE_LIMIT_ENABLED=true
```

Default limits:
- `/oauth/token`: 60 requests per minute per IP
- `/oauth/authorize`: 30 per minute
- WebAuthn endpoints: 10 per minute

## Troubleshooting

### Bootstrap Token Expired

Manually reset:
```sql
DELETE FROM system_config WHERE config_key IN ('bootstrap_complete', 'bootstrap_token', 'bootstrap_expiry');
```

Then run `make bootstrap` again.

### WebAuthn Not Working

- Ensure HTTPS is active (`https://` not `http://`)
- Verify `WEBAUTHN_RP_ID` matches your domain exactly
- Check browser console for WebAuthn errors
- Security keys must support resident keys/discoverable credentials

### "Missing required environment variables"

Run `make health` to diagnose. Ensure `.env` exists and is readable.

### Database Connection Failed

- Verify credentials in `.env`
- Check MySQL is running: `systemctl status mysql`
- Test connection: `mysql -u blackwall -p blackwall`

## Testing

```bash
# Run PHP CodeSniffer
make cs

# Run tests (when implemented)
make test
```

## Runbook

### Daily Operations

- **Monitor audit logs**: Check for failed authentications, rate limit hits
- **Review OAuth client usage**: Ensure no unexpected clients
- **Rotate credentials**: JWT signing keys every 90 days

### Incident Response

1. **Suspicious activity detected**:
   - Search audit logs by IP/correlation ID
   - Disable affected OAuth client or user
   - Check for unauthorised privilege escalations

2. **Token compromise suspected**:
   - Revoke tokens via `/oauth/revoke`
   - Rotate JWT signing keys
   - Force re-authentication for affected project

### Backup

```bash
# Database
mysqldump -u blackwall -p blackwall > blackwall_backup_$(date +%F).sql

# Environment config
cp .env .env.backup
```

### Restore

```bash
mysql -u blackwall -p blackwall < blackwall_backup_2026-02-04.sql
```

## Licence

Proprietary - BlackWall OAuth 2.1 + OIDC Server

## Support

For issues or questions, contact your system administrator.

---

**BlackWall** - Secure, modern, WebAuthn-only OAuth 2.1 + OpenID Connect


## Features

- ✅ OAuth 2.1 with PKCE (required for all clients)
- ✅ OpenID Connect (OIDC) with discovery, JWKS, ID tokens
- ✅ WebAuthn-only authentication (no passwords!)
- ✅ Multi-tenant by project with UUID-based project_id
- ✅ Flexible token formats: JWT or opaque
- ✅ Named privilege levels per project
- ✅ Comprehensive audit logging with searchable UI
- ✅ Token introspection (RFC 7662) and revocation (RFC 7009)
- ✅ Rate limiting
- ✅ Bootstrap 5 dark UI with charcoal theme
- ✅ PSR-12 compliant PHP 8.2+

## Requirements

- PHP 8.2 or higher
- MySQL 5.7+ or MariaDB 10.3+
- Apache with mod_rewrite
- Composer
- HTTPS (required for WebAuthn)

## Installation

### 1. Clone and Install Dependencies

```bash
cd /home/andy/domains/blackwall.dixon.cx
composer install
```

### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

**Required settings:**

```ini
DB_HOST=localhost
DB_NAME=blackwall
DB_USER=blackwall
DB_PASS=YOUR_SECURE_PASSWORD

APP_URL=https://blackwall.dixon.cx
WEBAUTHN_RP_ID=blackwall.dixon.cx
WEBAUTHN_RP_NAME="BlackWall OAuth"

# Generate with: openssl rand -base64 32
JWT_SIGNING_KEY=GENERATE_RANDOM_KEY
CSRF_SECRET=GENERATE_RANDOM_KEY
```

**⚠️ SECURITY: Rotate the provided password and never commit .env to version control!**

### 3. Create Database

```bash
mysql -u root -p
```

```sql
CREATE DATABASE blackwall CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'blackwall'@'localhost' IDENTIFIED BY 'YOUR_SECURE_PASSWORD';
GRANT ALL PRIVILEGES ON blackwall.* TO 'blackwall'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Run Migrations

```bash
make migrate
# Or manually:
mysql -u blackwall -p blackwall < migrations/001_initial_schema.sql
```

### 5. Bootstrap the System

```bash
make bootstrap
# Or:
php bin/blackwall
```

Follow the prompts to:
1. Create the "BlackWall Admin" project
2. Create the initial admin user
3. Get a bootstrap URL to enroll your WebAuthn credential

**Open the bootstrap URL in your browser and register your security key or platform authenticator.**

### 6. Verify Installation

```bash
make health
```

Visit:
- Admin panel: https://blackwall.dixon.cx/admin/login
- OIDC discovery: https://blackwall.dixon.cx/.well-known/openid-configuration

## Architecture

```
blackwall.dixon.cx/
├── bin/               # CLI tools (bootstrap)
├── config/            # Application bootstrap and routes
├── migrations/        # Database schema
├── public_html/       # Web root (DocumentRoot)
│   ├── .htaccess
│   ├── index.php
│   └── assets/        # CSS/JS
├── src/
│   ├── Controller/    # HTTP controllers
│   ├── Service/       # Business logic
│   ├── Repository/    # Database access
│   ├── Model/         # Domain models
│   ├── Security/      # JWT, PKCE, hashing, rate limiting
│   ├── Middleware/    # Correlation ID, IP extraction, audit context
│   └── Domain/        # Value objects
├── templates/         # PHP templates (Bootstrap 5)
├── vendor/            # Composer dependencies
├── .env               # Environment config (NEVER commit)
└── composer.json
```

## Usage

### Create a Project

1. Log in to https://blackwall.dixon.cx/admin
2. Navigate to **Projects** → **Create Project**
3. Enter project name (e.g., "My Application")
4. Note the **project UUID** - clients will need this

### Define Privilege Levels

1. Go to **Projects** → [Your Project] → **Privilege Levels**
2. Create levels:
   - Level 1: "Owner" (admin access)
   - Level 2: "User" (standard access)
   - Level 3: "Read-only" (limited access)

### Assign Users to Projects

1. **Projects** → [Your Project] → **User Assignments**
2. Add users and select their privilege level by name

### Create an OAuth Client

1. **Projects** → [Your Project] → **OAuth Clients** → **Create**
2. Configure:
   - **Client Name**: "My App"
   - **Redirect URIs**: `https://myapp.example.com/callback`
   - **Token Type**: JWT or Opaque
   - **OIDC Enabled**: Yes/No
   - **Scopes**: `openid profile email offline_access`

3. Save the **client_id** and **client_secret** (if confidential)

## OAuth 2.1 Flow

### Authorization Code + PKCE

```
1. Client generates code_verifier and code_challenge (SHA256)

2. Redirect user to:
   GET /oauth/authorize?
       client_id=CLIENT_ID&
       response_type=code&
       redirect_uri=https://myapp.example.com/callback&
       scope=openid%20profile%20email%20offline_access&
       code_challenge=BASE64URL(SHA256(code_verifier))&
       code_challenge_method=S256&
       project_id=PROJECT_UUID&
       state=RANDOM_STATE&
       nonce=RANDOM_NONCE

3. User authenticates (WebAuthn) and approves

4. Redirect back to client:
   https://myapp.example.com/callback?code=AUTH_CODE&state=STATE

5. Exchange code for tokens:
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&
   code=AUTH_CODE&
   redirect_uri=https://myapp.example.com/callback&
   client_id=CLIENT_ID&
   client_secret=CLIENT_SECRET&  # if confidential
   code_verifier=CODE_VERIFIER

6. Response (JWT mode):
   {
     "access_token": "eyJ...",    # JWT with claims
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "...",      # if offline_access requested
     "id_token": "eyJ...",        # if OIDC (openid scope)
     "scope": "openid profile email offline_access"
   }
```

## Token Claims

### JWT Access Token

```json
{
  "iss": "https://blackwall.dixon.cx",
  "aud": "client_id",
  "sub": "user-uuid",
  "iat": 1234567890,
  "exp": 1234571490,
  "scope": "openid profile email",
  "project_id": "project-uuid",
  "privilege_level": 1,
  "privilege_name": "Owner"
}
```

### ID Token (OIDC)

```json
{
  "iss": "https://blackwall.dixon.cx",
  "aud": "client_id",
  "sub": "user-uuid",
  "iat": 1234567890,
  "exp": 1234571490,
  "nonce": "client-nonce",
  "email": "user@example.com",  # if email scope
  "name": "User Name"            # if profile scope
}
```

### Opaque Token Introspection

```
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=OPAQUE_TOKEN&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET
```

Response:
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client_id",
  "sub": "user-uuid",
  "exp": 1234571490,
  "iss": "https://blackwall.dixon.cx",
  "aud": "client_id",
  "project_id": "project-uuid",
  "privilege_level": 1,
  "privilege_name": "Owner"
}
```

## Client Integration

### Validating JWT Access Tokens

```php
// 1. Download JWKS
$jwks = file_get_contents('https://blackwall.dixon.cx/oauth/jwks');

// 2. Parse and verify JWT
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

$config = Configuration::forAsymmetricSigner(
    new Sha256(),
    InMemory::plainText('not-used'),
    InMemory::plainText($publicKeyPem) // from JWKS
);

$token = $config->parser()->parse($jwtString);

// 3. Validate
$constraints = [
    new \Lcobucci\JWT\Validation\Constraint\IssuedBy('https://blackwall.dixon.cx'),
    new \Lcobucci\JWT\Validation\Constraint\PermittedFor('your-client-id'),
    new \Lcobucci\JWT\Validation\Constraint\ValidAt(new SystemClock(new DateTimeZone('UTC'))),
];

if (!$config->validator()->validate($token, ...$constraints)) {
    throw new Exception('Invalid token');
}

// 4. Extract claims
$projectId = $token->claims()->get('project_id');
$privilegeLevel = $token->claims()->get('privilege_level');
$privilegeName = $token->claims()->get('privilege_name');
$userUuid = $token->claims()->get('sub');

// 5. Enforce authorization
if ($privilegeLevel > 2) {
    throw new Exception('Insufficient privileges');
}
```

### Example Middleware (PHP)

```php
class BlackWallAuthMiddleware
{
    public function handle($request, $next)
    {
        $authHeader = $request->header('Authorization');
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $token = substr($authHeader, 7);

        // For JWT: validate locally
        $claims = $this->validateJWT($token);

        // For Opaque: call introspection
        // $claims = $this->introspectToken($token);

        if (!$claims || $claims['project_id'] !== config('blackwall.project_id')) {
            return response()->json(['error' => 'Invalid project'], 403);
        }

        $request->attributes->set('user_uuid', $claims['sub']);
        $request->attributes->set('privilege_level', $claims['privilege_level']);
        $request->attributes->set('privilege_name', $claims['privilege_name']);

        return $next($request);
    }
}
```

## Audit Logging

All security and auth events are logged to the `audit_log` table.

### Search Audit Logs

Admin UI: **Audit Log** → Filter by:
- Date range
- Project UUID
- User UUID
- IP address
- Event type (e.g., `oauth.token.issue`, `webauthn.authentication.fail`)
**Dashboard Recent Activity**: Click any IP address to filter audit logs by that IP.

- Outcome (success/fail/info)
- Correlation ID

### Event Types Logged

- **WebAuthn**: `webauthn.registration.*`, `webauthn.authentication.*`
- **Admin**: `admin.login.*`, `admin.user.*`, `admin.project.*`, `admin.oauth_client.*`
- **OAuth**: `oauth.authorize.*`, `oauth.token.*`, `oauth.revoke`, `oauth.introspect`
- **OIDC**: `oidc.discovery`, `oidc.userinfo`, `jwks.fetch`
- **Security**: `security.ratelimit.hit`, `security.csrf.fail`

Each log entry includes:
- Correlation ID (for request tracing)
- IP address
- User agent
- Actor (user performing action)
- Project and OAuth client (if applicable)
- WebAuthn credential (if applicable)
- Metadata JSON (scopes, errors, privilege info, etc.)

**Never logs**: raw tokens, raw auth codes, WebAuthn challenges, or private keys.

## Security

### Dotenv and Environment Variables

**Apache/FPM Caveat**: By default, PHP-FPM may not pass environment variables from the shell.

If `Config::get()` throws "not found" errors:

1. **Check FPM config** (`/etc/php/8.2/fpm/pool.d/www.conf`):
   ```ini
   clear_env = no
   ```

2. **Check `php.ini`** (`variables_order`):
   ```ini
   variables_order = "EGPCS"
   ```

3. **Verify** with health check:
   ```bash
   make health
   ```

### Key Rotation

**JWT Signing Keys**: Generate new keys and mark old ones inactive:

```sql
INSERT INTO jwt_signing_keys (kid, private_key, public_key, algorithm, is_active)
VALUES ('new-kid', '...', '...', 'RS256', 1);

UPDATE jwt_signing_keys SET is_active = 0 WHERE kid = 'old-kid';
```

Clients will automatically fetch the new key from `/oauth/jwks`.

### Rate Limiting

Configured in `.env`:
```ini
RATE_LIMIT_ENABLED=true
```

Default limits:
- `/oauth/token`: 60 requests per minute per IP
- `/oauth/authorize`: 30 per minute
- WebAuthn endpoints: 10 per minute

### Content Security Policy

Add to Apache vhost or `.htaccess`:
```apache
Header set Content-Security-Policy "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"
```

## Apache Configuration

Example vhost for `blackwall.dixon.cx`:

```apache
<VirtualHost *:443>
    ServerName blackwall.dixon.cx
    DocumentRoot /home/andy/domains/blackwall.dixon.cx/public_html

    SSLEngine on
    SSLCertificateFile /path/to/fullchain.pem
    SSLCertificateKeyFile /path/to/privkey.pem

    <Directory /home/andy/domains/blackwall.dixon.cx/public_html>
        AllowOverride All
        Require all granted
    </Directory>

    # Pass environment variables (if using .env in shell)
    # SetEnv APP_ENV production

    ErrorLog /home/andy/domains/blackwall.dixon.cx/logs/error.log
    CustomLog /home/andy/domains/blackwall.dixon.cx/logs/access.log combined
</VirtualHost>
```

## Troubleshooting

### Bootstrap Token Expired

Manually reset:
```sql
DELETE FROM system_config WHERE config_key IN ('bootstrap_complete', 'bootstrap_token', 'bootstrap_expiry');
```

Then run `make bootstrap` again.

### WebAuthn Not Working

- Ensure HTTPS is active (`https://` not `http://`)
- Verify `WEBAUTHN_RP_ID` matches your domain exactly
- Check browser console for WebAuthn errors

### "Missing required environment variables"

Run `make health` to diagnose. Ensure `.env` exists and is readable.

### Database Connection Failed

- Verify credentials in `.env`
- Check MySQL is running: `systemctl status mysql`
- Test connection: `mysql -u blackwall -p blackwall`

## Testing

```bash
# Run PHP CodeSniffer
make cs

# Run tests (when implemented)
make test
```

## Runbook

### Daily Operations

- **Monitor audit logs**: Check for failed authentications, rate limit hits
- **Review OAuth client usage**: Ensure no unexpected clients
- **Rotate credentials**: JWT signing keys every 90 days

### Incident Response

1. **Suspicious activity detected**:
   - Search audit logs by IP/correlation ID
   - Disable affected OAuth client or user
   - Check for unauthorized privilege escalations

2. **Token compromise suspected**:
   - Revoke tokens via `/oauth/revoke`
   - Rotate JWT signing keys
   - Force re-authentication for affected project

### Backup

```bash
# Database
mysqldump -u blackwall -p blackwall > blackwall_backup_$(date +%F).sql

# Environment config
cp .env .env.backup
```

### Restore

```bash
mysql -u blackwall -p blackwall < blackwall_backup_2026-02-04.sql
```

## License

Proprietary - BlackWall OAuth 2.1 + OIDC Server

## Support

For issues or questions, contact your system administrator.

---

**BlackWall** - Secure, modern, WebAuthn-only OAuth 2.1 + OpenID Connect
