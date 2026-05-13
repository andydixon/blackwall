# BlackWall Client Integration Guide

This guide shows how to integrate your application with BlackWall OAuth 2.1 + OIDC.

## Overview

BlackWall issues tokens with three critical claims:

- `project_id` (UUID): Identifies which project the user is accessing
- `privilege_level` (integer): Numeric privilege (1=highest/admin, 2=user, 3+=custom)
- `privilege_name` (string): Human-readable privilege name (e.g., "Owner", "Admin", "User")

Your application **must** validate the `project_id` matches your registered project and enforce authorization based on `privilege_level`.

## Prerequisites

1. Administrator creates your project in BlackWall
2. Administrator creates an OAuth client for your project
3. You receive:
   - `client_id`
   - `client_secret` (if confidential client)
   - `project_id` (UUID)
   - Redirect URI(s)

## Token Formats

BlackWall supports two token formats:

### JWT Access Tokens (Recommended)

- Self-contained, signed tokens
- Validate locally without calling BlackWall
- Faster, reduces load on auth server

### Opaque Access Tokens

- Random strings stored in database
- Require introspection endpoint call
- Use if you need real-time revocation checks

## Authorization Code Flow with PKCE

### Step 1: Generate PKCE Parameters

```php
// Generate code verifier (43-128 characters, base64url)
$codeVerifier = bin2hex(random_bytes(32));

// Generate code challenge (SHA256 + base64url)
$codeChallenge = rtrim(strtr(base64_encode(
    hash('sha256', $codeVerifier, true)
), '+/', '-_'), '=');
```

### Step 2: Redirect User to Authorization Endpoint

```php
$authUrl = 'https://blackwall.cx/oauth/authorize?' . http_build_query([
    'client_id' => 'YOUR_CLIENT_ID',
    'response_type' => 'code',
    'redirect_uri' => 'https://yourapp.com/callback',
    'scope' => 'openid profile email offline_access',
    'code_challenge' => $codeChallenge,
    'code_challenge_method' => 'S256',
    'project_id' => 'YOUR_PROJECT_UUID',
    'state' => bin2hex(random_bytes(16)), // CSRF protection
    'nonce' => bin2hex(random_bytes(16)), // OIDC replay protection
]);

// Store code_verifier and state in session
$_SESSION['oauth_code_verifier'] = $codeVerifier;
$_SESSION['oauth_state'] = $state;

header('Location: ' . $authUrl);
exit;
```

### Step 3: Handle Callback

```php
// Verify state (CSRF protection)
if ($_GET['state'] !== $_SESSION['oauth_state']) {
    die('Invalid state');
}

$code = $_GET['code'];
$codeVerifier = $_SESSION['oauth_code_verifier'];

// Exchange code for tokens
$tokenResponse = file_get_contents('https://blackwall.cx/oauth/token', false, stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => 'Content-Type: application/x-www-form-urlencoded',
        'content' => http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://yourapp.com/callback',
            'client_id' => 'YOUR_CLIENT_ID',
            'client_secret' => 'YOUR_CLIENT_SECRET', // if confidential
            'code_verifier' => $codeVerifier,
        ]),
    ],
]));

$tokens = json_decode($tokenResponse, true);

// Store tokens securely
$_SESSION['access_token'] = $tokens['access_token'];
$_SESSION['refresh_token'] = $tokens['refresh_token'] ?? null;
$_SESSION['id_token'] = $tokens['id_token'] ?? null;
```

## Validating JWT Access Tokens

### Option 1: Using lcobucci/jwt (Recommended)

```php
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\Clock\SystemClock;

// Download and cache JWKS
$jwks = json_decode(file_get_contents('https://blackwall.cx/oauth/jwks'), true);

// Extract public key for the token's kid
$publicKeyPem = $this->getPublicKeyFromJWKS($jwks, $kid);

$config = Configuration::forAsymmetricSigner(
    new Sha256(),
    InMemory::plainText('not-used'),
    InMemory::plainText($publicKeyPem)
);

// Parse token
$token = $config->parser()->parse($_SESSION['access_token']);

// Validate
$constraints = [
    new IssuedBy('https://blackwall.cx'),
    new PermittedFor('YOUR_CLIENT_ID'),
    new ValidAt(new SystemClock(new \DateTimeZone('UTC'))),
];

if (!$config->validator()->validate($token, ...$constraints)) {
    throw new \Exception('Invalid token');
}

// Extract claims
$projectId = $token->claims()->get('project_id');
$privilegeLevel = $token->claims()->get('privilege_level');
$privilegeName = $token->claims()->get('privilege_name');
$userUuid = $token->claims()->get('sub');
$scopes = explode(' ', $token->claims()->get('scope'));

// Enforce project
if ($projectId !== 'YOUR_PROJECT_UUID') {
    throw new \Exception('Token not valid for this project');
}

// Enforce privilege
if ($privilegeLevel > 2) { // Only admin and user
    throw new \Exception('Insufficient privileges');
}
```

### Helper: Extract Public Key from JWKS

```php
private function getPublicKeyFromJWKS(array $jwks, string $kid): string
{
    foreach ($jwks['keys'] as $key) {
        if ($key['kid'] === $kid) {
            // Convert JWK to PEM
            $n = $this->base64UrlDecode($key['n']);
            $e = $this->base64UrlDecode($key['e']);
            
            // Use phpseclib or similar to convert n,e to PEM
            // For simplicity, cache and download PEM directly if possible
            
            return $publicKeyPem;
        }
    }
    throw new \Exception('Key not found in JWKS');
}

private function base64UrlDecode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}
```

## Validating Opaque Access Tokens

```php
$introspectionResponse = file_get_contents('https://blackwall.cx/oauth/introspect', false, stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => 'Content-Type: application/x-www-form-urlencoded',
        'content' => http_build_query([
            'token' => $_SESSION['access_token'],
            'client_id' => 'YOUR_CLIENT_ID',
            'client_secret' => 'YOUR_CLIENT_SECRET',
        ]),
    ],
]));

$introspection = json_decode($introspectionResponse, true);

if (!$introspection['active']) {
    throw new \Exception('Token not active');
}

$projectId = $introspection['project_id'];
$privilegeLevel = $introspection['privilege_level'];
$privilegeName = $introspection['privilege_name'];
$userUuid = $introspection['sub'];

// Enforce project and privilege
if ($projectId !== 'YOUR_PROJECT_UUID') {
    throw new \Exception('Invalid project');
}

if ($privilegeLevel > 2) {
    throw new \Exception('Insufficient privileges');
}
```

## Middleware Example

```php
namespace App\Middleware;

class BlackWallAuthMiddleware
{
    private string $projectId;
    private int $minPrivilegeLevel;

    public function __construct(string $projectId, int $minPrivilegeLevel = 2)
    {
        $this->projectId = $projectId;
        $this->minPrivilegeLevel = $minPrivilegeLevel;
    }

    public function __invoke($request, $handler)
    {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return $this->errorResponse('Missing Authorization header', 401);
        }

        $token = substr($authHeader, 7);

        try {
            $claims = $this->validateJWT($token); // or introspectOpaque($token)

            // Enforce project
            if ($claims['project_id'] !== $this->projectId) {
                return $this->errorResponse('Invalid project', 403);
            }

            // Enforce privilege
            if ($claims['privilege_level'] > $this->minPrivilegeLevel) {
                return $this->errorResponse('Insufficient privileges', 403);
            }

            // Attach user info to request
            $request = $request->withAttribute('user_uuid', $claims['sub']);
            $request = $request->withAttribute('privilege_level', $claims['privilege_level']);
            $request = $request->withAttribute('privilege_name', $claims['privilege_name']);

            return $handler->handle($request);

        } catch (\Exception $e) {
            return $this->errorResponse($e->getMessage(), 401);
        }
    }

    private function validateJWT(string $token): array
    {
        // Implement JWT validation as shown above
        // Return claims array
    }

    private function errorResponse(string $message, int $status): ResponseInterface
    {
        $response = new Response();
        $response->getBody()->write(json_encode(['error' => $message]));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
```

## Privilege Enforcement Patterns

### Level-Based

```php
// Admin only (level 1)
if ($privilegeLevel > 1) {
    throw new ForbiddenException('Admin required');
}

// Admin or User (level 1-2)
if ($privilegeLevel > 2) {
    throw new ForbiddenException('Insufficient privileges');
}
```

### Name-Based

```php
$allowedRoles = ['Owner', 'Admin'];
if (!in_array($privilegeName, $allowedRoles)) {
    throw new ForbiddenException('Not authorized');
}
```

### Route-Specific

```php
// Admin panel routes
$app->group('/admin', function ($group) {
    // Requires privilege_level = 1
})->add(new BlackWallAuthMiddleware($projectId, 1));

// API routes
$app->group('/api', function ($group) {
    // Requires privilege_level <= 2 (Admin or User)
})->add(new BlackWallAuthMiddleware($projectId, 2));

// Public data routes
$app->group('/public', function ($group) {
    // Requires any valid token
})->add(new BlackWallAuthMiddleware($projectId, 999));
```

## Refresh Tokens

```php
if (isTokenExpired($_SESSION['access_token'])) {
    $refreshResponse = file_get_contents('https://blackwall.cx/oauth/token', false, stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/x-www-form-urlencoded',
            'content' => http_build_query([
                'grant_type' => 'refresh_token',
                'refresh_token' => $_SESSION['refresh_token'],
                'client_id' => 'YOUR_CLIENT_ID',
                'client_secret' => 'YOUR_CLIENT_SECRET',
            ]),
        ],
    ]));

    $tokens = json_decode($refreshResponse, true);
    $_SESSION['access_token'] = $tokens['access_token'];
    $_SESSION['refresh_token'] = $tokens['refresh_token'] ?? $_SESSION['refresh_token'];
}
```

## Logout

```php
// Revoke tokens
file_get_contents('https://blackwall.cx/oauth/revoke', false, stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => 'Content-Type: application/x-www-form-urlencoded',
        'content' => http_build_query([
            'token' => $_SESSION['access_token'],
            'client_id' => 'YOUR_CLIENT_ID',
            'client_secret' => 'YOUR_CLIENT_SECRET',
        ]),
    ],
]));

// Clear session
session_destroy();
header('Location: /');
```

## OIDC UserInfo Endpoint

```php
$userInfo = file_get_contents('https://blackwall.cx/oauth/userinfo', false, stream_context_create([
    'http' => [
        'header' => 'Authorization: Bearer ' . $_SESSION['access_token'],
    ],
]));

$user = json_decode($userInfo, true);
// { "sub": "user-uuid", "email": "user@example.com", "name": "User Name" }
```

## Best Practices

1. **Always validate project_id**: Prevent cross-project token misuse
2. **Cache JWKS**: Download once, cache for 24 hours, refresh on validation failure
3. **Use HTTPS everywhere**: WebAuthn and OAuth require TLS
4. **Validate state parameter**: Prevent CSRF
5. **Validate nonce in ID token**: Prevent replay (OIDC)
6. **Store tokens securely**: Use httpOnly session cookies, never localStorage
7. **Implement token refresh**: Don't force re-login on expiry
8. **Log authorization failures**: Monitor suspicious activity

## Example: Full Integration (Slim Framework)

```php
use Slim\Factory\AppFactory;
use App\Middleware\BlackWallAuthMiddleware;

$app = AppFactory::create();

// Public route (no auth)
$app->get('/', function ($request, $response) {
    $response->getBody()->write('Public homepage');
    return $response;
});

// OAuth callback
$app->get('/oauth/callback', function ($request, $response) {
    // Handle authorization code exchange (see Step 3 above)
    return $response->withHeader('Location', '/dashboard')->withStatus(302);
});

// Protected routes
$app->group('/dashboard', function ($group) {
    $group->get('', function ($request, $response) {
        $userUuid = $request->getAttribute('user_uuid');
        $privilegeName = $request->getAttribute('privilege_name');
        
        $response->getBody()->write("Welcome, user {$userUuid} ({$privilegeName})");
        return $response;
    });
})->add(new BlackWallAuthMiddleware('YOUR_PROJECT_UUID', 2));

// Admin-only routes
$app->group('/admin', function ($group) {
    $group->get('/users', function ($request, $response) {
        $response->getBody()->write('Admin: User management');
        return $response;
    });
})->add(new BlackWallAuthMiddleware('YOUR_PROJECT_UUID', 1));

$app->run();
```

## Troubleshooting

### "Invalid project" error

- Verify `project_id` in authorize URL matches your registered project UUID
- Check token claims contain correct `project_id`

### "Insufficient privileges" error

- Verify user is assigned to project in BlackWall admin
- Check `privilege_level` in token matches your requirements

### JWT validation fails

- Ensure JWKS is fresh (re-download on validation error)
- Check `iss` matches `https://blackwall.cx` exactly
- Verify `aud` matches your `client_id`
- Check system clock is synchronized (JWT exp/iat validation)

### PKCE validation fails

- Ensure `code_verifier` matches the one used to generate `code_challenge`
- Verify `code_challenge_method` is `S256`
- Check code verifier is 43-128 characters

---

**Need help?** Contact your BlackWall administrator.
