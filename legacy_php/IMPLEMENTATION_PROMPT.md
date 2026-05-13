# BlackWall OAuth 2.1 / OpenID Connect Integration Guide

## System Overview

BlackWall is a WebAuthn-secured OAuth 2.1 and OpenID Connect (OIDC) authentication provider that enables passwordless authentication for your applications. This document provides AI assistants with context to help you integrate BlackWall into your application.

## What is BlackWall?

BlackWall is an OAuth 2.1 / OIDC server that provides:
- **Passwordless Authentication**: Users authenticate using WebAuthn (security keys, passkeys, biometrics)
- **OAuth 2.1 Authorisation**: Standard OAuth flows with PKCE
- **OpenID Connect**: User identity and profile information
- **Multi-Project Support**: Isolate users and clients per project
- **Privilege Levels**: Fine-grained authorisation levels (1-10)
- **Comprehensive Audit Logging**: Track all authentication and authorisation events

## Server Information

**Base URL**: `https://blackwall.cx`

**Discovery Endpoint**: `https://blackwall.cx/.well-known/openid-configuration`

**Key Endpoints**:
- Authorisation: `https://blackwall.cx/oauth/authorize`
- Token: `https://blackwall.cx/oauth/token`
- UserInfo: `https://blackwall.cx/oauth/userinfo`
- JWKS: `https://blackwall.cx/oauth/jwks`
- Token Revocation: `https://blackwall.cx/oauth/revoke`
- Token Introspection: `https://blackwall.cx/oauth/introspect`

## Supported Features

### OAuth 2.1 Flows
- ✅ Authorisation Code Flow with PKCE (required)
- ✅ Client Credentials Flow
- ✅ Token refresh
- ✅ Token revocation
- ✅ Token introspection

### OpenID Connect
- ✅ Discovery (`.well-known/openid-configuration`)
- ✅ UserInfo endpoint
- ✅ ID Tokens (JWT)
- ✅ JWKS key rotation support

### Grant Types
- `authorisation_code` - For user authentication (with PKCE)
- `refresh_token` - For token renewal
- `client_credentials` - For service-to-service

### Response Types
- `code` - Authorisation code (standard flow)

### Scopes
- `openid` - Required for OIDC
- `profile` - User profile information (name, preferred_username)
- `email` - User email address (if available)
- `offline_access` - Request refresh token

### Token Types
- **Access Tokens**: Bearer tokens (opaque), 1 hour lifetime
- **Refresh Tokens**: 30 days lifetime
- **ID Tokens**: JWT signed with RS256

## Integration Patterns

### Pattern 1: Web Application with User Login

**Use Case**: Your web app needs users to authenticate via BlackWall

**Flow**: Authorisation Code + PKCE

**Steps**:
1. Register OAuth client in BlackWall admin panel
2. Configure redirect URI (must be exact match)
3. Implement OAuth 2.1 authorisation code flow with PKCE
4. Exchange code for tokens
5. Use access token to fetch user info
6. Store user session in your application

**Example Libraries**:
- Node.js: `passport-oauth2`, `openid-client`
- Python: `authlib`, `python-oauth2`
- PHP: `league/oauth2-client`
- Go: `golang.org/x/oauth2`

### Pattern 2: API Authentication

**Use Case**: Your API needs to verify tokens from BlackWall

**Flow**: Bearer token validation

**Steps**:
1. Extract bearer token from `Authorisation` header
2. Validate token via introspection endpoint
3. Check token is active and has required scopes
4. Use token metadata for authorisation decisions

### Pattern 3: Service-to-Service Authentication

**Use Case**: Your backend service needs to call another service

**Flow**: Client Credentials

**Steps**:
1. Register service client in BlackWall
2. Use client credentials grant to obtain access token
3. Include token in API requests
4. Receiving service validates token

## OAuth Client Registration

### Client Types

**Public Clients** (Web/Mobile Apps):
- Cannot securely store secrets
- Must use PKCE
- Example: Single-Page Apps, Mobile Apps

**Confidential Clients** (Server Apps):
- Can securely store secrets
- Should use PKCE (recommended)
- Example: Traditional web apps, backend services

### Required Information

When creating an OAuth client in BlackWall, you need:

- **Client Name**: Human-readable identifier
- **Redirect URIs**: Exact URLs where users will be redirected (comma-separated)
- **Client Type**: `public` or `confidential`
- **Grant Types**: What flows are allowed
- **Scopes**: What data the client can access
- **Project**: Which project this client belongs to

### Security Considerations

1. **Always use PKCE** - Even for confidential clients
2. **Exact redirect URI matching** - No wildcards
3. **Use HTTPS** - Required for production
4. **Short-lived tokens** - Access tokens expire in 1 hour
5. **Rotate refresh tokens** - New refresh token issued on each use
6. **Store client secrets securely** - Never commit to version control

## Implementation Examples

### Authorisation Code Flow with PKCE

#### Step 1: Generate PKCE Challenge

```javascript
// Generate code verifier (random string)
const codeVerifier = generateRandomString(128);

// Generate code challenge (SHA256 hash)
const codeChallenge = base64UrlEncode(
  sha256(codeVerifier)
);
```

#### Step 2: Redirect to Authorisation Endpoint

```
https://blackwall.cx/oauth/authorize?
  response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://yourapp.com/callback
  &scope=openid profile email
  &state=RANDOM_STATE_STRING
  &code_challenge=CODE_CHALLENGE
  &code_challenge_method=S256
```

#### Step 3: Handle Callback

```javascript
// Extract authorisation code from callback
const code = req.query.code;
const state = req.query.state;

// Verify state matches to prevent CSRF
if (state !== sessionState) {
  throw new Error('Invalid state');
}
```

#### Step 4: Exchange Code for Tokens

```javascript
const response = await fetch('https://blackwall.cx/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorisation_code',
    code: code,
    redirect_uri: 'https://yourapp.com/callback',
    client_id: 'YOUR_CLIENT_ID',
    code_verifier: codeVerifier, // From Step 1
    // client_secret: 'SECRET' // Only for confidential clients
  })
});

const tokens = await response.json();
// {
//   access_token: "...",
//   token_type: "Bearer",
//   expires_in: 3600,
//   refresh_token: "...",
//   id_token: "...",
//   scope: "openid profile email"
// }
```

#### Step 5: Fetch User Information

```javascript
const userInfoResponse = await fetch('https://blackwall.cx/oauth/userinfo', {
  headers: {
    'Authorisation': `Bearer ${tokens.access_token}`
  }
});

const userInfo = await userInfoResponse.json();
// {
//   sub: "user-uuid-here",
//   name: "User Display Name",
//   preferred_username: "username",
//   email: "user@example.com",
//   email_verified: true
// }
```

### Token Validation (API Side)

#### Option 1: Introspection (Recommended)

```javascript
const response = await fetch('https://blackwall.cx/oauth/introspect', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorisation': 'Basic ' + base64Encode(clientId + ':' + clientSecret)
  },
  body: new URLSearchParams({
    token: accessToken
  })
});

const introspection = await response.json();
if (introspection.active) {
  // Token is valid
  const userId = introspection.sub;
  const scopes = introspection.scope.split(' ');
  // Check authorisation...
}
```

#### Option 2: UserInfo Endpoint

```javascript
// Let BlackWall validate the token
const response = await fetch('https://blackwall.cx/oauth/userinfo', {
  headers: { 'Authorisation': `Bearer ${accessToken}` }
});

if (response.ok) {
  const user = await response.json();
  // Token is valid, user authenticated
} else if (response.status === 401) {
  // Token invalid or expired
}
```

### Refresh Token Flow

```javascript
const response = await fetch('https://blackwall.cx/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: 'YOUR_CLIENT_ID',
    // client_secret: 'SECRET' // For confidential clients
  })
});

const tokens = await response.json();
// New access_token and refresh_token
```

### Token Revocation

```javascript
await fetch('https://blackwall.cx/oauth/revoke', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorisation': 'Basic ' + base64Encode(clientId + ':' + clientSecret)
  },
  body: new URLSearchParams({
    token: accessToken,
    token_type_hint: 'access_token' // or 'refresh_token'
  })
});
```

## User Data Structure

### UserInfo Response

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "name": "John Doe",
  "preferred_username": "john.doe@example.com",
  "email": "john.doe@example.com",
  "email_verified": true
}
```

### ID Token Claims

```json
{
  "iss": "https://blackwall.cx",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "your-client-id",
  "exp": 1234567890,
  "iat": 1234564290,
  "name": "John Doe",
  "preferred_username": "john.doe@example.com",
  "email": "john.doe@example.com",
  "email_verified": true
}
```

### Token Introspection Response

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "your-client-id",
  "token_type": "Bearer",
  "exp": 1234567890,
  "iat": 1234564290,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "your-client-id",
  "iss": "https://blackwall.cx"
}
```

## Error Handling

### OAuth Error Responses

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: redirect_uri"
}
```

### Common Error Codes

- `invalid_request` - Missing or invalid parameters
- `invalid_client` - Client authentication failed
- `invalid_grant` - Authorisation code/refresh token invalid or expired
- `unauthorised_client` - Client not authorized for requested grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Requested scope invalid or exceeds allowed
- `access_denied` - User denied authorisation

### HTTP Status Codes

- `200` - Success
- `400` - Bad Request (invalid parameters)
- `401` - Unauthorised (invalid client credentials or token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found (invalid endpoint)
- `500` - Server Error

## Testing Your Integration

### 1. Test Authorisation Flow

1. Visit authorisation URL in browser
2. Should redirect to BlackWall login
3. Authenticate with WebAuthn (security key)
4. Grant permissions
5. Should redirect back with authorisation code

### 2. Test Token Exchange

1. Exchange code for tokens
2. Verify access_token, refresh_token, and id_token are present
3. Verify expires_in is 3600 (1 hour)

### 3. Test UserInfo

1. Call UserInfo endpoint with access token
2. Verify user data returned
3. Test with expired token (should get 401)

### 4. Test Token Refresh

1. Use refresh_token to get new tokens
2. Verify old refresh_token is invalidated
3. Test with expired refresh_token (should fail)

### 5. Test Logout

1. Revoke tokens when user logs out
2. Verify tokens no longer work after revocation

## Privilege Levels

BlackWall supports privilege levels 1-10 for fine-grained authorisation:

- Stored in token metadata
- Available via introspection
- Your application defines what each level means
- Example: Level 1 = Admin, Level 2 = User, Level 3 = Guest

Access privilege information:
1. Use token introspection endpoint
2. Check custom claims in response
3. Make authorisation decisions in your app

## Database Schema (For Reference)

BlackWall uses the following key tables:

- `users` - User accounts
- `projects` - Isolated application projects
- `oauth_clients` - OAuth client registrations
- `oauth_access_tokens` - Active access tokens
- `oauth_refresh_tokens` - Active refresh tokens
- `oauth_authorisation_codes` - Temporary authorisation codes
- `user_project_roles` - User-to-project assignments with privilege levels
- `webauthn_credentials` - WebAuthn security keys
- `audit_log` - Comprehensive audit trail

## Common Integration Scenarios

### Scenario 1: Single-Page Application (React, Vue, Angular)

**Requirements**:
- Public client (no secret)
- Authorisation Code + PKCE
- Silent token refresh

**Recommendations**:
- Use OIDC library (e.g., `oidc-client-ts`)
- Store tokens in memory (not localStorage)
- Use iframe for silent refresh
- Implement token refresh before expiry

### Scenario 2: Traditional Web Application (PHP, Node, Python)

**Requirements**:
- Confidential client (has secret)
- Authorisation Code + PKCE
- Server-side session

**Recommendations**:
- Use OAuth2 library for your language
- Store tokens in encrypted session
- Refresh tokens automatically
- Implement logout with revocation

### Scenario 3: Mobile Application (iOS, Android)

**Requirements**:
- Public client (no secret)
- Authorisation Code + PKCE
- Native browser for auth (not webview)

**Recommendations**:
- Use system browser (ASWebAuthenticationSession, Chrome Custom Tabs)
- Use PKCE for security
- Store tokens in secure keychain/keystore
- Implement biometric re-authentication

### Scenario 4: Microservices Architecture

**Requirements**:
- Service clients (confidential)
- Client Credentials flow
- Token introspection

**Recommendations**:
- Each service has its own client
- Use client credentials for service-to-service
- Gateway validates user tokens
- Internal services trust gateway or use introspection

## Troubleshooting

### "redirect_uri_mismatch" Error

**Cause**: Redirect URI doesn't exactly match registered URI

**Solution**: 
- Check for trailing slashes
- Verify http vs https
- Ensure port numbers match
- Update client configuration in BlackWall admin

### "invalid_grant" Error

**Cause**: Authorisation code expired or already used

**Solution**:
- Codes expire in 10 minutes
- Codes are single-use only
- Don't retry with same code
- Start authorisation flow again

### "invalid_client" Error

**Cause**: Client authentication failed

**Solution**:
- Verify client_id is correct
- Check client_secret (for confidential clients)
- Ensure client is active in BlackWall
- Verify Basic auth header format

### Tokens Not Working

**Causes**:
- Token expired (check `exp` claim)
- Token revoked
- Invalid bearer token format

**Solution**:
- Use refresh token to get new access token
- Check token format: `Authorisation: Bearer TOKEN`
- Verify token via introspection endpoint

## Security Best Practices

1. **Always use HTTPS** in production
2. **Validate state parameter** to prevent CSRF
3. **Use PKCE** even for confidential clients
4. **Don't expose tokens** in URLs or logs
5. **Implement token refresh** before expiry
6. **Revoke tokens** on logout
7. **Rotate client secrets** periodically
8. **Monitor audit logs** for suspicious activity
9. **Validate redirect URIs** strictly
10. **Use short-lived access tokens** (1 hour)

## Rate Limiting

BlackWall implements rate limiting on token endpoints:
- Token endpoint: 10 requests per minute per client
- Introspection: 60 requests per minute per client
- UserInfo: 60 requests per minute per user

Implement exponential backoff if you receive 429 responses.

## Support and Documentation

- **Admin Panel**: https://blackwall.cx/admin
- **API Base URL**: https://blackwall.cx
- **Discovery Document**: https://blackwall.cx/.well-known/openid-configuration

## Sample Integration Prompt for AI Assistants

When asking an AI to help integrate BlackWall, provide this context:

```
I need to integrate OAuth 2.1 / OpenID Connect authentication with BlackWall.

Server: https://blackwall.cx
Discovery: https://blackwall.cx/.well-known/openid-configuration

My application:
- Type: [web/mobile/API/service]
- Language/Framework: [specify]
- Client Type: [public/confidential]
- Required Scopes: openid profile email
- Redirect URI: [your URI]

Requirements:
- Implement Authorisation Code flow with PKCE
- Handle token refresh
- Display user information after login
- Implement secure logout with token revocation

Please help me implement this integration following OAuth 2.1 and OIDC best practices.
```

## Advanced Topics

### Custom Claims in ID Tokens

Currently supported:
- `sub` - User UUID (always present)
- `name` - User display name (if profile scope)
- `preferred_username` - Username (if profile scope)
- `email` - Email address (if email scope)
- `email_verified` - Email verification status

### Privilege Level Authorisation

1. Obtain access token via standard OAuth flow
2. Use introspection endpoint to get token metadata
3. Check privilege level in your application
4. Make authorisation decisions based on level

Example:
```javascript
const introspection = await introspectToken(accessToken);
if (introspection.active) {
  const privilegeLevel = introspection.privilege_level; // 1-10
  if (privilegeLevel <= 2) {
    // Admin or privileged user
  }
}
```

### Multi-Project Isolation

BlackWall supports multiple projects for tenant isolation:
- Each client belongs to one project
- Users can have different privilege levels per project
- Tokens are scoped to specific projects
- Cross-project access requires multiple clients

## Conclusion

BlackWall provides enterprise-grade OAuth 2.1 / OIDC authentication with WebAuthn security. This guide should help you integrate it into any application. For specific implementation questions, consult your AI assistant with the context from this document.

**Remember**: Security is paramount. Always use HTTPS, implement PKCE, validate tokens properly, and follow OAuth 2.1 best practices.
