# OAuth Provider Implementation Guide

Date: 2026-02-04T13:19:12.411Z

This guide explains how to authenticate users against a specific project using the built-in OAuth provider backed by hardware smart key authentication at /ai.

Provider endpoints (hosted on https://blackwall.dixon.cx):
- Authorization: GET /oauth/authorize
- Token: POST /oauth/token
- UserInfo: GET /oauth/userinfo

Configuration (config/config.php or environment variables):
- BW_OAUTH_ISSUER: e.g., https://blackwall.dixon.cx
- BW_OAUTH_JWT_SECRET: strong secret for HMAC (HS256)
- BW_OAUTH_CLIENT_ID: project ID (string)
- BW_OAUTH_CLIENT_SECRET: client secret for the project
- BW_OAUTH_REDIRECT_URI: callback URL for the project

Multiple projects:
- Define multiple clients under 'oauth.clients' in config/config.php. Each client.id should be the project ID and have its own secret and allowed redirect_uris.

Flow overview:
1) User authenticates with smart key at /ai/login (creates session: user_id, username, name, email, is_admin).
2) Client redirects browser to /oauth/authorize with response_type=code, client_id={projectId}, redirect_uri, scope, state.
3) Provider checks session; if not authenticated, asks user to login at /ai/login, then continue.
4) Provider issues an authorization code (JWT, short-lived) and redirects back to redirect_uri with code and state.
5) Client exchanges code at /oauth/token with grant_type=authorization_code, client_id, client_secret, redirect_uri.
6) Provider returns access_token (JWT) and expires_in.
7) Client calls /oauth/userinfo with Authorization: Bearer {access_token} to get user claims.

Parameters
- /oauth/authorize (GET):
  - response_type: "code"
  - client_id: project ID registered in config
  - redirect_uri: must match one of the client's redirect_uris
  - scope: space-delimited (optional; echoed into access token)
  - state: opaque value (optional; echoed in redirect)

- /oauth/token (POST form):
  - grant_type: "authorization_code"
  - code: authorization code (JWT from /authorize)
  - client_id: project ID
  - client_secret: project secret
  - redirect_uri: must match original authorize request

- /oauth/userinfo (GET):
  - Header: Authorization: Bearer {access_token}

JWT details
- Algorithm: HS256 (HMAC with BW_OAUTH_JWT_SECRET)
- Authorization code payload: { iss, typ:"auth_code", iat, exp, client_id, redirect_uri, scope, sub, username, name, email, is_admin }
- Access token payload: { iss, typ:"access", iat, exp, client_id, scope, sub, username, name, email, is_admin }

Project-specific authentication
- Treat client_id as the project ID. Register each project as a client in config with its own secret and redirect URIs.
- Optionally include project-specific scopes (e.g., scope="project:read project:{projectId}") and validate them in the consuming app.

Security notes
- Use HTTPS in production.
- Keep BW_OAUTH_JWT_SECRET long and random.
- Validate state on the client side to prevent CSRF.
- Restrict redirect_uris per project.
- Rotate client secrets periodically.

Examples
Authorization request:
GET https://blackwall.dixon.cx/oauth/authorize?response_type=code&client_id=project-123&redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback&scope=openid%20email%20profile&state=xyz

Token exchange (form-encoded):
grant_type=authorization_code&code={CODE}&client_id=project-123&client_secret={SECRET}&redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback

UserInfo:
GET /oauth/userinfo with Authorization: Bearer {access_token}

Troubleshooting
- invalid_client: client_id/secret mismatch or client not registered.
- invalid_redirect_uri: redirect_uri not in allowed list.
- unsupported_response_type / unsupported_grant_type: use code + authorization_code.
- invalid_grant: code invalid/expired or mismatched client/redirect.
- invalid_token: missing/expired/invalid Bearer token.

Mapping users
- User identity is sourced from the smart key session (/ai). Claims include: sub (user_id), username, name, email, is_admin.
- Update /ai setup to add/register users and keys.
