BlackWall Client SDK

Contents:
- src/BlackWallAuth.php: PHP class for OAuth 2.1 + PKCE with BlackWall
- examples/quickstart.php: Single-file login + callback demo (set clientId/redirectUri)
- examples/callback.php: Dedicated callback handler example

Usage:
1) Initialize and redirect to login
   - Point a route/page to examples/quickstart.php or use BlackWallAuth::getAuthorizationUrl() in your app.
2) Handle callback
   - Deploy examples/callback.php at your registered redirectUri and set clientId/redirectUri.
3) Token exchange and user info
   - Use exchangeCodeForTokens() and getUserInfo() as shown.

Config keys:
- clientId (required)
- clientSecret (optional; confidential clients only)
- authorizeUrl, tokenUrl (required), userInfoUrl (optional)
- redirectUri (required)
- scope (optional; default "openid profile email")

Notes:
- Always use PKCE; session must persist for state/code_verifier.
- Verify state on callback to prevent CSRF.
