# BlackWall OAuth 2.1 - Quick Start Guide

## 5-Minute Integration

### Server Details
- **Base URL**: `https://blackwall.dixon.cx`
- **Authorization**: `https://blackwall.dixon.cx/oauth/authorize`
- **Token**: `https://blackwall.dixon.cx/oauth/token`
- **UserInfo**: `https://blackwall.dixon.cx/oauth/userinfo`

### Step 1: Register Your Client
1. Go to BlackWall admin panel
2. Create new OAuth client
3. Set redirect URI (e.g., `https://yourapp.com/callback`)
4. Note your `client_id`

### Step 2: Initiate Login

```php
<?php
session_start();

// Generate PKCE values
$codeVerifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
$state = bin2hex(random_bytes(16));

// Store in session
$_SESSION['oauth_code_verifier'] = $codeVerifier;
$_SESSION['oauth_state'] = $state;

// Build authorization URL
$params = [
    'response_type' => 'code',
    'client_id' => 'YOUR_CLIENT_ID',
    'redirect_uri' => 'https://yourapp.com/callback',
    'scope' => 'openid profile email offline_access',
    'state' => $state,
    'code_challenge' => $codeChallenge,
    'code_challenge_method' => 'S256',
];

$authUrl = 'https://blackwall.dixon.cx/oauth/authorize?' . http_build_query($params);
header("Location: $authUrl");
exit;
```

### Step 3: Handle Callback

```php
<?php
session_start();

// Get code and state from callback
$code = $_GET['code'];
$state = $_GET['state'];

// Verify state (CSRF protection)
if ($state !== $_SESSION['oauth_state']) {
    die('Invalid state');
}

// Exchange code for tokens
$tokenData = [
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => 'https://yourapp.com/callback',
    'client_id' => 'YOUR_CLIENT_ID',
    'code_verifier' => $_SESSION['oauth_code_verifier'],
];

$ch = curl_init('https://blackwall.dixon.cx/oauth/token');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($tokenData));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);

$response = curl_exec($ch);
$tokens = json_decode($response, true);
curl_close($ch);

// Get user info
$ch = curl_init('https://blackwall.dixon.cx/oauth/userinfo');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $tokens['access_token']]);

$userInfo = json_decode(curl_exec($ch), true);
curl_close($ch);

// Store in session
$_SESSION['loggedIn'] = true;
$_SESSION['access_token'] = $tokens['access_token'];
$_SESSION['refresh_token'] = $tokens['refresh_token'];
$_SESSION['user'] = $userInfo;

// Clean up OAuth data
unset($_SESSION['oauth_code_verifier']);
unset($_SESSION['oauth_state']);

header("Location: /");
exit;
```

## Common Issues

### Error: "No authorization request found"
**Cause**: Session data not persisting between login and callback.

**Solutions**:
1. Ensure `session_start()` is called at the beginning of both files
2. Don't call `session_write_close()` before redirect
3. Check PHP session configuration (cookies must work)
4. Verify redirect_uri matches exactly (including trailing slash)

### Error: "invalid_grant"
**Cause**: Authorization code expired or already used.

**Solutions**:
1. Codes expire in 10 minutes - use immediately
2. Codes are single-use only
3. Don't retry with same code

### Error: "redirect_uri_mismatch"
**Cause**: Redirect URI doesn't match registered URI.

**Solutions**:
1. Check for trailing slashes
2. Verify http vs https
3. Must be exact match (no wildcards)

## Minimal Working Example

See the `/cms/` directory for a complete working implementation:
- `login/index.php` - Initiates OAuth flow
- `blackwall-callback.php` - Handles callback
- `src/NeoCMS/Authentication.php` - Full OAuth client class

## Key Points

1. **Always use PKCE** - Required for security
2. **Store state in session** - For CSRF protection
3. **Verify state on callback** - Security critical
4. **Use authorization_code grant** - Not "authorisation" (American spelling)
5. **Session must persist** - Between login page and callback

## Testing Your Integration

1. Visit your login page
2. You'll be redirected to BlackWall
3. Authenticate with WebAuthn
4. You'll be redirected back with a code
5. Your callback exchanges code for tokens
6. User is now logged in!

## Need Help?

Check the full guide: `IMPLEMENTATION_PROMPT.md`
