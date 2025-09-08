<?php
// Minimal boilerplate authentication example using BlackWallAuth
session_start();

require __DIR__ . '/../src/BlackWallAuth.php';

use BlackWallSDK\BlackWallAuth;

$auth = new BlackWallAuth([
    'clientId' => 'YOUR_CLIENT_ID',
    // 'clientSecret' => 'YOUR_CLIENT_SECRET', // only for confidential clients
    'authorizeUrl' => 'https://blackwall.dixon.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.dixon.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.dixon.cx/oauth/userinfo',
    'redirectUri' => 'https://yourapp.example.com/callback', // update to your callback URL
    'scope' => 'openid profile email offline_access',
]);

if (!isset($_GET['code'])) {
    $authData = $auth->getAuthorizationUrl();
    header('Location: ' . $authData['url']);
    exit;
}

// Optional: verify state from session (CSRF protection)
if (isset($_GET['state']) && isset($_SESSION['blackwall_oauth_state']) && $_GET['state'] !== $_SESSION['blackwall_oauth_state']) {
    http_response_code(400);
    echo 'Invalid state';
    exit;
}

$tokens = $auth->exchangeCodeForTokens($_GET['code']);
$user = $auth->getUserInfo($tokens['access_token']);

header('Content-Type: text/plain');
echo "Authenticated!\n\nUser:\n";
echo json_encode($user, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";
echo "Tokens (truncated):\n";
echo json_encode([
    'access_token' => isset($tokens['access_token']) ? substr($tokens['access_token'], 0, 16) . '…' : null,
    'id_token' => isset($tokens['id_token']) ? substr($tokens['id_token'], 0, 16) . '…' : null,
    'refresh_token' => isset($tokens['refresh_token']) ? substr($tokens['refresh_token'], 0, 8) . '…' : null,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
