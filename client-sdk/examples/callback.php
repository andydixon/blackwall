<?php
// Example OAuth callback handler using BlackWallAuth
session_start();
require __DIR__ . '/../src/BlackWallAuth.php';
use BlackWallSDK\BlackWallAuth;

$auth = new BlackWallAuth([
    'clientId' => 'YOUR_CLIENT_ID',
    // 'clientSecret' => 'YOUR_CLIENT_SECRET', // only for confidential clients
    'authorizeUrl' => 'https://blackwall.dixon.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.dixon.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.dixon.cx/oauth/userinfo',
    'redirectUri' => 'https://yourapp.example.com/callback',
]);

if (!isset($_GET['code']) || !isset($_GET['state'])) {
    http_response_code(400);
    echo 'Missing code/state';
    exit;
}

if (isset($_SESSION['blackwall_oauth_state']) && $_GET['state'] !== $_SESSION['blackwall_oauth_state']) {
    http_response_code(400);
    echo 'Invalid state';
    exit;
}

try {
    $tokens = $auth->exchangeCodeForTokens($_GET['code']);
    $_SESSION['access_token'] = $tokens['access_token'] ?? null;
    $_SESSION['refresh_token'] = $tokens['refresh_token'] ?? null;
    // Optional: fetch user info
    if (isset($_SESSION['access_token'])) {
        $_SESSION['user'] = $auth->getUserInfo($_SESSION['access_token']);
    }
    // Clean up state
    unset($_SESSION['blackwall_oauth_state'], $_SESSION['blackwall_oauth_code_verifier']);

    header('Location: /');
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Auth failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
