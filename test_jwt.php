<?php

require __DIR__ . '/vendor/autoload.php';

use BlackWall\Security\JWTManager;

// Get JWT token from command line argument
if ($argc < 2) {
    echo "Usage: php test_jwt.php <jwt_token>\n";
    exit(1);
}

$tokenString = $argv[1];

echo "Testing JWT token...\n";
echo "Token: " . substr($tokenString, 0, 50) . "...\n\n";

try {
    $jwtManager = new JWTManager();
    
    echo "Attempting to parse...\n";
    $token = $jwtManager->parse($tokenString);
    
    if (!$token) {
        echo "❌ Failed to parse token\n";
        exit(1);
    }
    
    echo "✓ Token parsed successfully\n";
    echo "Headers: " . json_encode($token->headers()->all(), JSON_PRETTY_PRINT) . "\n";
    echo "Claims: " . json_encode($token->claims()->all(), JSON_PRETTY_PRINT) . "\n\n";
    
    echo "Attempting to validate...\n";
    $isValid = $jwtManager->validate($token);
    
    if ($isValid) {
        echo "✓ Token is valid\n";
    } else {
        echo "❌ Token validation failed\n";
    }
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . ":" . $e->getLine() . "\n";
    exit(1);
}
