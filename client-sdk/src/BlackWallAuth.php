<?php
namespace BlackWallSDK;

class BlackWallAuth
{
    private string $clientId;
    private ?string $clientSecret;
    private string $authorizeUrl;
    private string $tokenUrl;
    private ?string $userInfoUrl;
    private string $redirectUri;
    private string $defaultScope;

    public function __construct(array $config)
    {
        foreach (['clientId','authorizeUrl','tokenUrl','redirectUri'] as $key) {
            if (empty($config[$key])) {
                throw new \InvalidArgumentException("$key is required");
            }
        }
        $this->clientId = $config['clientId'];
        $this->clientSecret = $config['clientSecret'] ?? null;
        $this->authorizeUrl = rtrim($config['authorizeUrl'], '/');
        $this->tokenUrl = rtrim($config['tokenUrl'], '/');
        $this->userInfoUrl = isset($config['userInfoUrl']) ? rtrim($config['userInfoUrl'], '/') : null;
        $this->redirectUri = $config['redirectUri'];
        $this->defaultScope = $config['scope'] ?? 'openid profile email';
    }

    /**
     * Build the authorization URL and return PKCE details.
     * @return array{url:string,state:string,code_verifier:string,code_challenge:string}
     */
    public function getAuthorizationUrl(array $opts = []): array
    {
        $state = $opts['state'] ?? bin2hex(random_bytes(16));
        $codeVerifier = $opts['code_verifier'] ?? $this->randomUrlSafe(43);
        $codeChallenge = $this->base64Url(hash('sha256', $codeVerifier, true));
        $scope = $opts['scope'] ?? $this->defaultScope;
        $extra = $opts['extra'] ?? [];
        $persist = $opts['persist'] ?? true; // persist state + code_verifier to PHP session

        if ($persist && $this->sessionActive()) {
            $_SESSION['blackwall_oauth_state'] = $state;
            $_SESSION['blackwall_oauth_code_verifier'] = $codeVerifier;
        }

        $query = array_merge([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $scope,
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ], $extra);

        $url = $this->authorizeUrl . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $url,
            'state' => $state,
            'code_verifier' => $codeVerifier,
            'code_challenge' => $codeChallenge,
        ];
    }

    /**
     * Exchange authorization code for tokens using PKCE.
     */
    public function exchangeCodeForTokens(string $code, ?string $codeVerifier = null): array
    {
        $verifier = $codeVerifier ?? ($_SESSION['blackwall_oauth_code_verifier'] ?? null);
        if (!$verifier) {
            throw new \RuntimeException('Missing code_verifier; pass as argument or enable session persistence.');
        }
        $payload = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'code_verifier' => $verifier,
        ];
        if ($this->clientSecret) {
            $payload['client_secret'] = $this->clientSecret; // only for confidential clients
        }

        return $this->httpPostForm($this->tokenUrl, $payload);
    }

    /**
     * Refresh an access token (if refresh_token was issued).
     */
    public function refreshAccessToken(string $refreshToken): array
    {
        $payload = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->clientId,
        ];
        if ($this->clientSecret) {
            $payload['client_secret'] = $this->clientSecret;
        }
        return $this->httpPostForm($this->tokenUrl, $payload);
    }

    /**
     * Retrieve OIDC userinfo using an access token.
     */
    public function getUserInfo(string $accessToken): array
    {
        if (!$this->userInfoUrl) {
            throw new \InvalidArgumentException('userInfoUrl not configured');
        }
        $ch = curl_init($this->userInfoUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken,
                'Accept: application/json',
            ],
        ]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($body === false) {
            throw new \RuntimeException("HTTP error: $err");
        }
        $data = json_decode($body, true);
        if ($status >= 400) {
            $msg = is_array($data) ? json_encode($data) : $body;
            throw new \RuntimeException("UserInfo error ($status): $msg");
        }
        return is_array($data) ? $data : [];
    }

    private function httpPostForm(string $url, array $fields): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'],
            CURLOPT_RETURNTRANSFER => true,
        ]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new \RuntimeException("HTTP error: $err");
        }

        $data = json_decode($body, true);
        if ($status >= 400) {
            $msg = is_array($data) ? json_encode($data) : $body;
            throw new \RuntimeException("Token endpoint error ($status): $msg");
        }
        if (!is_array($data)) {
            throw new \RuntimeException('Invalid JSON response from server');
        }
        return $data;
    }

    private function base64Url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private function randomUrlSafe(int $len): string
    {
        return $this->base64Url(random_bytes($len));
    }

    private function sessionActive(): bool
    {
        return session_status() === PHP_SESSION_ACTIVE;
    }
}
