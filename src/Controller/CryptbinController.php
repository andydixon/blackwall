<?php

declare(strict_types=1);

namespace BlackWall\Controller;

use BlackWall\Config;
use BlackWall\Security\Base64Url;
use BlackWall\Security\CSRFProtection;
use BlackWall\Security\CryptbinKeyVerifier;
use BlackWall\Security\RateLimiter;
use BlackWall\Security\SessionManager;
use BlackWall\Service\AuditLogger;
use BlackWall\Service\CryptbinKekService;
use BlackWall\Service\CryptbinStorageService;
use BlackWall\Service\WebAuthnService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\PhpRenderer;

class CryptbinController
{
    private const OP_WRAP_CREATE = 'wrap_create';
    private const OP_UNWRAP_VIEW = 'unwrap_view';
    private const OP_UPDATE = 'update';
    private const OP_DELETE = 'delete';

    private const OPERATION_TTL_SECONDS = 120;

    private PhpRenderer $renderer;
    private WebAuthnService $webauthn;
    private RateLimiter $rateLimiter;
    private CryptbinStorageService $storage;
    private CryptbinKekService $kek;

    public function __construct()
    {
        $this->renderer = new PhpRenderer(__DIR__ . '/../../templates');
        $this->webauthn = new WebAuthnService();
        $this->rateLimiter = new RateLimiter();
        $this->storage = new CryptbinStorageService();
        $this->kek = new CryptbinKekService();
    }

    public function createForm(Request $request, Response $response): Response
    {
        return $this->renderer->render($response, 'cryptbin/create.php', [
            'csrfToken' => CSRFProtection::generateToken(),
            'maxUploadBytes' => Config::getInt('CRYPTBIN_MAX_UPLOAD_BYTES', 5242880),
            'maxTextBytes' => Config::getInt('CRYPTBIN_MAX_TEXT_BYTES', 262144),
        ]);
    }

    public function create(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        $audit = $this->audit($request);

        if (!$this->validateCsrf($body)) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'cryptbin.create']);
            return $this->json($response, ['error' => 'Invalid CSRF token'], 403);
        }

        $id = (string) ($body['id'] ?? '');
        if (!CryptbinStorageService::isValidId($id)) {
            return $this->json($response, ['error' => 'Invalid id'], 400);
        }

        if (!$this->checkRateLimits($request, $id, 'cryptbin.create', 8, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        if ($this->storage->exists($id)) {
            return $this->json($response, ['error' => 'ID already exists'], 409);
        }

        $itemType = (string) ($body['item_type'] ?? '');
        if (!in_array($itemType, ['text', 'file'], true)) {
            return $this->json($response, ['error' => 'Invalid item type'], 400);
        }

        $keyB64 = (string) ($body['key_b64url'] ?? '');
        if (!CryptbinKeyVerifier::validateKeyMaterial($keyB64)) {
            return $this->json($response, ['error' => 'Invalid key'], 400);
        }

        $ciphertext = Base64Url::decode((string) ($body['ciphertext_b64url'] ?? ''));
        if ($ciphertext === false || $ciphertext === '') {
            return $this->json($response, ['error' => 'Invalid ciphertext'], 400);
        }

        $maxUpload = Config::getInt('CRYPTBIN_MAX_UPLOAD_BYTES', 5242880);
        if (strlen($ciphertext) > $maxUpload) {
            return $this->json($response, ['error' => 'Payload too large'], 413);
        }

        $nonce = Base64Url::decode((string) ($body['cipher_nonce_b64url'] ?? ''));
        if ($nonce === false || strlen($nonce) !== 12) {
            return $this->json($response, ['error' => 'Invalid cipher nonce'], 400);
        }

        $cipherAlg = (string) ($body['cipher_alg'] ?? '');
        if ($cipherAlg !== 'AES-256-GCM') {
            return $this->json($response, ['error' => 'Unsupported cipher algorithm'], 400);
        }

        $wrappedDek = (string) ($body['wrapped_dek'] ?? '');
        $wrappedDekNonce = (string) ($body['wrapped_dek_nonce'] ?? '');
        $wrappedDekAlg = (string) ($body['wrapped_dek_alg'] ?? '');
        $kekVersion = (string) ($body['kek_version'] ?? '');

        if ($wrappedDek === '' || $wrappedDekNonce === '' || $wrappedDekAlg === '' || $kekVersion === '') {
            return $this->json($response, ['error' => 'Missing wrapped DEK'], 400);
        }

        $mimeType = trim((string) ($body['mime_type'] ?? 'application/octet-stream'));
        if ($mimeType === '') {
            $mimeType = 'application/octet-stream';
        }

        $allowedMime = trim(Config::get('CRYPTBIN_ALLOWED_MIME', ''));
        if ($allowedMime !== '') {
            $allowed = array_map('trim', explode(',', $allowedMime));
            if (!in_array($mimeType, $allowed, true)) {
                return $this->json($response, ['error' => 'MIME type not allowed'], 400);
            }
        }

        $filename = $this->storage->sanitizeOriginalFilename((string) ($body['original_filename'] ?? ''), $itemType);

        try {
            $verifier = CryptbinKeyVerifier::createVerifier($keyB64);
        } catch (\Throwable $e) {
            return $this->json($response, ['error' => 'Unable to create key verifier'], 500);
        }

        $now = gmdate('c');
        $metadata = [
            'id' => $id,
            'version' => 1,
            'item_type' => $itemType,
            'original_filename' => $filename,
            'mime_type' => $mimeType,
            'cipher_alg' => $cipherAlg,
            'cipher_nonce_b64url' => Base64Url::encode($nonce),
            'wrapped_dek' => $wrappedDek,
            'wrapped_dek_nonce' => $wrappedDekNonce,
            'wrapped_dek_alg' => $wrappedDekAlg,
            'kek_version' => $kekVersion,
            'verifier' => $verifier,
            'created_at' => $now,
            'updated_at' => $now,
            'requires_webauthn_for_view' => true,
        ];

        $expiryDays = Config::getInt('CRYPTBIN_DEFAULT_RETENTION_DAYS', 0);
        if ($expiryDays > 0) {
            $metadata['expires_at'] = gmdate('c', time() + ($expiryDays * 86400));
        }

        $this->storage->writeItem($id, $ciphertext, $metadata);

        $audit->logSuccess('cryptbin.create.success', [
            'target_type' => 'cryptbin',
            'target_id' => $id,
            'message' => 'Cryptbin item created',
        ]);

        return $this->json($response, ['success' => true, 'id' => $id, 'url' => '/cryptbin/' . $id]);
    }

    public function view(Request $request, Response $response, array $args): Response
    {
        $id = (string) ($args['id'] ?? '');

        if (!CryptbinStorageService::isValidId($id)) {
            return $response->withStatus(404);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $response->withStatus(404);
        }

        return $this->renderer->render($response, 'cryptbin/view.php', [
            'csrfToken' => CSRFProtection::generateToken(),
            'id' => $id,
            'maxUploadBytes' => Config::getInt('CRYPTBIN_MAX_UPLOAD_BYTES', 5242880),
            'maxTextBytes' => Config::getInt('CRYPTBIN_MAX_TEXT_BYTES', 262144),
        ]);
    }

    public function share(Request $request, Response $response, array $args): Response
    {
        $id = (string) ($args['id'] ?? '');

        if (!CryptbinStorageService::isValidId($id)) {
            return $response->withStatus(404);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $response->withStatus(404);
        }

        return $this->renderer->render($response, 'cryptbin/share.php', [
            'id' => $id,
        ]);
    }

    public function metadata(Request $request, Response $response, array $args): Response
    {
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');
        if (!CryptbinStorageService::isValidId($id)) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }
        if (!$this->checkRateLimits($request, $id, 'cryptbin.metadata', 60, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        return $this->json($response, $this->storage->publicMetadata($meta));
    }

    public function ciphertext(Request $request, Response $response, array $args): Response
    {
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');
        if (!CryptbinStorageService::isValidId($id)) {
            return $response->withStatus(404);
        }
        if (!$this->checkRateLimits($request, $id, 'cryptbin.ciphertext', 60, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $response->withStatus(404);
        }

        $ciphertext = $this->storage->readCiphertext($id);
        if ($ciphertext === null) {
            return $response->withStatus(404);
        }

        $response->getBody()->write($ciphertext);
        return $response
            ->withHeader('Content-Type', 'application/octet-stream')
            ->withHeader('Cache-Control', 'no-store');
    }

    public function webauthnChallenge(Request $request, Response $response, array $args): Response
    {
        $body = (array) $request->getParsedBody();
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');
        $op = (string) ($body['op'] ?? '');

        if (!$this->validateCsrf($body)) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'cryptbin.challenge']);
            return $this->json($response, ['error' => 'Invalid CSRF token'], 403);
        }

        if (!CryptbinStorageService::isValidId($id) || !$this->isAllowedOperation($op)) {
            return $this->json($response, ['error' => 'Invalid request'], 400);
        }

        if ($op !== self::OP_WRAP_CREATE) {
            $meta = $this->storage->readMetadata($id);
            if ($meta === null || $this->isExpired($meta)) {
                return $this->json($response, ['error' => 'Not found'], 404);
            }
        }

        if (!$this->checkRateLimits($request, $id, 'cryptbin.webauthn.challenge', 20, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        $challenge = base64_encode(random_bytes(32));
        $nonce = Base64Url::encode(random_bytes(16));

        SessionManager::start();
        $operations = (array) SessionManager::get('cryptbin_webauthn_ops', []);
        $operations[$nonce] = [
            'id' => $id,
            'op' => $op,
            'challenge' => $challenge,
            'expires_at' => time() + self::OPERATION_TTL_SECONDS,
            'issued_at' => time(),
        ];
        SessionManager::set('cryptbin_webauthn_ops', $operations);

        return $this->json($response, [
            'nonce' => $nonce,
            'publicKey' => [
                'challenge' => $challenge,
                'timeout' => 60000,
                'rpId' => Config::get('WEBAUTHN_RP_ID'),
                'userVerification' => 'required',
            ],
            'expires_in_seconds' => self::OPERATION_TTL_SECONDS,
        ]);
    }

    public function wrap(Request $request, Response $response, array $args): Response
    {
        $body = (array) $request->getParsedBody();
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');

        if (!$this->validateCsrf($body)) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'cryptbin.wrap']);
            return $this->json($response, ['error' => 'Invalid CSRF token'], 403);
        }

        if (!CryptbinStorageService::isValidId($id)) {
            return $this->json($response, ['error' => 'Invalid ID'], 400);
        }

        if (!$this->checkRateLimits($request, $id, 'cryptbin.wrap', 12, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        if (($body['op'] ?? '') !== self::OP_WRAP_CREATE) {
            return $this->json($response, ['error' => 'Invalid operation'], 400);
        }

        $authResult = $this->verifyOperationAssertion($request, $id, self::OP_WRAP_CREATE, $body);
        if ($authResult === null) {
            $audit->logFail('cryptbin.wrap.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'WebAuthn verification failed']);
            return $this->json($response, ['error' => 'WebAuthn verification failed'], 403);
        }

        $dek = Base64Url::decode((string) ($body['dek_b64url'] ?? ''));
        if ($dek === false || strlen($dek) !== 32) {
            return $this->json($response, ['error' => 'Invalid DEK'], 400);
        }

        $wrapped = $this->kek->wrapDek($dek, $id);

        $audit->logSuccess('cryptbin.wrap.success', [
            'target_type' => 'cryptbin',
            'target_id' => $id,
            'webauthn_credential_id' => $authResult['credential_db_id'],
            'webauthn_credential_public_id' => $authResult['credential_id'],
        ]);

        return $this->json($response, [
            'success' => true,
            'wrapped' => $wrapped,
        ]);
    }

    public function unwrap(Request $request, Response $response, array $args): Response
    {
        $body = (array) $request->getParsedBody();
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');

        if (!$this->validateCsrf($body)) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'cryptbin.unwrap']);
            return $this->json($response, ['error' => 'Invalid CSRF token'], 403);
        }

        if (!CryptbinStorageService::isValidId($id)) {
            return $this->json($response, ['error' => 'Invalid ID'], 400);
        }

        if (!$this->checkRateLimits($request, $id, 'cryptbin.unwrap', 20, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $authResult = $this->verifyOperationAssertion($request, $id, self::OP_UNWRAP_VIEW, $body);
        if ($authResult === null) {
            $audit->logFail('cryptbin.unwrap.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'WebAuthn verification failed']);
            return $this->json($response, ['error' => 'WebAuthn verification failed'], 403);
        }

        try {
            $dek = $this->kek->unwrapDek($meta, $id);
        } catch (\Throwable $e) {
            $audit->logFail('cryptbin.unwrap.fail', [
                'target_type' => 'cryptbin',
                'target_id' => $id,
                'failure_reason' => 'Failed to unwrap DEK',
            ]);
            return $this->json($response, ['error' => 'Unable to unwrap DEK'], 500);
        }

        $audit->logSuccess('cryptbin.unwrap.success', [
            'target_type' => 'cryptbin',
            'target_id' => $id,
            'webauthn_credential_id' => $authResult['credential_db_id'],
            'webauthn_credential_public_id' => $authResult['credential_id'],
        ]);

        return $this->json($response, ['success' => true, 'dek_b64url' => Base64Url::encode($dek)]);
    }

    public function update(Request $request, Response $response, array $args): Response
    {
        $body = (array) $request->getParsedBody();
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');

        if (!$this->validateCsrf($body)) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'cryptbin.update']);
            return $this->json($response, ['error' => 'Invalid CSRF token'], 403);
        }

        if (!CryptbinStorageService::isValidId($id)) {
            return $this->json($response, ['error' => 'Invalid ID'], 400);
        }

        if (!$this->checkRateLimits($request, $id, 'cryptbin.update', 10, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $keyB64 = (string) ($body['key_b64url'] ?? '');
        if (!$this->verifyKey($meta, $keyB64)) {
            $audit->logFail('cryptbin.update.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'Invalid key']);
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $authResult = $this->verifyOperationAssertion($request, $id, self::OP_UPDATE, $body);
        if ($authResult === null) {
            $audit->logFail('cryptbin.update.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'WebAuthn verification failed']);
            return $this->json($response, ['error' => 'WebAuthn verification failed'], 403);
        }

        $itemType = (string) ($body['item_type'] ?? '');
        if (!in_array($itemType, ['text', 'file'], true)) {
            return $this->json($response, ['error' => 'Invalid item type'], 400);
        }

        $ciphertext = Base64Url::decode((string) ($body['ciphertext_b64url'] ?? ''));
        if ($ciphertext === false || $ciphertext === '') {
            return $this->json($response, ['error' => 'Invalid ciphertext'], 400);
        }

        $maxUpload = Config::getInt('CRYPTBIN_MAX_UPLOAD_BYTES', 5242880);
        if (strlen($ciphertext) > $maxUpload) {
            return $this->json($response, ['error' => 'Payload too large'], 413);
        }

        $nonce = Base64Url::decode((string) ($body['cipher_nonce_b64url'] ?? ''));
        if ($nonce === false || strlen($nonce) !== 12) {
            return $this->json($response, ['error' => 'Invalid cipher nonce'], 400);
        }

        $dek = Base64Url::decode((string) ($body['dek_b64url'] ?? ''));
        if ($dek === false || strlen($dek) !== 32) {
            return $this->json($response, ['error' => 'Invalid DEK'], 400);
        }

        $cipherAlg = (string) ($body['cipher_alg'] ?? '');
        if ($cipherAlg !== 'AES-256-GCM') {
            return $this->json($response, ['error' => 'Unsupported cipher algorithm'], 400);
        }

        $mimeType = trim((string) ($body['mime_type'] ?? 'application/octet-stream'));
        if ($mimeType === '') {
            $mimeType = 'application/octet-stream';
        }

        $allowedMime = trim(Config::get('CRYPTBIN_ALLOWED_MIME', ''));
        if ($allowedMime !== '') {
            $allowed = array_map('trim', explode(',', $allowedMime));
            if (!in_array($mimeType, $allowed, true)) {
                return $this->json($response, ['error' => 'MIME type not allowed'], 400);
            }
        }

        $filename = $this->storage->sanitizeOriginalFilename((string) ($body['original_filename'] ?? ''), $itemType);
        $wrapped = $this->kek->wrapDek($dek, $id);

        $newMetadata = $meta;
        $newMetadata['item_type'] = $itemType;
        $newMetadata['original_filename'] = $filename;
        $newMetadata['mime_type'] = $mimeType;
        $newMetadata['cipher_alg'] = $cipherAlg;
        $newMetadata['cipher_nonce_b64url'] = Base64Url::encode($nonce);
        $newMetadata['wrapped_dek'] = $wrapped['wrapped_dek'];
        $newMetadata['wrapped_dek_nonce'] = $wrapped['wrapped_dek_nonce'];
        $newMetadata['wrapped_dek_alg'] = $wrapped['wrapped_dek_alg'];
        $newMetadata['kek_version'] = $wrapped['kek_version'];
        $newMetadata['updated_at'] = gmdate('c');

        $this->storage->writeItem($id, $ciphertext, $newMetadata);

        $audit->logSuccess('cryptbin.update.success', [
            'target_type' => 'cryptbin',
            'target_id' => $id,
            'webauthn_credential_id' => $authResult['credential_db_id'],
            'webauthn_credential_public_id' => $authResult['credential_id'],
        ]);

        return $this->json($response, ['success' => true]);
    }

    public function delete(Request $request, Response $response, array $args): Response
    {
        $body = (array) $request->getParsedBody();
        $audit = $this->audit($request);
        $id = (string) ($args['id'] ?? '');

        if (!$this->validateCsrf($body)) {
            $audit->logFail('security.csrf.fail', ['failure_reason' => 'cryptbin.delete']);
            return $this->json($response, ['error' => 'Invalid CSRF token'], 403);
        }

        if (!CryptbinStorageService::isValidId($id)) {
            return $this->json($response, ['error' => 'Invalid ID'], 400);
        }

        if (!$this->checkRateLimits($request, $id, 'cryptbin.delete', 6, 300)) {
            $audit->logFail('security.ratelimit.hit', ['target_type' => 'cryptbin', 'target_id' => $id]);
            return $this->json($response, ['error' => 'Rate limit exceeded'], 429);
        }

        $meta = $this->storage->readMetadata($id);
        if ($meta === null || $this->isExpired($meta)) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $keyB64 = (string) ($body['key_b64url'] ?? '');
        if (!$this->verifyKey($meta, $keyB64)) {
            $audit->logFail('cryptbin.delete.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'Invalid key']);
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $authResult = $this->verifyOperationAssertion($request, $id, self::OP_DELETE, $body);
        if ($authResult === null) {
            $audit->logFail('cryptbin.delete.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'WebAuthn verification failed']);
            return $this->json($response, ['error' => 'WebAuthn verification failed'], 403);
        }

        if (!$this->storage->deleteItem($id)) {
            $audit->logFail('cryptbin.delete.fail', ['target_type' => 'cryptbin', 'target_id' => $id, 'failure_reason' => 'Delete failed']);
            return $this->json($response, ['error' => 'Unable to delete item'], 500);
        }

        $audit->logSuccess('cryptbin.delete.success', [
            'target_type' => 'cryptbin',
            'target_id' => $id,
            'webauthn_credential_id' => $authResult['credential_db_id'],
            'webauthn_credential_public_id' => $authResult['credential_id'],
        ]);

        return $this->json($response, ['success' => true]);
    }

    private function verifyOperationAssertion(Request $request, string $id, string $op, array $body): ?array
    {
        $nonce = (string) ($body['nonce'] ?? '');
        $credentialId = (string) ($body['id'] ?? '');
        $authenticatorData = (string) ($body['response']['authenticatorData'] ?? '');
        $clientDataJSON = (string) ($body['response']['clientDataJSON'] ?? '');
        $signature = (string) ($body['response']['signature'] ?? '');

        if ($nonce === '' || $credentialId === '' || $authenticatorData === '' || $clientDataJSON === '' || $signature === '') {
            return null;
        }

        SessionManager::start();
        $operations = (array) SessionManager::get('cryptbin_webauthn_ops', []);
        $operation = $operations[$nonce] ?? null;
        unset($operations[$nonce]);
        SessionManager::set('cryptbin_webauthn_ops', $operations);

        if (!is_array($operation)) {
            return null;
        }

        if (!isset($operation['id'], $operation['op'], $operation['challenge'], $operation['expires_at'])) {
            return null;
        }

        if ((int) $operation['expires_at'] < time()) {
            return null;
        }

        if (!hash_equals((string) $operation['id'], $id)) {
            return null;
        }

        if (!hash_equals((string) $operation['op'], $op)) {
            return null;
        }

        if (!$this->hasUserVerificationFlag($authenticatorData)) {
            return null;
        }

        $verified = $this->webauthn->verifyAssertion(
            $credentialId,
            $clientDataJSON,
            $authenticatorData,
            $signature,
            (string) $operation['challenge']
        );

        if (!$verified) {
            return null;
        }

        $credential = $this->webauthn->getCredentialById($credentialId);
        if (!$credential) {
            return null;
        }

        return [
            'credential_id' => $credentialId,
            'credential_db_id' => (int) $credential['id'],
        ];
    }

    private function hasUserVerificationFlag(string $authenticatorDataB64Url): bool
    {
        $authData = Base64Url::decode($authenticatorDataB64Url);
        if ($authData === false || strlen($authData) < 33) {
            return false;
        }

        $flags = ord($authData[32]);
        return ($flags & 0x04) !== 0;
    }

    private function verifyKey(array $metadata, string $keyB64): bool
    {
        return CryptbinKeyVerifier::verify($keyB64, (string) ($metadata['verifier'] ?? ''));
    }

    private function isAllowedOperation(string $op): bool
    {
        return in_array($op, [
            self::OP_WRAP_CREATE,
            self::OP_UNWRAP_VIEW,
            self::OP_UPDATE,
            self::OP_DELETE,
        ], true);
    }

    private function isExpired(array $meta): bool
    {
        if (!isset($meta['expires_at'])) {
            return false;
        }

        $expiry = strtotime((string) $meta['expires_at']);
        if ($expiry === false) {
            return false;
        }

        return $expiry < time();
    }

    private function validateCsrf(array $body): bool
    {
        $token = (string) ($body['csrf_token'] ?? '');
        return $token !== '' && CSRFProtection::validateToken($token);
    }

    private function checkRateLimits(Request $request, string $id, string $action, int $maxAttempts, int $windowSeconds): bool
    {
        $ip = (string) $request->getAttribute('ip_address', '0.0.0.0');

        $ipAllowed = $this->rateLimiter->check('ip:' . $ip, $action, $maxAttempts, $windowSeconds);
        $idAllowed = $this->rateLimiter->check('id:' . $id, $action, $maxAttempts, $windowSeconds);

        return $ipAllowed && $idAllowed;
    }

    private function audit(Request $request): AuditLogger
    {
        /** @var AuditLogger $audit */
        $audit = $request->getAttribute('audit_logger');
        return $audit;
    }

    private function json(Response $response, array $payload, int $status = 200): Response
    {
        $response->getBody()->write(json_encode($payload));
        return $response
            ->withStatus($status)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store');
    }
}
