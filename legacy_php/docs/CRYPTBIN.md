# Cryptbin

## Overview

Cryptbin is a no-account encrypted pastebin facility with access controlled by:

- `id`: 16-character random token in URL path (`/cryptbin/<ID>`)
- `key` (`KB`): 32-byte client-held secret in URL fragment (`#<KB>`) so the server never receives it automatically

Example URL:

`/cryptbin/A1b2C3d4E5f6G7h8#<base64url-encoded-32-byte-key>`

## Threat Model Assumptions

- TLS is trusted in transit.
- Browser runtime is trusted while the session is active.
- Server is trusted to enforce WebAuthn challenge verification and KEK usage controls.
- Server compromise can expose ciphertext and wrapped DEKs, but not plaintext directly.
- URL fragments are handled client-side only; they are not sent in HTTP requests.

## Crypto Design

### Data Encryption

- Client generates DEK (32 random bytes) per item.
- Client encrypts plaintext with `AES-256-GCM` (WebCrypto).
- Server stores only ciphertext + crypto metadata.
- Plaintext is never sent to server.

### Access Key Verifier

- Client key `KB` is base64url(32 random bytes).
- Server stores only an Argon2id verifier of `KB` (`password_hash(..., PASSWORD_ARGON2ID)`).
- Update/Delete require successful `password_verify` of provided `KB` against stored verifier.
- Server never stores `KB` in plaintext.

### Tier 2 Envelope Encryption (DEK/KEK)

- Server holds KEK (`CRYPTBIN_KEK_BASE64`, 32 bytes).
- DEK is wrapped server-side using libsodium XChaCha20-Poly1305 with AAD bound to item ID.
- Wrap/unwrap operations are WebAuthn-gated with UV required.
- DEK is transiently present server-side only during wrap/unwrap and then discarded.

## WebAuthn Authorization Policy

Cryptbin requires WebAuthn for every KEK operation:

- create wrap (`wrap_create`)
- view unwrap (`unwrap_view`)
- update (`update`)
- delete (`delete`)

Each operation uses:

- one-time server-issued nonce
- one-time challenge
- operation binding (`op`)
- item binding (`id`)
- short TTL (120s)

Replay is prevented by consuming nonce+challenge exactly once.

## API Endpoints

- `GET /cryptbin` create page
- `POST /cryptbin/create` store ciphertext+metadata
- `GET /cryptbin/<ID>` view shell
- `GET /cryptbin/<ID>/meta` safe metadata
- `GET /cryptbin/<ID>/ciphertext` ciphertext bytes
- `POST /cryptbin/<ID>/webauthn/challenge` operation-bound challenge
- `POST /cryptbin/<ID>/wrap` wrap DEK for create
- `POST /cryptbin/<ID>/unwrap` unwrap DEK for view
- `POST /cryptbin/<ID>/update` verify key + WebAuthn + rewrap new DEK + replace ciphertext
- `POST /cryptbin/<ID>/delete` verify key + WebAuthn + delete metadata/payload

## Storage Layout

Configured by `CRYPTBIN_STORAGE_PATH` (must be outside `public_html`):

- `<ID>.bin` ciphertext bytes
- `<ID>.json` metadata (`verifier`, wrapped DEK metadata, mime, filename, timestamps)

Writes are atomic via temporary file + rename.
Deletes use a two-step rename-then-remove process to avoid partial state.

## Configuration

Required:

- `CRYPTBIN_KEK_BASE64` (base64 for 32 random bytes)

Recommended:

- `CRYPTBIN_STORAGE_PATH` (outside web root)
- `CRYPTBIN_MAX_UPLOAD_BYTES`
- `CRYPTBIN_MAX_TEXT_BYTES`
- `CRYPTBIN_ALLOWED_MIME` (optional CSV allow-list)
- `CRYPTBIN_DEFAULT_RETENTION_DAYS` (optional)
- `CRYPTBIN_KEK_VERSION`

Generate KEK example:

```bash
openssl rand -base64 32
```

## Deployment Notes

1. Ensure storage directory exists and is writable by PHP process.
2. Keep storage outside `public_html`.
3. Keep `CRYPTBIN_KEK_BASE64` in environment secret storage.
4. Enforce HTTPS (required by WebAuthn).

## KEK Rotation (Operational Strategy)

- Introduce new KEK with incremented `CRYPTBIN_KEK_VERSION`.
- During maintenance task, iterate items:
  1. unwrap DEK with old KEK version
  2. wrap DEK with new KEK
  3. update `wrapped_dek*` + `kek_version` in metadata atomically
- Retain previous KEK until migration completes.

