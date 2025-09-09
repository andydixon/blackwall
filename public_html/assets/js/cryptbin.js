(function () {
    'use strict';

    const config = window.CRYPTBIN_CONFIG || {};
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    let currentMeta = null;
    let currentPlaintext = null;

    function showAlert(type, message) {
        const alert = document.getElementById('cryptbin-alert');
        if (!alert) {
            return;
        }

        alert.className = 'alert alert-' + type;
        alert.textContent = message;
        alert.classList.remove('d-none');
    }

    function clearAlert() {
        const alert = document.getElementById('cryptbin-alert');
        if (!alert) {
            return;
        }
        alert.classList.add('d-none');
        alert.textContent = '';
    }

    function base64ToBytes(value) {
        const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
        const padding = normalized.length % 4;
        const padded = padding === 0 ? normalized : normalized + '='.repeat(4 - padding);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function bytesToBase64Url(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i += 1) {
            binary += String.fromCharCode(bytes[i]);
        }

        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    function randomBase64Url(length) {
        const bytes = new Uint8Array(length);
        crypto.getRandomValues(bytes);
        return bytesToBase64Url(bytes);
    }

    function randomId() {
        const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        let result = '';
        while (result.length < 16) {
            const bytes = new Uint8Array(16);
            crypto.getRandomValues(bytes);
            for (let i = 0; i < bytes.length && result.length < 16; i += 1) {
                // Rejection sampling avoids modulo bias for 62-char alphabet.
                if (bytes[i] < 248) {
                    result += chars[bytes[i] % chars.length];
                }
            }
        }
        return result;
    }

    async function encryptAesGcm(plaintextBytes, dekBytes) {
        const iv = new Uint8Array(12);
        crypto.getRandomValues(iv);

        const key = await crypto.subtle.importKey(
            'raw',
            dekBytes,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            plaintextBytes
        );

        return {
            ciphertext: new Uint8Array(encrypted),
            iv: iv,
            algorithm: 'AES-256-GCM'
        };
    }

    async function decryptAesGcm(ciphertextBytes, dekBytes, ivBytes) {
        const key = await crypto.subtle.importKey(
            'raw',
            dekBytes,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBytes },
            key,
            ciphertextBytes
        );

        return new Uint8Array(plaintext);
    }

    async function postJson(url, payload) {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const message = data.error || ('Request failed: ' + response.status);
            throw new Error(message);
        }

        return data;
    }

    async function getJson(url) {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        });

        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || ('Request failed: ' + response.status));
        }

        return data;
    }

    function toPublicKeyCredentialRequestOptions(publicKey) {
        return {
            challenge: base64ToBytes(publicKey.challenge),
            timeout: publicKey.timeout,
            rpId: publicKey.rpId,
            userVerification: publicKey.userVerification
        };
    }

    async function runWebAuthnOperation(id, op) {
        const challenge = await postJson('/cryptbin/' + encodeURIComponent(id) + '/webauthn/challenge', {
            csrf_token: config.csrfToken,
            op: op
        });

        const assertion = await navigator.credentials.get({
            publicKey: toPublicKeyCredentialRequestOptions(challenge.publicKey)
        });

        return {
            nonce: challenge.nonce,
            id: assertion.id,
            rawId: bytesToBase64Url(new Uint8Array(assertion.rawId)),
            response: {
                clientDataJSON: bytesToBase64Url(new Uint8Array(assertion.response.clientDataJSON)),
                authenticatorData: bytesToBase64Url(new Uint8Array(assertion.response.authenticatorData)),
                signature: bytesToBase64Url(new Uint8Array(assertion.response.signature)),
                userHandle: assertion.response.userHandle ? bytesToBase64Url(new Uint8Array(assertion.response.userHandle)) : null
            },
            type: assertion.type
        };
    }

    async function handleCreate() {
        clearAlert();

        if (!window.PublicKeyCredential || !window.crypto?.subtle) {
            showAlert('danger', 'WebAuthn and WebCrypto support are required.');
            return;
        }

        const isText = document.getElementById('text-tab').classList.contains('active');
        const id = randomId();
        const keyB64 = randomBase64Url(32);
        const dekBytes = base64ToBytes(randomBase64Url(32));

        let plaintextBytes;
        let mimeType;
        let filename;
        let itemType;

        if (isText) {
            const value = document.getElementById('text-input').value;
            plaintextBytes = encoder.encode(value);
            itemType = 'text';
            mimeType = 'text/plain;charset=utf-8';
            filename = 'cryptbin.txt';

            if (plaintextBytes.length === 0) {
                showAlert('warning', 'Enter text before creating a Cryptbin item.');
                return;
            }

            if (plaintextBytes.length > config.maxTextBytes) {
                showAlert('danger', 'Text exceeds max bytes: ' + config.maxTextBytes);
                return;
            }
        } else {
            const fileInput = document.getElementById('file-input');
            const file = fileInput.files[0];
            if (!file) {
                showAlert('warning', 'Select a file before creating a Cryptbin item.');
                return;
            }

            const fileArray = await file.arrayBuffer();
            plaintextBytes = new Uint8Array(fileArray);
            itemType = 'file';
            mimeType = file.type || 'application/octet-stream';
            filename = file.name || 'cryptbin.bin';
        }

        const encrypted = await encryptAesGcm(plaintextBytes, dekBytes);

        if (encrypted.ciphertext.length > config.maxUploadBytes) {
            showAlert('danger', 'Encrypted payload exceeds max bytes: ' + config.maxUploadBytes);
            return;
        }

        try {
            const assertion = await runWebAuthnOperation(id, 'wrap_create');
            const wrapped = await postJson('/cryptbin/' + encodeURIComponent(id) + '/wrap', {
                csrf_token: config.csrfToken,
                op: 'wrap_create',
                nonce: assertion.nonce,
                id: assertion.id,
                rawId: assertion.rawId,
                response: assertion.response,
                dek_b64url: bytesToBase64Url(dekBytes)
            });

            const created = await postJson('/cryptbin/create', {
                csrf_token: config.csrfToken,
                id: id,
                key_b64url: keyB64,
                item_type: itemType,
                original_filename: filename,
                mime_type: mimeType,
                cipher_alg: encrypted.algorithm,
                cipher_nonce_b64url: bytesToBase64Url(encrypted.iv),
                ciphertext_b64url: bytesToBase64Url(encrypted.ciphertext),
                wrapped_dek: wrapped.wrapped.wrapped_dek,
                wrapped_dek_nonce: wrapped.wrapped.wrapped_dek_nonce,
                wrapped_dek_alg: wrapped.wrapped.wrapped_dek_alg,
                kek_version: wrapped.wrapped.kek_version
            });

            window.location.href = '/cryptbin/' + encodeURIComponent(id) + '/share#' + keyB64;
        } catch (error) {
            showAlert('danger', error.message || 'Failed to create Cryptbin item.');
        }
    }

    async function fetchCiphertext(id) {
        const response = await fetch('/cryptbin/' + encodeURIComponent(id) + '/ciphertext', {
            method: 'GET',
            headers: {
                'Accept': 'application/octet-stream'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load ciphertext payload');
        }

        const arrayBuffer = await response.arrayBuffer();
        return new Uint8Array(arrayBuffer);
    }

    function currentKeyFromFragment() {
        const hash = window.location.hash || '';
        return hash.startsWith('#') ? hash.slice(1) : hash;
    }

    async function loadView() {
        clearAlert();

        if (!window.PublicKeyCredential || !window.crypto?.subtle) {
            showAlert('danger', 'WebAuthn and WebCrypto support are required.');
            return;
        }

        const id = config.id;
        const keyB64 = currentKeyFromFragment();
        const keyWarning = document.getElementById('key-warning');
        keyWarning.classList.toggle('d-none', keyB64.length > 0);

        currentMeta = await getJson('/cryptbin/' + encodeURIComponent(id) + '/meta');
        const ciphertext = await fetchCiphertext(id);

        const unwrapAssertion = await runWebAuthnOperation(id, 'unwrap_view');
        const unwrap = await postJson('/cryptbin/' + encodeURIComponent(id) + '/unwrap', {
            csrf_token: config.csrfToken,
            op: 'unwrap_view',
            nonce: unwrapAssertion.nonce,
            id: unwrapAssertion.id,
            rawId: unwrapAssertion.rawId,
            response: unwrapAssertion.response
        });

        const dekBytes = base64ToBytes(unwrap.dek_b64url);
        const ivBytes = base64ToBytes(currentMeta.cipher_nonce_b64url);
        const plaintext = await decryptAesGcm(ciphertext, dekBytes, ivBytes);
        currentPlaintext = plaintext;

        document.getElementById('loading-state').classList.add('d-none');

        if (currentMeta.item_type === 'text') {
            document.getElementById('text-content-wrapper').classList.remove('d-none');
            document.getElementById('text-content').value = decoder.decode(plaintext);
            document.getElementById('update-file-input').disabled = true;
        } else {
            document.getElementById('file-content-wrapper').classList.remove('d-none');
            document.getElementById('update-file-input').disabled = false;

            const meta = document.getElementById('file-meta');
            meta.textContent = (currentMeta.original_filename || 'download.bin') + ' (' + (plaintext.length) + ' bytes)';

            const blob = new Blob([plaintext], { type: currentMeta.mime_type || 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const downloadBtn = document.getElementById('download-btn');
            downloadBtn.onclick = function () {
                const link = document.createElement('a');
                link.href = url;
                link.download = currentMeta.original_filename || 'cryptbin.bin';
                document.body.appendChild(link);
                link.click();
                link.remove();
            };
        }

        showAlert('success', 'Item decrypted successfully.');
    }

    async function handleUpdate() {
        clearAlert();

        const id = config.id;
        const keyB64 = currentKeyFromFragment();
        if (!keyB64) {
            showAlert('warning', 'Missing key fragment. Update requires URL fragment key.');
            return;
        }

        let plaintextBytes;
        let itemType;
        let filename;
        let mimeType;

        const fileInput = document.getElementById('update-file-input');
        const selectedFile = fileInput.files[0];

        if (selectedFile) {
            plaintextBytes = new Uint8Array(await selectedFile.arrayBuffer());
            itemType = 'file';
            filename = selectedFile.name || 'cryptbin.bin';
            mimeType = selectedFile.type || 'application/octet-stream';
        } else {
            const textArea = document.getElementById('text-content');
            if (!textArea || textArea.closest('.d-none')) {
                showAlert('warning', 'Select a replacement file to update this item.');
                return;
            }
            plaintextBytes = encoder.encode(textArea.value);
            itemType = 'text';
            filename = 'cryptbin.txt';
            mimeType = 'text/plain;charset=utf-8';

            if (plaintextBytes.length > config.maxTextBytes) {
                showAlert('danger', 'Text exceeds max bytes: ' + config.maxTextBytes);
                return;
            }
        }

        const dekBytes = base64ToBytes(randomBase64Url(32));
        const encrypted = await encryptAesGcm(plaintextBytes, dekBytes);

        if (encrypted.ciphertext.length > config.maxUploadBytes) {
            showAlert('danger', 'Encrypted payload exceeds max bytes: ' + config.maxUploadBytes);
            return;
        }

        try {
            const assertion = await runWebAuthnOperation(id, 'update');
            await postJson('/cryptbin/' + encodeURIComponent(id) + '/update', {
                csrf_token: config.csrfToken,
                op: 'update',
                nonce: assertion.nonce,
                id: assertion.id,
                rawId: assertion.rawId,
                response: assertion.response,
                key_b64url: keyB64,
                item_type: itemType,
                original_filename: filename,
                mime_type: mimeType,
                cipher_alg: encrypted.algorithm,
                cipher_nonce_b64url: bytesToBase64Url(encrypted.iv),
                ciphertext_b64url: bytesToBase64Url(encrypted.ciphertext),
                dek_b64url: bytesToBase64Url(dekBytes)
            });

            window.location.href = '/cryptbin/' + encodeURIComponent(id) + '/share#' + keyB64;
        } catch (error) {
            showAlert('danger', error.message || 'Update failed.');
        }
    }

    function initShareMode() {
        const keyB64 = currentKeyFromFragment();
        const shareUrl = window.location.origin + '/cryptbin/' + encodeURIComponent(config.id) + '#' + keyB64;

        const shareArea = document.getElementById('share-url');
        const copyBtn = document.getElementById('copy-url-btn');
        const copyStatus = document.getElementById('copy-status');
        const openBtn = document.getElementById('open-item-btn');

        if (!shareArea || !copyBtn || !copyStatus || !openBtn) {
            return;
        }

        shareArea.value = shareUrl;
        openBtn.href = '/cryptbin/' + encodeURIComponent(config.id) + '#' + keyB64;

        if (!keyB64) {
            copyStatus.textContent = 'Warning: URL fragment key is missing. Open from a URL containing #<key>.';
        }

        copyBtn.addEventListener('click', async function () {
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(shareUrl);
                } else {
                    shareArea.focus();
                    shareArea.select();
                    document.execCommand('copy');
                }
                copyStatus.textContent = 'Copied. Store this URL securely.';
            } catch (error) {
                copyStatus.textContent = 'Copy failed. Select and copy the URL manually.';
            }
        });
    }

    async function handleDelete() {
        clearAlert();

        const id = config.id;
        const keyB64 = currentKeyFromFragment();
        if (!keyB64) {
            showAlert('warning', 'Missing key fragment. Delete requires URL fragment key.');
            return;
        }

        if (!window.confirm('Delete this Cryptbin item permanently?')) {
            return;
        }

        try {
            const assertion = await runWebAuthnOperation(id, 'delete');
            await postJson('/cryptbin/' + encodeURIComponent(id) + '/delete', {
                csrf_token: config.csrfToken,
                op: 'delete',
                nonce: assertion.nonce,
                id: assertion.id,
                rawId: assertion.rawId,
                response: assertion.response,
                key_b64url: keyB64
            });

            window.location.href = '/cryptbin';
        } catch (error) {
            showAlert('danger', error.message || 'Delete failed.');
        }
    }

    function initCreateMode() {
        const createBtn = document.getElementById('create-btn');
        if (!createBtn) {
            return;
        }

        createBtn.addEventListener('click', function () {
            handleCreate().catch(function (error) {
                showAlert('danger', error.message || 'Unexpected error while creating item.');
            });
        });
    }

    function initViewMode() {
        const updateBtn = document.getElementById('update-btn');
        const deleteBtn = document.getElementById('delete-btn');

        if (updateBtn) {
            updateBtn.addEventListener('click', function () {
                handleUpdate().catch(function (error) {
                    showAlert('danger', error.message || 'Unexpected update error.');
                });
            });
        }

        if (deleteBtn) {
            deleteBtn.addEventListener('click', function () {
                handleDelete().catch(function (error) {
                    showAlert('danger', error.message || 'Unexpected delete error.');
                });
            });
        }

        loadView().catch(function (error) {
            showAlert('danger', error.message || 'Unable to decrypt item.');
        });
    }

    if (config.mode === 'create') {
        initCreateMode();
    } else if (config.mode === 'view') {
        initViewMode();
    } else if (config.mode === 'share') {
        initShareMode();
    }
})();
