<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-5">
                <div class="card shadow-lg">
                    <div class="card-body p-5">
                        <div class="text-center mb-4">
                            <h1 class="h3 mb-3 fw-bold">🔒 BlackWall</h1>
                            <p class="text-muted">OAuth 2.1 + OpenID Connect</p>
                        </div>

                        <div id="login-container">
                            <h5 class="mb-3">Administrator Login</h5>
                            <p class="small text-muted">Authenticate using your WebAuthn security key or platform authenticator.</p>
                            
                            <button id="webauthn-login" class="btn btn-primary w-100 py-2">
                                🔑 Authenticate with WebAuthn
                            </button>

                            <div id="error-message" class="alert alert-danger mt-3 d-none"></div>
                            <div id="status-message" class="text-center text-muted mt-3 d-none">
                                <div class="spinner-border spinner-border-sm me-2"></div>
                                <span></span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="text-center mt-3">
                    <small class="text-muted">BlackWall v1.0 • WebAuthn-Only Authentication</small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const csrfToken = <?= json_encode($csrfToken) ?>;

        // Helper function to convert base64 to ArrayBuffer
        function base64ToArrayBuffer(base64) {
            const binaryString = window.atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }

        // Helper function to convert ArrayBuffer to base64
        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        }

        document.getElementById('webauthn-login').addEventListener('click', async () => {
            const errorEl = document.getElementById('error-message');
            const statusEl = document.getElementById('status-message');
            let requestedRpId = null;
            
            errorEl.classList.add('d-none');
            statusEl.classList.remove('d-none');
            statusEl.querySelector('span').textContent = 'Requesting challenge...';

            try {
                // Get challenge
                const challengeResp = await fetch('/admin/login/challenge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ csrf_token: csrfToken })
                });

                const challengeData = await challengeResp.json();
                requestedRpId = challengeData.rpId || null;
                
                statusEl.querySelector('span').textContent = 'Touch your security key...';

                // Prepare WebAuthn options
                const publicKeyOptions = {
                    challenge: base64ToArrayBuffer(challengeData.challenge),
                    timeout: challengeData.timeout,
                    rpId: challengeData.rpId,
                    userVerification: challengeData.userVerification
                };

                // Call WebAuthn API to get credential
                const credential = await navigator.credentials.get({
                    publicKey: publicKeyOptions
                });

                statusEl.querySelector('span').textContent = 'Verifying...';

                // Prepare credential data for server
                const credentialData = {
                    csrf_token: csrfToken,
                    id: credential.id,
                    rawId: arrayBufferToBase64(credential.rawId),
                    type: credential.type,
                    response: {
                        authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                        signature: arrayBufferToBase64(credential.response.signature),
                        userHandle: credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null
                    }
                };

                const verifyResp = await fetch('/admin/login/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(credentialData)
                });

                const verifyData = await verifyResp.json();

                if (verifyData.success) {
                    statusEl.querySelector('span').textContent = 'Success! Redirecting...';
                    window.location.href = verifyData.redirect || '/admin/dashboard';
                } else {
                    throw new Error(verifyData.error || 'Authentication failed');
                }

            } catch (error) {
                console.error(error);
                if (error && error.name === 'SecurityError') {
                    const rp = requestedRpId || 'unknown';
                    errorEl.textContent = `WebAuthn domain mismatch: page host is ${window.location.hostname}, but rpId is ${rp}.`;
                } else {
                    errorEl.textContent = error.message || 'Authentication failed. Please try again.';
                }
                errorEl.classList.remove('d-none');
                statusEl.classList.add('d-none');
            }
        });
    </script>
</body>
</html>
