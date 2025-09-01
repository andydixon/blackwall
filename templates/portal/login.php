<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal Login - BlackWall</title>
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
                            <h1 class="h3 mb-3 fw-bold">🔒 BlackWall Portal</h1>
                            <p class="text-muted">Manage your projects and security keys</p>
                        </div>

                        <div id="login-container">
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
                    <small class="text-muted">BlackWall Portal • WebAuthn Authentication</small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const csrfToken = <?= json_encode($csrfToken) ?>;

        function base64ToArrayBuffer(base64) {
            const binaryString = window.atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }

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
            
            errorEl.classList.add('d-none');
            statusEl.classList.remove('d-none');
            statusEl.querySelector('span').textContent = 'Requesting challenge...';

            try {
                const challengeResp = await fetch('/portal/login/challenge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ csrf_token: csrfToken })
                });

                const challengeData = await challengeResp.json();
                
                statusEl.querySelector('span').textContent = 'Touch your security key...';

                const publicKeyOptions = {
                    challenge: base64ToArrayBuffer(challengeData.challenge),
                    timeout: challengeData.timeout,
                    rpId: challengeData.rpId,
                    userVerification: challengeData.userVerification
                };

                const credential = await navigator.credentials.get({
                    publicKey: publicKeyOptions
                });

                statusEl.querySelector('span').textContent = 'Verifying...';

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

                const verifyResp = await fetch('/portal/login/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(credentialData)
                });

                const verifyData = await verifyResp.json();

                if (verifyData.success) {
                    statusEl.querySelector('span').textContent = 'Success! Redirecting...';
                    window.location.href = verifyData.redirect || '/portal';
                } else {
                    throw new Error(verifyData.error || 'Authentication failed');
                }

            } catch (error) {
                console.error(error);
                errorEl.textContent = error.message || 'Authentication failed. Please try again.';
                errorEl.classList.remove('d-none');
                statusEl.classList.add('d-none');
            }
        });
    </script>
</body>
</html>
