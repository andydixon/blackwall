<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enroll Security Key - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-6">
                <div class="card bg-secondary">
                    <div class="card-body p-4">
                        <h3 class="mb-3">🔐 Enroll Security Key</h3>
                        <p>Complete WebAuthn credential enrollment for:</p>
                        <p><strong><?= htmlspecialchars($user['display_label'] ?? $user['uuid']) ?></strong></p>

                        <div id="enroll-container">
                            <button id="enroll-btn" class="btn btn-primary btn-lg w-100">
                                Register Security Key
                            </button>
                        </div>

                        <div id="status" class="alert alert-info mt-3 d-none"></div>
                        <div id="error" class="alert alert-danger mt-3 d-none"></div>

                        <div class="mt-4 text-muted small">
                            <p class="mb-1"><strong>Instructions:</strong></p>
                            <ul class="mb-0">
                                <li>Click the button above to begin</li>
                                <li>Follow your browser's prompts to use your security key</li>
                                <li>You may need to touch your security key or authenticate with biometrics</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const options = <?= json_encode($options) ?>;
        const token = <?= json_encode($token) ?>;

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

        document.getElementById('enroll-btn').addEventListener('click', async () => {
            const statusEl = document.getElementById('status');
            const errorEl = document.getElementById('error');
            
            statusEl.classList.remove('d-none');
            statusEl.textContent = 'Touch your security key...';
            errorEl.classList.add('d-none');

            try {
                // Convert challenge and user.id from base64 to ArrayBuffer
                const publicKeyOptions = {
                    ...options,
                    challenge: base64ToArrayBuffer(options.challenge),
                    user: {
                        ...options.user,
                        id: base64ToArrayBuffer(options.user.id)
                    }
                };

                // Call WebAuthn API
                const credential = await navigator.credentials.create({
                    publicKey: publicKeyOptions
                });

                statusEl.textContent = 'Verifying credential...';

                // Prepare credential data for server
                const credentialData = {
                    token: token,
                    id: credential.id,
                    rawId: arrayBufferToBase64(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                        attestationObject: arrayBufferToBase64(credential.response.attestationObject)
                    }
                };

                const response = await fetch('/enroll/complete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(credentialData)
                });

                const data = await response.json();

                if (data.success) {
                    statusEl.classList.remove('alert-info');
                    statusEl.classList.add('alert-success');
                    statusEl.textContent = '✅ Success! Your security key has been enrolled. Redirecting...';
                    setTimeout(() => {
                        window.location.href = data.redirect;
                    }, 2000);
                } else {
                    throw new Error(data.error || 'Enrollment failed');
                }
            } catch (error) {
                console.error(error);
                statusEl.classList.add('d-none');
                if (error && error.name === 'SecurityError') {
                    const rp = (options.rp && options.rp.id) ? options.rp.id : 'unknown';
                    errorEl.textContent = `WebAuthn domain mismatch: page host is ${window.location.hostname}, but rpId is ${rp}.`;
                } else {
                    errorEl.textContent = error.message || 'WebAuthn registration failed';
                }
                errorEl.classList.remove('d-none');
            }
        });
    </script>
</body>
</html>
