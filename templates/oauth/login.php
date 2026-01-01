<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to <?= htmlspecialchars($clientName) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">
    <div class="container">
        <div class="row justify-content-center min-vh-100 align-items-center">
            <div class="col-md-5">
                <div class="card bg-dark border-secondary shadow-lg">
                    <div class="card-body p-5">
                        <div class="text-center mb-4">
                            <?php if (!empty($organization) && !empty($organization->logoUrl)): ?>
                                <img src="<?= htmlspecialchars($organization->logoUrl) ?>" alt="<?= htmlspecialchars($organization->name) ?>" style="max-height: 56px;" class="mb-3">
                            <?php endif; ?>
                            <h1 class="h3 fw-bold">Sign in to continue</h1>
                            <p class="text-muted mb-0"><?= htmlspecialchars($clientName) ?> is requesting access</p>
                        </div>

                        <div id="error" class="alert alert-danger d-none"></div>

                        <div class="text-center py-4">
                            <button id="loginBtn" class="btn btn-primary btn-lg px-5">
                                <i class="bi bi-shield-check"></i> Sign in with Security Key
                            </button>
                        </div>

                        <div class="text-center mt-4">
                            <small class="text-muted">
                                You'll use your security key or biometric authentication to sign in
                            </small>
                        </div>
                    </div>
                </div>
                
                <div class="text-center mt-3">
                    <small class="text-muted">
                        <?php if (!empty($organization)): ?>
                            <?= htmlspecialchars($organization->name) ?> ·
                        <?php endif; ?>
                        Powered by <strong>BlackWall</strong> · 
                        <a href="<?= htmlspecialchars($returnUrl) ?>" class="text-decoration-none">Cancel</a>
                    </small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const csrfToken = <?= json_encode($csrfToken ?? '') ?>;
        const loginBtn = document.getElementById('loginBtn');
        const errorDiv = document.getElementById('error');

        loginBtn.addEventListener('click', async () => {
            try {
                loginBtn.disabled = true;
                loginBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Preparing...';
                errorDiv.classList.add('d-none');

                // Get challenge
                const challengeResp = await fetch('/oauth/login/challenge', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ csrf_token: csrfToken })
                });
                
                if (!challengeResp.ok) throw new Error('Failed to get challenge');
                
                const challengeData = await challengeResp.json();
                
                loginBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Touch your security key...';

                // Create credential request
                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: Uint8Array.from(atob(challengeData.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                        timeout: 60000,
                        rpId: window.location.hostname,
                        userVerification: 'required'
                    }
                });

                loginBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Verifying...';

                // Verify credential
                const verifyResp = await fetch('/oauth/login/verify', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        csrf_token: csrfToken,
                        id: credential.id,
                        rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                        type: credential.type,
                        response: {
                            authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                            signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                            userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
                        }
                    })
                });

                const verifyData = await verifyResp.json();
                
                if (verifyData.success) {
                    window.location.href = verifyData.redirect;
                } else {
                    throw new Error(verifyData.error || 'Authentication failed');
                }
            } catch (err) {
                console.error(err);
                errorDiv.textContent = err.message || 'Authentication failed. Please try again.';
                errorDiv.classList.remove('d-none');
                loginBtn.disabled = false;
                loginBtn.innerHTML = '<i class="bi bi-shield-check"></i> Try Again';
            }
        });
    </script>
</body>
</html>
