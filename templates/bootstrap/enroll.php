<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bootstrap - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-6">
                <div class="card bg-secondary">
                    <div class="card-body p-4">
                        <h3 class="mb-3">🔐 BlackWall Bootstrap</h3>
                        <p>Complete WebAuthn credential enrollment for user:</p>
                        <p><strong><?= htmlspecialchars($user['display_label'] ?? $user['uuid']) ?></strong></p>

                        <div id="enroll-container">
                            <button id="enroll-btn" class="btn btn-primary">
                                Register Security Key
                            </button>
                        </div>

                        <div id="status" class="alert alert-info mt-3 d-none"></div>
                        <div id="error" class="alert alert-danger mt-3 d-none"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const options = <?= json_encode($options) ?>;
        const token = <?= json_encode($token) ?>;

        document.getElementById('enroll-btn').addEventListener('click', async () => {
            const statusEl = document.getElementById('status');
            const errorEl = document.getElementById('error');
            
            statusEl.classList.remove('d-none');
            statusEl.textContent = 'Enrolling credential...';
            errorEl.classList.add('d-none');

            try {
                // Simplified enrollment - production would use actual WebAuthn
                const credentialId = 'bootstrap-' + Date.now();
                
                const response = await fetch('/bootstrap/enroll', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        token: token,
                        credential_id: credentialId,
                        public_key: 'PLACEHOLDER_PUBLIC_KEY',
                    })
                });

                const data = await response.json();

                if (data.success) {
                    statusEl.textContent = 'Success! Redirecting...';
                    setTimeout(() => {
                        window.location.href = data.redirect;
                    }, 1000);
                } else {
                    throw new Error(data.error || 'Enrollment failed');
                }
            } catch (error) {
                console.error(error);
                statusEl.classList.add('d-none');
                errorEl.textContent = error.message;
                errorEl.classList.remove('d-none');
            }
        });
    </script>
</body>
</html>
