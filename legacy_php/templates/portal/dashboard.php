<div class="row">
    <div class="col-12">
        <div class="page-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h2>🏠 User Portal</h2>
                    <p class="text-muted mb-0">Welcome, <strong><?= htmlspecialchars($user['display_label'] ?? $user['uuid']) ?></strong></p>
                </div>
                <div>
                    <form method="POST" action="/portal/logout" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <button type="submit" class="btn btn-outline-light btn-sm">Logout</button>
                    </form>
                </div>
            </div>
        </div>

        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <?php if ($_GET['success'] === 'key_deleted'): ?>
                    ✓ Security key removed successfully
                <?php endif; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['error'])): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?php if ($_GET['error'] === 'cannot_delete_current_key'): ?>
                    ✗ You cannot delete the key you're currently logged in with
                <?php elseif ($_GET['error'] === 'unauthorized'): ?>
                    ✗ Unauthorized action
                <?php elseif ($_GET['error'] === 'invalid_key'): ?>
                    ✗ Invalid key reference
                <?php elseif ($_GET['error'] === 'min_keys'): ?>
                    ✗ You must retain at least <?= (int) \BlackWall\Config::getInt('MIN_WEBAUTHN_KEYS', 1) ?> key(s)
                <?php elseif ($_GET['error'] === 'csrf'): ?>
                    ✗ Invalid request token. Please retry.
                <?php endif; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <!-- Projects Section -->
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">📦 Your Projects</h5>
            </div>
            <div class="card-body">
                <?php if (empty($projects)): ?>
                    <div class="text-center py-4">
                        <div class="fs-1 text-muted mb-3">📦</div>
                        <p class="text-muted">You are not assigned to any projects yet.</p>
                        <p class="small text-muted">Contact your administrator to get access.</p>
                    </div>
                <?php else: ?>
                    <div class="row g-3">
                        <?php foreach ($projects as $project): ?>
                            <div class="col-md-6 col-lg-4">
                                <div class="card stat-card h-100" style="border-left-color: <?= $project['privilege_level'] <= 2 ? '#3b82f6' : ($project['privilege_level'] <= 5 ? '#10b981' : '#f59e0b') ?>">
                                    <div class="card-body">
                                        <div class="d-flex align-items-start mb-2">
                                            <div class="fs-3 me-3">📦</div>
                                            <div class="flex-grow-1">
                                                <h6 class="mb-1"><?= htmlspecialchars($project['name']) ?></h6>
                                                <p class="small text-muted mb-2">
                                                    <?= htmlspecialchars($project['description'] ?? 'No description') ?>
                                                </p>
                                            </div>
                                        </div>
                                        <div class="d-flex align-items-center justify-content-between">
                                            <span class="badge bg-primary"><?= htmlspecialchars($project['privilege_label']) ?></span>
                                            <span class="badge <?= $project['status'] === 'active' ? 'bg-success' : 'bg-secondary' ?>">
                                                <?= htmlspecialchars($project['status']) ?>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Security Keys Section -->
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">🔑 Security Keys</h5>
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addKeyModal">
                        + Add Key
                    </button>
                </div>
            </div>
            <div class="card-body">
                <?php if (empty($credentials)): ?>
                    <div class="text-center py-4">
                        <div class="fs-1 text-muted mb-3">🔑</div>
                        <p class="text-muted">No security keys found.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>Label</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th>Last Used</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($credentials as $cred): ?>
                                    <tr>
                                        <td>
                                            <strong><?= htmlspecialchars($cred['label'] ?? 'Unnamed Key') ?></strong>
                                            <?php if ((int)$cred['id'] === $loginCredentialId): ?>
                                                <span class="badge bg-success ms-2">Current Session</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <span class="badge bg-success">Active</span>
                                        </td>
                                        <td class="text-muted">
                                            <?= date('M j, Y', strtotime($cred['created_at'])) ?>
                                        </td>
                                        <td class="text-muted">
                                            <?= $cred['last_used_at'] ? date('M j, Y H:i', strtotime($cred['last_used_at'])) : 'Never' ?>
                                        </td>
                                        <td>
                                            <?php if ((int)$cred['id'] === $loginCredentialId): ?>
                                                <span class="text-muted small">Cannot delete current key</span>
                                            <?php else: ?>
                                                <form method="POST" action="/portal/keys/<?= urlencode($cred['credential_id']) ?>/delete" class="d-inline" 
                                                      onsubmit="return confirm('Are you sure you want to delete this security key? This action cannot be undone.')">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- User Info Section -->
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">👤 Account Information</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-muted">User UUID</h6>
                        <code><?= htmlspecialchars($user['uuid']) ?></code>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-muted">Display Label</h6>
                        <p class="mb-0"><?= htmlspecialchars($user['display_label'] ?? '-') ?></p>
                    </div>
                </div>
                <div class="row mt-3">
                    <div class="col-md-6">
                        <h6 class="text-muted">Account Status</h6>
                        <span class="badge bg-success"><?= htmlspecialchars($user['status']) ?></span>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-muted">Account Created</h6>
                        <p class="mb-0"><?= date('M j, Y', strtotime($user['created_at'])) ?></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Add Key Modal -->
<div class="modal fade" id="addKeyModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content bg-dark">
            <div class="modal-header">
                <h5 class="modal-title">Add Security Key</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label">Key Label</label>
                    <input type="text" id="keyLabel" class="form-control" placeholder="e.g., YubiKey 5, Touch ID" value="My Security Key">
                    <div class="form-text">Give your key a recognizable name</div>
                </div>
                <div id="addKeyStatus" class="alert d-none"></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" id="addKeyBtn" class="btn btn-primary">Register Key</button>
            </div>
        </div>
    </div>
</div>

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

    document.getElementById('addKeyBtn').addEventListener('click', async () => {
        const statusEl = document.getElementById('addKeyStatus');
        const label = document.getElementById('keyLabel').value.trim();

        if (!label) {
            statusEl.className = 'alert alert-danger';
            statusEl.textContent = 'Please enter a label for your key';
            statusEl.classList.remove('d-none');
            return;
        }

        statusEl.className = 'alert alert-info';
        statusEl.textContent = 'Touch your security key...';
        statusEl.classList.remove('d-none');

        try {
            // Get registration options
            const optionsResp = await fetch('/portal/keys/add/init', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csrf_token: csrfToken })
            });

            const options = await optionsResp.json();

            // Prepare options for WebAuthn API
            const publicKeyOptions = {
                ...options,
                challenge: base64ToArrayBuffer(options.challenge),
                user: {
                    ...options.user,
                    id: base64ToArrayBuffer(options.user.id)
                }
            };

            // Create credential
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions
            });

            statusEl.textContent = 'Verifying credential...';

            // Send to server
            const credentialData = {
                csrf_token: csrfToken,
                id: credential.id,
                rawId: arrayBufferToBase64(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                    attestationObject: arrayBufferToBase64(credential.response.attestationObject)
                },
                label: label
            };

            const registerResp = await fetch('/portal/keys/add/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(credentialData)
            });

            const result = await registerResp.json();

            if (result.success) {
                statusEl.className = 'alert alert-success';
                statusEl.textContent = 'Security key added successfully! Reloading...';
                setTimeout(() => window.location.reload(), 1500);
            } else {
                throw new Error(result.error || 'Registration failed');
            }
        } catch (error) {
            console.error(error);
            statusEl.className = 'alert alert-danger';
            statusEl.textContent = error.message || 'Failed to register key. Please try again.';
        }
    });
</script>
