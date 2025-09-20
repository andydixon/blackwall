<div class="row mb-4">
    <div class="col">
        <h1 class="display-6 mb-3">User Details</h1>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="/admin/users">Users</a></li>
                <li class="breadcrumb-item active"><?= htmlspecialchars($user->displayLabel ?? $user->uuid) ?></li>
            </ol>
        </nav>
    </div>
</div>

<?php if (isset($_GET['error']) && $_GET['error'] === 'min_keys'): ?>
    <div class="alert alert-danger mb-4">
        Cannot delete credential. User must retain at least <?= (int) \BlackWall\Config::getInt('MIN_WEBAUTHN_KEYS', 1) ?> key(s).
    </div>
<?php endif; ?>

<?php if (isset($_GET['success']) && $_GET['success'] === 'delete_requested'): ?>
    <div class="alert alert-success mb-4">
        Credential deletion request submitted for approval.
    </div>
<?php endif; ?>

<?php if (isset($enrollmentLink)): ?>
    <div class="alert alert-success border-success mb-4" role="alert">
        <h4 class="alert-heading">✅ Enrollment Link Generated!</h4>
        <p class="mb-2">Send this link to the user to enroll their security key. The link expires in 24 hours:</p>
        <div class="input-group mt-3">
            <input type="text" class="form-control bg-dark border-success text-success font-monospace" 
                   value="<?= htmlspecialchars($enrollmentLink) ?>" readonly id="enrollmentLink">
            <button class="btn btn-outline-success" type="button" onclick="copyEnrollmentLink()">Copy</button>
        </div>
    </div>
    <script>
    function copyEnrollmentLink() {
        const el = document.getElementById('enrollmentLink');
        el.select();
        document.execCommand('copy');
        alert('Enrollment link copied!');
    }
    </script>
<?php endif; ?>

<div class="row">
    <div class="col-lg-8">
        <div class="card bg-dark border-secondary mb-4">
            <div class="card-header fw-bold">User Information</div>
            <div class="card-body">
                <table class="table table-dark mb-0">
                    <tr>
                        <th style="width: 200px;">UUID</th>
                        <td><code class="text-info"><?= htmlspecialchars($user->uuid) ?></code></td>
                    </tr>
                    <tr>
                        <th>Display Label</th>
                        <td><?= htmlspecialchars($user->displayLabel ?? '-') ?></td>
                    </tr>
                    <tr>
                        <th>Status</th>
                        <td>
                            <?php if ($user->status === 'active'): ?>
                                <span class="badge bg-success">Active</span>
                            <?php else: ?>
                                <span class="badge bg-danger">Disabled</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th>Created</th>
                        <td><?= $user->createdAt->format('Y-m-d H:i:s') ?></td>
                    </tr>
                    <tr>
                        <th>Last Updated</th>
                        <td><?= $user->updatedAt->format('Y-m-d H:i:s') ?></td>
                    </tr>
                </table>
            </div>
        </div>

        <div class="card bg-dark border-secondary mb-4">
            <div class="card-header d-flex justify-content-between align-items-center fw-bold">
                <span>WebAuthn Credentials (<?= count($credentials) ?>)</span>
                <?php if (empty($credentials)): ?>
                    <form method="POST" action="/admin/users/<?= $user->uuid ?>/enrollment-link" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <button type="submit" class="btn btn-sm btn-success">
                            <i class="bi bi-key"></i> Generate Enrollment Link
                        </button>
                    </form>
                <?php endif; ?>
            </div>
            <div class="card-body">
                <?php if (empty($credentials)): ?>
                    <div class="alert alert-warning mb-0">
                        <strong>⚠️ No credentials enrolled</strong>
                        <p class="mb-0 mt-2">This user cannot log in until they enroll a WebAuthn security key. Generate an enrollment link above and send it to the user.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>Label</th>
                                    <th>Credential ID</th>
                                    <th>Created</th>
                                    <th>Last Used</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($credentials as $cred): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($cred['label'] ?? '-') ?></td>
                                        <td><code class="small"><?= htmlspecialchars(substr($cred['credential_id'], 0, 40)) ?>...</code></td>
                                        <td><?= htmlspecialchars($cred['created_at']) ?></td>
                                        <td><?= htmlspecialchars($cred['last_used_at'] ?? 'Never') ?></td>
                                        <td>
                                            <form method="POST" action="/admin/users/<?= $user->uuid ?>/credentials/<?= urlencode($cred['credential_id']) ?>/delete" 
                                                  class="d-inline" onsubmit="return confirm('Are you sure you want to delete this credential?');">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div class="mt-3">
                        <form method="POST" action="/admin/users/<?= $user->uuid ?>/enrollment-link" class="d-inline">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-outline-primary">
                                Add Another Key (Generate Enrollment Link)
                            </button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="card bg-dark border-secondary">
            <div class="card-header fw-bold">Project Assignments (<?= count($assignments) ?>)</div>
            <div class="card-body">
                <?php if (empty($assignments)): ?>
                    <p class="text-muted mb-0">No project assignments</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>Project</th>
                                    <th>Privilege Level</th>
                                    <th>Assigned</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($assignments as $assignment): ?>
                                    <tr>
                                        <td>
                                            <a href="/admin/projects/<?= $assignment['project_uuid'] ?>" class="text-decoration-none">
                                                <?= htmlspecialchars($assignment['project_name']) ?>
                                            </a>
                                        </td>
                                        <td><span class="badge bg-info"><?= htmlspecialchars($assignment['privilege_label']) ?></span></td>
                                        <td><?= htmlspecialchars($assignment['created_at']) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-4">
        <div class="card bg-dark border-primary mb-4">
            <div class="card-header bg-primary text-white fw-bold">Quick Actions</div>
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="/admin/audit?actor_user_uuid=<?= urlencode($user->uuid) ?>" class="btn btn-outline-light">
                        View Audit Logs
                    </a>
                    <form method="POST" action="/admin/users/<?= $user->uuid ?>/update" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="display_label" value="<?= htmlspecialchars($user->displayLabel ?? '') ?>">
                        <?php if ($user->status === 'active'): ?>
                            <input type="hidden" name="status" value="disabled">
                            <button type="submit" class="btn btn-outline-warning w-100" onclick="return confirm('Disable this user?')">
                                Disable User
                            </button>
                        <?php else: ?>
                            <input type="hidden" name="status" value="active">
                            <button type="submit" class="btn btn-outline-success w-100">
                                Enable User
                            </button>
                        <?php endif; ?>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
