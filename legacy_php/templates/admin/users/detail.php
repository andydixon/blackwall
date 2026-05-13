<div class="page-header d-flex justify-content-between align-items-center">
    <div>
        <h2 class="mb-1"><?= htmlspecialchars($user->displayLabel ?? $user->uuid) ?></h2>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb mb-0">
                <li class="breadcrumb-item"><a href="/admin/users">Users</a></li>
                <li class="breadcrumb-item active"><?= htmlspecialchars($user->displayLabel ?? $user->uuid) ?></li>
            </ol>
        </nav>
    </div>
</div>

<?php if (isset($_GET['error']) && $_GET['error'] === 'min_keys'): ?>
    <div class="alert alert-danger mb-4">Cannot delete credential. User must retain at least <?= (int) \BlackWall\Config::getInt('MIN_WEBAUTHN_KEYS', 1) ?> key(s).</div>
<?php endif; ?>
<?php if (isset($_GET['error']) && $_GET['error'] === 'last_super_admin'): ?>
    <div class="alert alert-danger mb-4">Operation blocked. At least one active <code>super_admin</code> user must remain.</div>
<?php endif; ?>
<?php if (isset($_GET['error']) && $_GET['error'] === 'rate_limited'): ?>
    <div class="alert alert-danger mb-4">Too many admin changes in a short period. Please wait and retry.</div>
<?php endif; ?>
<?php if (isset($_GET['success']) && $_GET['success'] === 'delete_requested'): ?>
    <div class="alert alert-success mb-4">Credential deletion request submitted for approval.</div>
<?php endif; ?>
<?php if (isset($_GET['success']) && $_GET['success'] === 'status_change_requested'): ?>
    <div class="alert alert-success mb-4">User status change request submitted for approval.</div>
<?php endif; ?>

<?php if (isset($enrollmentLink)): ?>
    <div class="alert alert-success mb-4">
        <h6 class="mb-2 fw-bold">Enrollment Link Generated</h6>
        <p class="small mb-2">Send this link to the user to enroll their security key. Expires in 24 hours.</p>
        <div class="input-group">
            <input type="text" class="form-control font-monospace" value="<?= htmlspecialchars($enrollmentLink) ?>" readonly id="enrollmentLink" style="font-size:0.8125rem;">
            <button class="btn btn-outline-success" type="button" onclick="navigator.clipboard.writeText(document.getElementById('enrollmentLink').value)">Copy</button>
        </div>
    </div>
<?php endif; ?>

<div class="row g-3">
    <div class="col-lg-8">

        <!-- User info -->
        <div class="card mb-3">
            <div class="card-header d-flex align-items-center gap-2">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                User Information
            </div>
            <div class="card-body p-0">
                <table class="table table-dark mb-0 align-middle">
                    <tr>
                        <td class="text-muted small fw-500 py-3 px-4" style="width:180px">UUID</td>
                        <td class="py-3 px-4"><code class="text-info"><?= htmlspecialchars($user->uuid) ?></code></td>
                    </tr>
                    <tr>
                        <td class="text-muted small fw-500 py-3 px-4">Display Label</td>
                        <td class="py-3 px-4"><?= htmlspecialchars($user->displayLabel ?? '—') ?></td>
                    </tr>
                    <tr>
                        <td class="text-muted small fw-500 py-3 px-4">Status</td>
                        <td class="py-3 px-4">
                            <?php if ($user->status === 'active'): ?>
                                <span class="badge bg-success">Active</span>
                            <?php else: ?>
                                <span class="badge bg-danger">Disabled</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td class="text-muted small fw-500 py-3 px-4">Created</td>
                        <td class="py-3 px-4 text-muted small"><?= $user->createdAt->format('Y-m-d H:i:s') ?></td>
                    </tr>
                    <tr>
                        <td class="text-muted small fw-500 py-3 px-4" style="border-bottom:none">Last Updated</td>
                        <td class="py-3 px-4 text-muted small" style="border-bottom:none"><?= $user->updatedAt->format('Y-m-d H:i:s') ?></td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Credentials -->
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span class="d-flex align-items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>
                    WebAuthn Credentials
                    <span class="badge bg-secondary"><?= count($credentials) ?></span>
                </span>
                <?php if (empty($credentials)): ?>
                    <form method="POST" action="/admin/users/<?= $user->uuid ?>/enrollment-link" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <button type="submit" class="btn btn-sm btn-success">Generate Enrollment Link</button>
                    </form>
                <?php endif; ?>
            </div>
            <div class="card-body <?= empty($credentials) ? '' : 'p-0' ?>">
                <?php if (empty($credentials)): ?>
                    <div class="alert alert-warning mb-0">
                        <strong>No credentials enrolled.</strong>
                        <p class="mb-0 mt-1 small">This user cannot log in until they enroll a WebAuthn security key. Generate an enrollment link and send it to the user.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0 align-middle">
                            <thead>
                                <tr>
                                    <th>Label</th>
                                    <th>Credential ID</th>
                                    <th>Created</th>
                                    <th>Last Used</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($credentials as $cred): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($cred['label'] ?? '—') ?></td>
                                        <td><code class="small"><?= htmlspecialchars(substr($cred['credential_id'], 0, 40)) ?>…</code></td>
                                        <td class="text-muted small"><?= htmlspecialchars($cred['created_at']) ?></td>
                                        <td class="text-muted small"><?= htmlspecialchars($cred['last_used_at'] ?? 'Never') ?></td>
                                        <td class="text-end">
                                            <form method="POST" action="/admin/users/<?= $user->uuid ?>/credentials/<?= urlencode($cred['credential_id']) ?>/delete"
                                                  class="d-inline" onsubmit="return confirm('Delete this credential?');">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div class="p-3 border-top" style="border-color:var(--border)!important">
                        <form method="POST" action="/admin/users/<?= $user->uuid ?>/enrollment-link" class="d-inline">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-outline-primary">Add Another Key</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Project assignments -->
        <div class="card">
            <div class="card-header d-flex align-items-center gap-2">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
                Project Assignments
                <span class="badge bg-secondary"><?= count($assignments) ?></span>
            </div>
            <div class="card-body <?= empty($assignments) ? '' : 'p-0' ?>">
                <?php if (empty($assignments)): ?>
                    <p class="text-muted small mb-0">No project assignments.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0 align-middle">
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
                                        <td class="text-muted small"><?= htmlspecialchars($assignment['created_at']) ?></td>
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
        <div class="card">
            <div class="card-header d-flex align-items-center gap-2">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
                Quick Actions
            </div>
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="/admin/audit?actor_user_uuid=<?= urlencode($user->uuid) ?>" class="btn btn-outline-light">
                        View Audit Logs
                    </a>
                    <form method="POST" action="/admin/users/<?= $user->uuid ?>/update">
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
