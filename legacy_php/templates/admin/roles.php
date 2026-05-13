<div class="row">
    <div class="col-12">
        <div class="page-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h2>🛂 Admin Roles</h2>
                    <p class="text-muted mb-0">Manage admin panel access and role assignments.</p>
                </div>
            </div>
        </div>

        <?php if (isset($_GET['error']) && $_GET['error'] === 'last_super_admin'): ?>
            <div class="alert alert-danger">
                Operation blocked. At least one active <code>super_admin</code> must remain.
            </div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'self_revoke'): ?>
            <div class="alert alert-danger">
                Operation blocked. You cannot revoke your own admin role from the current session.
            </div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'rate_limited'): ?>
            <div class="alert alert-danger">
                Too many admin changes in a short period. Please wait and retry.
            </div>
        <?php endif; ?>

        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">Assign Role</h5>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/roles">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <div class="row g-3 align-items-end">
                        <div class="col-md-6">
                            <label class="form-label">User</label>
                            <select name="user_id" class="form-select" required>
                                <option value="">Select user...</option>
                                <?php foreach ($users as $user): ?>
                                    <option value="<?= (int) $user->id ?>">
                                        <?= htmlspecialchars(($user->displayLabel ?? '(no label)') . ' · ' . $user->uuid) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Role</label>
                            <select name="role" class="form-select" required>
                                <option value="super_admin">Super Admin</option>
                                <option value="operator">Operator</option>
                                <option value="auditor">Auditor</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <button type="submit" class="btn btn-primary w-100">Assign</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Current Roles</h5>
            </div>
            <div class="card-body">
                <?php if (empty($roles)): ?>
                    <p class="text-muted mb-0">No explicit roles configured. Legacy fallback is currently active.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>UUID</th>
                                    <th>Role</th>
                                    <th>Active</th>
                                    <th>Updated</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($roles as $role): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($role['display_label'] ?? '-') ?></td>
                                        <td><code class="small"><?= htmlspecialchars($role['user_uuid']) ?></code></td>
                                        <td><span class="badge bg-info"><?= htmlspecialchars($role['role']) ?></span></td>
                                        <td>
                                            <?php if ((int) $role['is_active'] === 1): ?>
                                                <span class="badge bg-success">Active</span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary">Inactive</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-muted"><?= htmlspecialchars($role['updated_at']) ?></td>
                                        <td>
                                            <?php if ((int) $role['is_active'] === 1): ?>
                                                <form method="POST" action="/admin/roles/<?= (int) $role['user_id'] ?>/revoke" class="d-inline" onsubmit="return confirm('Revoke this admin role?');">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-danger">Revoke</button>
                                                </form>
                                            <?php else: ?>
                                                <span class="text-muted">-</span>
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
    </div>
</div>
