<div class="row">
    <div class="col-12">
        <div class="page-header d-flex justify-content-between align-items-center">
            <h2>Users</h2>
            <?php if (!empty($canCreateUser)): ?>
                <a href="/admin/users/create" class="btn btn-primary btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:-1px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    Create User
                </a>
            <?php endif; ?>
        </div>

        <div class="card">
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-dark table-hover mb-0 align-middle">
                        <thead>
                            <tr>
                                <th>UUID</th>
                                <th>Display Label</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($users)): ?>
                                <tr><td colspan="5" class="text-center text-muted py-4">No users found</td></tr>
                            <?php else: ?>
                                <?php foreach ($users as $user): ?>
                                    <tr>
                                        <td><code class="small"><?= htmlspecialchars($user->uuid) ?></code></td>
                                        <td><?= htmlspecialchars($user->displayLabel ?? '—') ?></td>
                                        <td>
                                            <?php if ($user->status === 'active'): ?>
                                                <span class="badge bg-success">Active</span>
                                            <?php else: ?>
                                                <span class="badge bg-danger">Disabled</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-muted small"><?= $user->createdAt->format('Y-m-d H:i') ?></td>
                                        <td class="text-end">
                                            <a href="/admin/users/<?= $user->uuid ?>" class="btn btn-sm btn-outline-light">View</a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
