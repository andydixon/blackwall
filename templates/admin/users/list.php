<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Users</h2>
            <a href="/admin/users/create" class="btn btn-primary">+ Create User</a>
        </div>

        <div class="card bg-dark">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-hover">
                        <thead>
                            <tr>
                                <th>UUID</th>
                                <th>Display Label</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($users)): ?>
                                <tr>
                                    <td colspan="5" class="text-center text-muted">No users found</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($users as $user): ?>
                                    <tr>
                                        <td><code class="small"><?= htmlspecialchars($user->uuid) ?></code></td>
                                        <td><?= htmlspecialchars($user->displayLabel ?? '-') ?></td>
                                        <td>
                                            <?php if ($user->status === 'active'): ?>
                                                <span class="badge bg-success">Active</span>
                                            <?php else: ?>
                                                <span class="badge bg-danger">Disabled</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?= $user->createdAt->format('Y-m-d H:i') ?></td>
                                        <td>
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
