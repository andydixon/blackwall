<div class="row">
    <div class="col-12">
        <div class="page-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h2>🛡️ Privilege Levels</h2>
                    <p class="text-muted mb-0">Project: <strong><?= htmlspecialchars($project->name) ?></strong></p>
                </div>
                <div>
                    <a href="/admin/projects/<?= $project->uuid ?>" class="btn btn-outline-light btn-sm me-2">← Back to Project</a>
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addPrivilegeModal" <?= empty($availableLevels) ? 'disabled' : '' ?>>
                        + Add Privilege
                    </button>
                </div>
            </div>
        </div>

        <?php if ($success === 'created'): ?>
            <div class="alert alert-success">Privilege level created successfully.</div>
        <?php elseif ($success === 'updated'): ?>
            <div class="alert alert-success">Privilege level updated successfully.</div>
        <?php elseif ($success === 'deleted'): ?>
            <div class="alert alert-success">Privilege level deleted successfully.</div>
        <?php elseif ($success === 'delete_requested'): ?>
            <div class="alert alert-success">Privilege level deletion request submitted for approval.</div>
        <?php endif; ?>

        <?php if ($error === 'csrf'): ?>
            <div class="alert alert-danger">Security validation failed. Please retry.</div>
        <?php elseif ($error === 'invalid_level'): ?>
            <div class="alert alert-danger">Invalid level. Use a value between 1 and 10.</div>
        <?php elseif ($error === 'duplicate'): ?>
            <div class="alert alert-danger">A privilege level with this level number or name already exists.</div>
        <?php elseif ($error === 'in_use'): ?>
            <div class="alert alert-danger">This level is currently assigned to users and cannot be deleted.</div>
        <?php elseif ($error === 'rate_limited'): ?>
            <div class="alert alert-danger">Too many admin changes in a short period. Please wait and retry.</div>
        <?php endif; ?>

        <div class="card">
            <div class="card-body">
                <?php if (empty($levelRows)): ?>
                    <div class="text-center py-5">
                        <div class="fs-1 text-muted mb-3">🛡️</div>
                        <h5 class="text-muted">No privilege levels defined</h5>
                        <p class="text-muted">Create a privilege level to control access policies.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>Level</th>
                                    <th>Effective Name</th>
                                    <th>Stored Name</th>
                                    <th>Description</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($levelRows as $row): ?>
                                    <?php $level = $row['entity']; ?>
                                    <tr>
                                        <td><span class="badge bg-primary"><?= (int) $level->level ?></span></td>
                                        <td><strong><?= htmlspecialchars($row['effective_name']) ?></strong></td>
                                        <td><code><?= htmlspecialchars($level->name) ?></code></td>
                                        <td class="text-muted"><?= htmlspecialchars($level->description ?? '-') ?></td>
                                        <td>
                                            <?php if ($row['in_use']): ?>
                                                <span class="badge bg-success">In Use</span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary">Unused</span>
                                            <?php endif; ?>
                                            <?php if ($row['is_override']): ?>
                                                <span class="badge bg-warning text-dark">Override</span>
                                            <?php else: ?>
                                                <span class="badge bg-info">Default</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-light me-1" data-bs-toggle="modal" data-bs-target="#editPrivilegeModal<?= $level->id ?>">
                                                Edit
                                            </button>
                                            <form method="POST" action="/admin/privileges/<?= $level->id ?>/delete" class="d-inline" onsubmit="return confirm('Delete privilege level <?= (int) $level->level ?>?');">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger" <?= $row['in_use'] ? 'disabled title="Level is in use"' : '' ?>>Delete</button>
                                            </form>
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

<?php foreach ($levelRows as $row): ?>
    <?php $level = $row['entity']; ?>
    <div class="modal fade" id="editPrivilegeModal<?= $level->id ?>" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">Edit Level <?= (int) $level->level ?></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="/admin/privileges/<?= $level->id ?>/update">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <div class="mb-3">
                            <label class="form-label">Name</label>
                            <input type="text" name="name" class="form-control" value="<?= htmlspecialchars($level->name) ?>" required maxlength="100">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <textarea name="description" class="form-control" rows="3" maxlength="500"><?= htmlspecialchars($level->description ?? '') ?></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php endforeach; ?>

<div class="modal fade" id="addPrivilegeModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content bg-dark">
            <div class="modal-header">
                <h5 class="modal-title">Add Privilege Level</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="/admin/projects/<?= $project->uuid ?>/privileges/create">
                <div class="modal-body">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <div class="mb-3">
                        <label class="form-label">Level</label>
                        <select name="level" class="form-select" required>
                            <option value="">Select level...</option>
                            <?php foreach ($availableLevels as $available): ?>
                                <option value="<?= (int) $available['level'] ?>">
                                    <?= (int) $available['level'] ?> - <?= htmlspecialchars($available['default_name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Name</label>
                        <input type="text" name="name" class="form-control" maxlength="100" placeholder="Leave blank to use default">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Description</label>
                        <textarea name="description" class="form-control" rows="3" maxlength="500"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Level</button>
                </div>
            </form>
        </div>
    </div>
</div>
