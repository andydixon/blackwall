<div class="row">
    <div class="col-12">
        <div class="page-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h2>👥 User Assignments</h2>
                    <p class="text-muted mb-0">Project: <strong><?= htmlspecialchars($project->name) ?></strong></p>
                </div>
                <div>
                    <a href="/admin/projects/<?= $project->uuid ?>" class="btn btn-outline-light btn-sm me-2">← Back to Project</a>
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addAssignmentModal">
                        + Add Assignment
                    </button>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-body">
                <?php if (empty($assignments)): ?>
                    <div class="text-center py-5">
                        <div class="fs-1 text-muted mb-3">👥</div>
                        <h5 class="text-muted">No user assignments yet</h5>
                        <p class="text-muted">Assign users to this project with specific privilege levels</p>
                        <button class="btn btn-primary mt-3" data-bs-toggle="modal" data-bs-target="#addAssignmentModal">
                            + Add First Assignment
                        </button>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>User UUID</th>
                                    <th>Privilege Level</th>
                                    <th>Assigned</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($assignments as $assignment): ?>
                                    <tr>
                                        <td>
                                            <strong><?= htmlspecialchars($assignment['user_display_label'] ?? '-') ?></strong>
                                        </td>
                                        <td>
                                            <code class="small"><?= htmlspecialchars($assignment['user_uuid'] ?? '-') ?></code>
                                        </td>
                                        <td>
                                            <span class="badge bg-primary">
                                                <?= htmlspecialchars($assignment['privilege_label']) ?>
                                            </span>
                                        </td>
                                        <td class="text-muted">
                                            <?= date('M j, Y', strtotime($assignment['created_at'])) ?>
                                        </td>
                                        <td>
                                            <form method="POST" action="/admin/assignments/<?= $assignment['id'] ?>/delete" class="d-inline" onsubmit="return confirm('Remove this assignment?')">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">Remove</button>
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

<!-- Add Assignment Modal -->
<div class="modal fade" id="addAssignmentModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content bg-dark">
            <div class="modal-header">
                <h5 class="modal-title">Add User Assignment</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="/admin/projects/<?= $project->uuid ?>/assignments/create">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">User</label>
                        <select name="user_id" class="form-select" required>
                            <option value="">Select user...</option>
                            <?php foreach ($allUsers as $user): ?>
                                <option value="<?= $user->id ?>">
                                    <?= htmlspecialchars($user->displayLabel ?? $user->uuid) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Privilege Level</label>
                        <select name="privilege_level" class="form-select" required>
                            <option value="">Select privilege level...</option>
                            <?php foreach ($privilegeLevels as $level): ?>
                                <option value="<?= $level['level'] ?>">
                                    <?= htmlspecialchars($level['name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Assignment</button>
                </div>
            </form>
        </div>
    </div>
</div>
