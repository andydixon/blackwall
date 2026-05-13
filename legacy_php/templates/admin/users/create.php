<div class="row">
    <div class="col-md-6 mx-auto">
        <?php if (isset($_GET['error']) && $_GET['error'] === 'assignment_level'): ?>
            <div class="alert alert-danger">Select a valid privilege level for the project assignment.</div>
        <?php endif; ?>

        <div class="card bg-dark">
            <div class="card-header">
                <h5>Create User</h5>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/users/create">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

                    <?php if (!empty($assignmentProject)): ?>
                        <input type="hidden" name="assignment_project_uuid" value="<?= htmlspecialchars($assignmentProject->uuid) ?>">

                        <div class="alert alert-info">
                            <div class="fw-bold mb-1">Create and Assign to Project</div>
                            <div class="small">
                                This user will be created in <strong><?= htmlspecialchars($assignmentProject->name) ?></strong>
                                and assigned to this project immediately.
                            </div>
                        </div>
                    <?php endif; ?>

                    <div class="mb-3">
                        <label class="form-label">Display Label (e.g., email)</label>
                        <input type="text" name="display_label" class="form-control" placeholder="user@example.com">
                        <small class="form-text text-muted">Optional. NOT used for authentication.</small>
                    </div>

                    <?php if (!empty($assignmentProject)): ?>
                        <div class="mb-3">
                            <label class="form-label">Project</label>
                            <input type="text" class="form-control" value="<?= htmlspecialchars($assignmentProject->name . ' (' . $assignmentProject->uuid . ')') ?>" readonly>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Privilege Level</label>
                            <select name="assignment_privilege_level" class="form-select" required>
                                <option value="">Select privilege level...</option>
                                <?php foreach ($assignmentPrivilegeLevels as $level): ?>
                                    <option value="<?= $level['level'] ?>">
                                        <?= htmlspecialchars($level['name']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    <?php elseif (!empty($scope['is_super_admin']) && !empty($organizations)): ?>
                        <div class="mb-3">
                            <label class="form-label">Organisation</label>
                            <select name="organization_uuid" class="form-select" required>
                                <?php foreach ($organizations as $organization): ?>
                                    <option value="<?= htmlspecialchars($organization->uuid) ?>">
                                        <?= htmlspecialchars($organization->name) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    <?php endif; ?>

                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-primary">
                            <?= !empty($assignmentProject) ? 'Create User and Assign' : 'Create User' ?>
                        </button>
                        <a href="<?= htmlspecialchars($assignmentBackUrl ?? '/admin/users') ?>" class="btn btn-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
