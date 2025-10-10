<div class="row">
    <div class="col-12">
        <h2><?= htmlspecialchars($project->name) ?></h2>
        <p class="text-muted">UUID: <code><?= htmlspecialchars($project->uuid) ?></code></p>

        <?php if (isset($_GET['success']) && $_GET['success'] === 'updated'): ?>
            <div class="alert alert-success">Project updated successfully.</div>
        <?php elseif (isset($_GET['success']) && $_GET['success'] === 'status_change_requested'): ?>
            <div class="alert alert-success">Project status change request submitted for approval.</div>
        <?php endif; ?>
        <?php if (isset($_GET['error']) && $_GET['error'] === 'csrf'): ?>
            <div class="alert alert-danger">Security validation failed. Please retry.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'invalid'): ?>
            <div class="alert alert-danger">Invalid project settings.</div>
        <?php endif; ?>

        <?php if (in_array($currentAdminRole ?? '', ['super_admin', 'operator'], true)): ?>
            <div class="card bg-dark border-secondary mt-3">
                <div class="card-header fw-bold">Project Settings</div>
                <div class="card-body">
                    <form method="POST" action="/admin/projects/<?= $project->uuid ?>/update" class="row g-3">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <div class="col-md-8">
                            <label class="form-label">Project Name</label>
                            <input type="text" name="name" class="form-control" value="<?= htmlspecialchars($project->name) ?>" required maxlength="255">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Status</label>
                            <select name="status" class="form-select" required>
                                <option value="active" <?= $project->status === 'active' ? 'selected' : '' ?>>Active</option>
                                <option value="disabled" <?= $project->status === 'disabled' ? 'selected' : '' ?>>Disabled</option>
                            </select>
                        </div>
                        <div class="col-12">
                            <button type="submit" class="btn btn-primary">Save Project</button>
                        </div>
                    </form>
                </div>
            </div>
        <?php endif; ?>

        <div class="row g-3 mt-3">
            <div class="col-md-4">
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6>Privilege Levels</h6>
                        <a href="/admin/projects/<?= $project->uuid ?>/privileges" class="btn btn-sm btn-primary mt-2">Manage</a>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6>User Assignments</h6>
                        <a href="/admin/projects/<?= $project->uuid ?>/assignments" class="btn btn-sm btn-primary mt-2">Manage</a>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6>OAuth Clients</h6>
                        <a href="/admin/projects/<?= $project->uuid ?>/clients" class="btn btn-sm btn-primary mt-2">Manage</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
