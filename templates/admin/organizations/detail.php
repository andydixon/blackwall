<div class="row mb-4">
    <div class="col-12 d-flex justify-content-between align-items-center">
        <h2>Organisation: <?= htmlspecialchars($organization->name) ?></h2>
        <a href="/admin/organisations" class="btn btn-outline-light btn-sm">Back</a>
    </div>
</div>

<?php if (!empty($enrollmentLink)): ?>
    <div class="alert alert-success">
        Admin enrollment link:
        <code><?= htmlspecialchars((string) $enrollmentLink) ?></code>
    </div>
<?php endif; ?>

<div class="row g-4">
    <div class="col-lg-6">
        <div class="card bg-dark">
            <div class="card-header">Settings</div>
            <div class="card-body">
                <form method="POST" action="/admin/organisations/<?= htmlspecialchars($organization->uuid) ?>/update">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <div class="mb-3">
                        <label class="form-label">Name</label>
                        <input type="text" name="name" class="form-control" value="<?= htmlspecialchars($organization->name) ?>" minlength="3" maxlength="120" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Slug</label>
                        <input type="text" name="slug" class="form-control" value="<?= htmlspecialchars($organization->slug) ?>" pattern="[a-z0-9-]{3,40}" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Logo URL</label>
                        <input type="url" name="logo_url" class="form-control" value="<?= htmlspecialchars($organization->logoUrl ?? '') ?>" placeholder="https://...">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Status</label>
                        <select name="status" class="form-select">
                            <option value="active" <?= $organization->status === 'active' ? 'selected' : '' ?>>active</option>
                            <option value="disabled" <?= $organization->status === 'disabled' ? 'selected' : '' ?>>disabled</option>
                        </select>
                    </div>
                    <?php if (!empty($canManageOrganizations)): ?>
                        <div class="mb-3">
                            <label class="form-label">Admin User UUID (optional override)</label>
                            <input type="text" name="admin_user_uuid" class="form-control" placeholder="<?= htmlspecialchars($adminUser?->uuid ?? '') ?>">
                        </div>
                    <?php endif; ?>
                    <button type="submit" class="btn btn-primary">Save</button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card bg-dark mb-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span>Organisation Admin</span>
                <?php if (!empty($canManageOrganizations) && !empty($adminUser)): ?>
                    <form method="POST" action="/admin/organisations/<?= htmlspecialchars($organization->uuid) ?>/switch-admin">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <button type="submit" class="btn btn-warning btn-sm">Switch As Admin</button>
                    </form>
                <?php endif; ?>
            </div>
            <div class="card-body">
                <?php if (!empty($adminUser)): ?>
                    <div><?= htmlspecialchars($adminUser->displayLabel ?? $adminUser->uuid) ?></div>
                    <code><?= htmlspecialchars($adminUser->uuid) ?></code>
                <?php else: ?>
                    <span class="text-muted">No admin user assigned</span>
                <?php endif; ?>
            </div>
        </div>

        <div class="card bg-dark">
            <div class="card-header">CSV User Import / Enrollment URL Export</div>
            <div class="card-body">
                <form method="POST" action="/admin/organisations/<?= htmlspecialchars($organization->uuid) ?>/users/import" enctype="multipart/form-data" class="mb-3">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <label class="form-label">Import CSV (`display_label,status`) and download enrollment URLs</label>
                    <input type="file" name="csv_file" class="form-control mb-2" accept=".csv" required>
                    <button type="submit" class="btn btn-primary btn-sm">Import and Export URLs</button>
                </form>
                <form method="POST" action="/admin/organisations/<?= htmlspecialchars($organization->uuid) ?>/enrollment-urls/export" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <button type="submit" class="btn btn-outline-light btn-sm">Export Enrollment URLs for Existing Users</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="row g-4 mt-1">
    <div class="col-lg-6">
        <div class="card bg-dark">
            <div class="card-header">Users (<?= count($users) ?>)</div>
            <div class="card-body">
                <ul class="list-group">
                    <?php foreach ($users as $user): ?>
                        <li class="list-group-item bg-dark text-light d-flex justify-content-between">
                            <span><?= htmlspecialchars($user->displayLabel ?? $user->uuid) ?></span>
                            <span class="badge <?= $user->status === 'active' ? 'bg-success' : 'bg-danger' ?>"><?= htmlspecialchars($user->status) ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card bg-dark">
            <div class="card-header">Projects (<?= count($projects) ?>)</div>
            <div class="card-body">
                <ul class="list-group">
                    <?php foreach ($projects as $project): ?>
                        <li class="list-group-item bg-dark text-light d-flex justify-content-between">
                            <span><?= htmlspecialchars($project->name) ?></span>
                            <span class="badge <?= $project->status === 'active' ? 'bg-success' : 'bg-danger' ?>"><?= htmlspecialchars($project->status) ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
</div>
