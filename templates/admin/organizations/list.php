<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Organisations</h2>
        </div>

        <?php if (!empty($canManageOrganizations)): ?>
            <div class="card bg-dark mb-4">
                <div class="card-header">
                    <h5 class="mb-0">Create Organisation</h5>
                </div>
                <div class="card-body">
                    <form method="POST" action="/admin/organisations/create" class="row g-3">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <div class="col-md-4">
                            <label class="form-label">Name</label>
                            <input type="text" name="name" class="form-control" minlength="3" maxlength="120" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">Slug</label>
                            <input type="text" name="slug" class="form-control" pattern="[a-z0-9-]{3,40}" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">Admin Display Label</label>
                            <input type="text" name="admin_display_label" class="form-control" required>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">Logo URL (optional)</label>
                            <input type="url" name="logo_url" class="form-control" placeholder="https://...">
                        </div>
                        <div class="col-12">
                            <button type="submit" class="btn btn-primary">Create Organisation</button>
                        </div>
                    </form>
                </div>
            </div>
        <?php endif; ?>

        <div class="card bg-dark">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-hover">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Slug</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($organizations)): ?>
                                <tr><td colspan="5" class="text-center text-muted">No organisations found</td></tr>
                            <?php else: ?>
                                <?php foreach ($organizations as $organization): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($organization->name) ?></td>
                                        <td><code><?= htmlspecialchars($organization->slug) ?></code></td>
                                        <td>
                                            <span class="badge <?= $organization->status === 'active' ? 'bg-success' : 'bg-danger' ?>">
                                                <?= htmlspecialchars($organization->status) ?>
                                            </span>
                                        </td>
                                        <td><?= $organization->createdAt->format('Y-m-d H:i') ?></td>
                                        <td><a href="/admin/organisations/<?= htmlspecialchars($organization->uuid) ?>" class="btn btn-sm btn-outline-light">Manage</a></td>
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

