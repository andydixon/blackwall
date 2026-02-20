<div class="row">
    <div class="col-md-6 mx-auto">
        <div class="card bg-dark">
            <div class="card-header">
                <h5>Create Project</h5>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/projects/create">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    
                    <div class="mb-3">
                        <label class="form-label">Project Name</label>
                        <input type="text" name="name" class="form-control" required>
                    </div>

                    <?php if (!empty($scope['is_super_admin']) && !empty($organizations)): ?>
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
                        <button type="submit" class="btn btn-primary">Create Project</button>
                        <a href="/admin/projects" class="btn btn-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
