<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Projects</h2>
            <?php if (!empty($canCreateProject)): ?>
                <a href="/admin/projects/create" class="btn btn-primary">+ Create Project</a>
            <?php endif; ?>
        </div>

        <div class="card bg-dark">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-hover">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>UUID</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($projects)): ?>
                                <tr>
                                    <td colspan="5" class="text-center text-muted">No projects found</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($projects as $project): ?>
                                    <tr>
                                        <td><strong><?= htmlspecialchars($project->name) ?></strong></td>
                                        <td><code class="small"><?= htmlspecialchars($project->uuid) ?></code></td>
                                        <td>
                                            <?php if ($project->status === 'active'): ?>
                                                <span class="badge bg-success">Active</span>
                                            <?php else: ?>
                                                <span class="badge bg-danger">Disabled</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?= $project->createdAt->format('Y-m-d H:i') ?></td>
                                        <td>
                                            <a href="/admin/projects/<?= $project->uuid ?>" class="btn btn-sm btn-outline-light">View</a>
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
