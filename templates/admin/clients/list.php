<div class="row mb-4">
    <div class="col">
        <h1 class="display-6 mb-3">OAuth Clients - <?= htmlspecialchars($project->name) ?></h1>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="/admin/projects">Projects</a></li>
                <li class="breadcrumb-item"><a href="/admin/projects/<?= $project->id ?>"><?= htmlspecialchars($project->name) ?></a></li>
                <li class="breadcrumb-item active">OAuth Clients</li>
            </ol>
        </nav>
    </div>
    <div class="col-auto">
        <a href="/admin/projects/<?= $project->id ?>/clients/create" class="btn btn-primary">
            <i class="bi bi-plus-circle"></i> Create New Client
        </a>
    </div>
</div>

<?php if (empty($clients)): ?>
    <div class="alert alert-info">
        <i class="bi bi-info-circle"></i> No OAuth clients configured for this project yet.
        <a href="/admin/projects/<?= $project->id ?>/clients/create" class="alert-link">Create your first client</a>.
    </div>
<?php else: ?>
    <div class="card bg-dark border-secondary">
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-dark table-hover mb-0">
                    <thead class="table-secondary">
                        <tr>
                            <th>Client ID</th>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th class="text-end">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($clients as $client): ?>
                            <tr>
                                <td><code class="text-info"><?= htmlspecialchars($client['client_id']) ?></code></td>
                                <td><?= htmlspecialchars($client['name'] ?? 'Unnamed') ?></td>
                                <td>
                                    <?php if ($client['is_confidential']): ?>
                                        <span class="badge bg-warning text-dark">Confidential</span>
                                    <?php else: ?>
                                        <span class="badge bg-success">Public</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge <?= $client['status'] === 'active' ? 'bg-success' : 'bg-secondary' ?>">
                                        <?= htmlspecialchars($client['status']) ?>
                                    </span>
                                </td>
                                <td><?= htmlspecialchars($client['created_at']) ?></td>
                                <td class="text-end">
                                    <a href="/admin/clients/<?= $client['id'] ?>" class="btn btn-sm btn-outline-light">
                                        View Details
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
<?php endif; ?>
