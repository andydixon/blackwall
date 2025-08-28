<div class="row">
    <div class="col-12">
        <h2><?= htmlspecialchars($project->name) ?></h2>
        <p class="text-muted">UUID: <code><?= htmlspecialchars($project->uuid) ?></code></p>

        <div class="row g-3 mt-3">
            <div class="col-md-4">
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6>Privilege Levels</h6>
                        <a href="/admin/projects/<?= $project->id ?>/privileges" class="btn btn-sm btn-primary mt-2">Manage</a>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6>User Assignments</h6>
                        <a href="/admin/projects/<?= $project->id ?>/assignments" class="btn btn-sm btn-primary mt-2">Manage</a>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6>OAuth Clients</h6>
                        <a href="/admin/projects/<?= $project->id ?>/clients" class="btn btn-sm btn-primary mt-2">Manage</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
