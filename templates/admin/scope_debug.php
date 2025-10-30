<div class="row">
    <div class="col-12">
        <div class="page-header">
            <h2>Scope Debug</h2>
            <p class="text-muted mb-0">Effective admin scope for the current session.</p>
        </div>
    </div>
</div>

<div class="row g-4">
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header">
                <h5 class="mb-0">Session Scope</h5>
            </div>
            <div class="card-body">
                <dl class="row mb-0">
                    <dt class="col-sm-5">Actor user ID</dt>
                    <dd class="col-sm-7"><code><?= (int) ($userId ?? 0) ?></code></dd>
                    <dt class="col-sm-5">Is admin</dt>
                    <dd class="col-sm-7"><?= !empty($scope['is_admin']) ? 'Yes' : 'No' ?></dd>
                    <dt class="col-sm-5">Is super admin</dt>
                    <dd class="col-sm-7"><?= !empty($scope['is_super_admin']) ? 'Yes' : 'No' ?></dd>
                    <dt class="col-sm-5">Scoped projects</dt>
                    <dd class="col-sm-7"><strong><?= count($scope['project_uuids'] ?? []) ?></strong></dd>
                </dl>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header">
                <h5 class="mb-0">Super Admin Matching</h5>
            </div>
            <div class="card-body">
                <dl class="row mb-0">
                    <dt class="col-sm-5">Configured name</dt>
                    <dd class="col-sm-7"><code><?= htmlspecialchars((string) ($superProjectName ?? '')) ?></code></dd>
                    <dt class="col-sm-5">Configured UUID</dt>
                    <dd class="col-sm-7">
                        <code><?= htmlspecialchars((string) (($superProjectUuid ?? '') !== '' ? $superProjectUuid : '(not set)')) ?></code>
                    </dd>
                </dl>
            </div>
        </div>
    </div>

    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Project UUIDs in Scope</h5>
            </div>
            <div class="card-body">
                <?php if (!empty($scope['project_uuids'])): ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped mb-0">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Project UUID</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach (($scope['project_uuids'] ?? []) as $index => $projectUuid): ?>
                                    <tr>
                                        <td><?= (int) $index + 1 ?></td>
                                        <td><code><?= htmlspecialchars((string) $projectUuid) ?></code></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <p class="text-muted mb-0">No project scope is currently assigned.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
