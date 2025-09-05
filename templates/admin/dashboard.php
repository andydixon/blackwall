<div class="row">
    <div class="col-12">
        <div class="page-header">
            <h2>🏠 Dashboard</h2>
            <p class="text-muted mb-0">Welcome to BlackWall OAuth 2.1 + OpenID Connect Server</p>
        </div>

        <div class="row g-4 mb-4">
            <div class="col-md-6 col-lg-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <div class="fs-2 me-3">👥</div>
                            <div>
                                <h6 class="text-muted mb-0">Users</h6>
                                <p class="display-6 mb-0"><?= $stats['users'] ?? 0 ?></p>
                            </div>
                        </div>
                        <a href="/admin/users" class="btn btn-sm btn-outline-light">Manage Users →</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card" style="border-left-color: #10b981">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <div class="fs-2 me-3">📦</div>
                            <div>
                                <h6 class="text-muted mb-0">Projects</h6>
                                <p class="display-6 mb-0" style="color: #10b981"><?= $stats['projects'] ?? 0 ?></p>
                            </div>
                        </div>
                        <a href="/admin/projects" class="btn btn-sm btn-outline-light">Manage Projects →</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card" style="border-left-color: #f59e0b">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <div class="fs-2 me-3">🔑</div>
                            <div>
                                <h6 class="text-muted mb-0">OAuth Clients</h6>
                                <p class="display-6 mb-0" style="color: #f59e0b"><?= $stats['clients'] ?? 0 ?></p>
                            </div>
                        </div>
                        <a href="/admin/projects" class="btn btn-sm btn-outline-light">View Clients →</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card" style="border-left-color: #8b5cf6">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <div class="fs-2 me-3">📋</div>
                            <div>
                                <h6 class="text-muted mb-0">Audit Logs</h6>
                                <p class="display-6 mb-0" style="color: #8b5cf6"><?= $stats['audit_count'] ?? 0 ?></p>
                            </div>
                        </div>
                        <a href="/admin/audit" class="btn btn-sm btn-outline-light">View Logs →</a>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">📊 Recent Activity</h5>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($recent_logs)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0">
                                    <thead>
                                        <tr>
                                            <th>Event</th>
                                            <th>Outcome</th>
                                            <th>User</th>
                                            <th>IP Address</th>
                                            <th>Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recent_logs as $log): ?>
                                            <tr>
                                                <td><code><?= htmlspecialchars($log['event_type']) ?></code></td>
                                                <td>
                                                    <?php
                                                    $badge = $log['outcome'] === 'success' ? 'bg-success' : ($log['outcome'] === 'fail' ? 'bg-danger' : 'bg-secondary');
                                                    ?>
                                                    <span class="badge <?= $badge ?>"><?= htmlspecialchars($log['outcome']) ?></span>
                                                </td>
                                                <td><?= htmlspecialchars($log['actor_user_uuid'] ?? '-') ?></td>
                                                <td>
                                                    <a href="/admin/audit?ip_address=<?= urlencode($log['ip_address']) ?>" 
                                                       class="text-decoration-none">
                                                        <code class="small"><?= htmlspecialchars($log['ip_address'] ?? '-') ?></code>
                                                    </a>
                                                </td>
                                                <td class="text-muted"><?= date('M j, H:i', strtotime($log['created_at'])) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <p class="text-muted mb-0">No recent activity</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">🔐 System Info</h5>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <h6 class="text-muted">Server Status</h6>
                            <span class="badge bg-success">🟢 Online</span>
                        </div>
                        <div class="mb-3">
                            <h6 class="text-muted">WebAuthn</h6>
                            <span class="badge bg-success">✓ Enabled</span>
                        </div>
                        <div class="mb-3">
                            <h6 class="text-muted">RP ID</h6>
                            <code><?= htmlspecialchars(\BlackWall\Config::get('WEBAUTHN_RP_ID')) ?></code>
                        </div>
                        <div class="mb-3">
                            <h6 class="text-muted">App URL</h6>
                            <code><?= htmlspecialchars(\BlackWall\Config::get('APP_URL')) ?></code>
                        </div>
                        <div>
                            <h6 class="text-muted">Version</h6>
                            <span class="badge bg-secondary">v1.0.0</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
