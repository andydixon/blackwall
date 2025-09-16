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

        <div class="row g-4 mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3">
                        <div>
                            <h5 class="mb-1">📈 Observability Snapshot (24h)</h5>
                            <p class="text-muted mb-0">
                                Success: <strong class="text-success"><?= (int) ($outcomeStats['success']['today'] ?? 0) ?></strong>
                                · Fail: <strong class="text-danger"><?= (int) ($outcomeStats['fail']['today'] ?? 0) ?></strong>
                                · Export JSON metrics for dashboards and alerts.
                            </p>
                        </div>
                        <div class="d-flex gap-2">
                            <a href="/admin/maintenance" class="btn btn-sm btn-outline-light">Maintenance Status</a>
                            <a href="/metrics" class="btn btn-sm btn-outline-info">Open Metrics JSON</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4 mb-4">
            <div class="col-lg-6">
                <div class="card stat-card h-100" style="border-left-color: #10b981;">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h5 class="mb-0">✅ Success Activity</h5>
                            <a href="/admin/audit?outcome=success" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row g-3">
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background: rgba(16, 185, 129, 0.12);">
                                    <div class="small text-muted text-uppercase">Today</div>
                                    <div class="fs-3 fw-bold" style="color: #10b981;"><?= (int) ($outcomeStats['success']['today'] ?? 0) ?></div>
                                </div>
                            </div>
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background: rgba(16, 185, 129, 0.12);">
                                    <div class="small text-muted text-uppercase">Week</div>
                                    <div class="fs-3 fw-bold" style="color: #10b981;"><?= (int) ($outcomeStats['success']['week'] ?? 0) ?></div>
                                </div>
                            </div>
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background: rgba(16, 185, 129, 0.12);">
                                    <div class="small text-muted text-uppercase">Month</div>
                                    <div class="fs-3 fw-bold" style="color: #10b981;"><?= (int) ($outcomeStats['success']['month'] ?? 0) ?></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card stat-card h-100" style="border-left-color: #ef4444;">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h5 class="mb-0">❌ Failed Activity</h5>
                            <a href="/admin/audit?outcome=fail" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row g-3">
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background: rgba(239, 68, 68, 0.12);">
                                    <div class="small text-muted text-uppercase">Today</div>
                                    <div class="fs-3 fw-bold" style="color: #ef4444;"><?= (int) ($outcomeStats['fail']['today'] ?? 0) ?></div>
                                </div>
                            </div>
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background: rgba(239, 68, 68, 0.12);">
                                    <div class="small text-muted text-uppercase">Week</div>
                                    <div class="fs-3 fw-bold" style="color: #ef4444;"><?= (int) ($outcomeStats['fail']['week'] ?? 0) ?></div>
                                </div>
                            </div>
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background: rgba(239, 68, 68, 0.12);">
                                    <div class="small text-muted text-uppercase">Month</div>
                                    <div class="fs-3 fw-bold" style="color: #ef4444;"><?= (int) ($outcomeStats['fail']['month'] ?? 0) ?></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4 mb-4">
            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">✅ Success Breakdown</h5>
                        <small class="text-muted">Top 12 (30 days)</small>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($successBreakdown)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0 align-middle">
                                    <thead>
                                        <tr>
                                            <th>Event</th>
                                            <th class="text-end">Today</th>
                                            <th class="text-end">Week</th>
                                            <th class="text-end">Month</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($successBreakdown as $row): ?>
                                            <?php $successAuditUrl = '/admin/audit?outcome=success&event_type=' . urlencode((string) $row['event_type']); ?>
                                            <tr style="cursor: pointer;" onclick="window.location.href='<?= htmlspecialchars($successAuditUrl, ENT_QUOTES) ?>'">
                                                <td>
                                                    <a href="<?= htmlspecialchars($successAuditUrl) ?>" class="text-decoration-none">
                                                        <code><?= htmlspecialchars($row['event_type']) ?></code>
                                                    </a>
                                                </td>
                                                <td class="text-end fw-semibold"><?= (int) $row['today_count'] ?></td>
                                                <td class="text-end fw-semibold"><?= (int) $row['week_count'] ?></td>
                                                <td class="text-end fw-semibold text-success"><?= (int) $row['month_count'] ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <p class="text-muted mb-0">No successful events in the last 30 days.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">❌ Failure Breakdown</h5>
                        <small class="text-muted">Top 12 (30 days)</small>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($failBreakdown)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0 align-middle">
                                    <thead>
                                        <tr>
                                            <th>Event</th>
                                            <th class="text-end">Today</th>
                                            <th class="text-end">Week</th>
                                            <th class="text-end">Month</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($failBreakdown as $row): ?>
                                            <?php $failAuditUrl = '/admin/audit?outcome=fail&event_type=' . urlencode((string) $row['event_type']); ?>
                                            <tr style="cursor: pointer;" onclick="window.location.href='<?= htmlspecialchars($failAuditUrl, ENT_QUOTES) ?>'">
                                                <td>
                                                    <a href="<?= htmlspecialchars($failAuditUrl) ?>" class="text-decoration-none">
                                                        <code><?= htmlspecialchars($row['event_type']) ?></code>
                                                    </a>
                                                </td>
                                                <td class="text-end fw-semibold"><?= (int) $row['today_count'] ?></td>
                                                <td class="text-end fw-semibold"><?= (int) $row['week_count'] ?></td>
                                                <td class="text-end fw-semibold text-danger"><?= (int) $row['month_count'] ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <p class="text-muted mb-0">No failed events in the last 30 days.</p>
                        <?php endif; ?>
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
