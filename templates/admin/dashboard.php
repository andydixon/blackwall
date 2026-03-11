<div class="row">
    <div class="col-12">
        <?php
        $formatSeconds = static function (int $seconds): string {
            if ($seconds < 60) {
                return $seconds . 's';
            }
            if ($seconds < 3600) {
                return (string) round($seconds / 60, 1) . 'm';
            }
            return (string) round($seconds / 3600, 1) . 'h';
        };
        ?>
        <div class="page-header">
            <h2>Dashboard</h2>
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

        <?php if (!empty($cryptbinDashboardStats)): ?>
        <?php
        $formatBytesCompact = static function (int $bytes): string {
            if ($bytes < 1024) {
                return $bytes . ' B';
            }
            $units = ['KB', 'MB', 'GB', 'TB'];
            $value = $bytes / 1024;
            foreach ($units as $unit) {
                if ($value < 1024 || $unit === 'TB') {
                    return round($value, 1) . ' ' . $unit;
                }
                $value /= 1024;
            }
            return round($value, 1) . ' TB';
        };
        ?>
        <div class="row g-4 mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3">
                        <div>
                            <h5 class="mb-1">🗄️ Cryptbin Overview</h5>
                            <p class="text-muted mb-0">
                                Items: <strong><?= (int) ($cryptbinDashboardStats['total_items'] ?? 0) ?></strong>
                                · Active: <strong class="text-success"><?= (int) ($cryptbinDashboardStats['active_items'] ?? 0) ?></strong>
                                · Expired: <strong class="text-warning"><?= (int) ($cryptbinDashboardStats['expired_items'] ?? 0) ?></strong>
                                · Stored: <strong><?= htmlspecialchars($formatBytesCompact((int) ($cryptbinDashboardStats['total_bytes'] ?? 0))) ?></strong>
                            </p>
                            <p class="text-muted mb-0 small">
                                Last updated: <?= htmlspecialchars((string) (($cryptbinDashboardStats['last_updated_at'] ?? null) ?: 'Never')) ?>
                                · Last accessed: <?= htmlspecialchars((string) (($cryptbinDashboardStats['last_accessed_at'] ?? null) ?: 'Never')) ?>
                            </p>
                        </div>
                        <div>
                            <a href="/admin/cryptbin" class="btn btn-sm btn-outline-light">Open Cryptbin Admin</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

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
            <div class="col-12">
                <div class="card">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3">
                        <div>
                            <h5 class="mb-1">⏱️ Approval Decision SLA</h5>
                            <p class="text-muted mb-0">
                                Median decision time: <strong><?= htmlspecialchars($formatSeconds((int) ($approvalSla['median_seconds'] ?? 0))) ?></strong>
                                · P95: <strong><?= htmlspecialchars($formatSeconds((int) ($approvalSla['p95_seconds'] ?? 0))) ?></strong>
                                · Decisions analysed: <strong><?= (int) ($approvalSla['decision_count'] ?? 0) ?></strong>
                            </p>
                        </div>
                        <div>
                            <?php if ((int) ($approvalSla['pending_older_than_threshold'] ?? 0) > 0): ?>
                                <span class="badge bg-danger fs-6">
                                    <?= (int) $approvalSla['pending_older_than_threshold'] ?>
                                    pending older than <?= (int) ($approvalSla['pending_warning_days'] ?? 0) ?> day(s)
                                </span>
                            <?php else: ?>
                                <span class="badge bg-success fs-6">No overdue pending approvals</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color: #f59e0b;">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-muted">Pending Approvals</h6>
                            <a href="/admin/approvals?status=pending" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row text-center g-2">
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Today</div>
                                <div class="fs-5 fw-bold" style="color: #f59e0b;"><?= (int) ($approvalStats['pending']['today'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Week</div>
                                <div class="fs-5 fw-bold" style="color: #f59e0b;"><?= (int) ($approvalStats['pending']['week'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Month</div>
                                <div class="fs-5 fw-bold" style="color: #f59e0b;"><?= (int) ($approvalStats['pending']['month'] ?? 0) ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color: #10b981;">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-muted">Approved</h6>
                            <a href="/admin/approvals?status=approved" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row text-center g-2">
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Today</div>
                                <div class="fs-5 fw-bold" style="color: #10b981;"><?= (int) ($approvalStats['approved']['today'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Week</div>
                                <div class="fs-5 fw-bold" style="color: #10b981;"><?= (int) ($approvalStats['approved']['week'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Month</div>
                                <div class="fs-5 fw-bold" style="color: #10b981;"><?= (int) ($approvalStats['approved']['month'] ?? 0) ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color: #ef4444;">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-muted">Rejected</h6>
                            <a href="/admin/approvals?status=rejected" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row text-center g-2">
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Today</div>
                                <div class="fs-5 fw-bold" style="color: #ef4444;"><?= (int) ($approvalStats['rejected']['today'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Week</div>
                                <div class="fs-5 fw-bold" style="color: #ef4444;"><?= (int) ($approvalStats['rejected']['week'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Month</div>
                                <div class="fs-5 fw-bold" style="color: #ef4444;"><?= (int) ($approvalStats['rejected']['month'] ?? 0) ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color: #6b7280;">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-muted">Cancelled</h6>
                            <a href="/admin/approvals?status=cancelled" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row text-center g-2">
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Today</div>
                                <div class="fs-5 fw-bold" style="color: #9ca3af;"><?= (int) ($approvalStats['cancelled']['today'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Week</div>
                                <div class="fs-5 fw-bold" style="color: #9ca3af;"><?= (int) ($approvalStats['cancelled']['week'] ?? 0) ?></div>
                            </div>
                            <div class="col-4">
                                <div class="small text-muted text-uppercase">Month</div>
                                <div class="fs-5 fw-bold" style="color: #9ca3af;"><?= (int) ($approvalStats['cancelled']['month'] ?? 0) ?></div>
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
                        <h5 class="mb-0">🛡️ CSRF Failures (Scoped)</h5>
                        <a href="/admin/audit?event_type=security.csrf.fail" class="btn btn-sm btn-outline-light">View</a>
                    </div>
                    <div class="card-body">
                        <div class="d-flex gap-4 mb-3">
                            <div><small class="text-muted">Today</small><div class="fw-bold text-danger"><?= (int) ($csrfSecurityStats['today'] ?? 0) ?></div></div>
                            <div><small class="text-muted">Week</small><div class="fw-bold text-danger"><?= (int) ($csrfSecurityStats['week'] ?? 0) ?></div></div>
                            <div><small class="text-muted">Month</small><div class="fw-bold text-danger"><?= (int) ($csrfSecurityStats['month'] ?? 0) ?></div></div>
                        </div>
                        <?php if (!empty($csrfTopProjects)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-sm mb-0">
                                    <thead><tr><th>Project</th><th class="text-end">30d</th></tr></thead>
                                    <tbody>
                                        <?php foreach ($csrfTopProjects as $row): ?>
                                            <tr>
                                                <td>
                                                    <?= htmlspecialchars((string) ($row['project_name'] ?? 'Unscoped')) ?>
                                                    <div><code class="small"><?= htmlspecialchars((string) ($row['project_uuid'] ?? 'unscoped')) ?></code></div>
                                                </td>
                                                <td class="text-end fw-semibold"><?= (int) ($row['month_count'] ?? 0) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <p class="text-muted mb-0">No CSRF failures recorded in the last 30 days.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">🚦 Rate-Limit Hits (Scoped)</h5>
                        <a href="/admin/audit?event_type=security.rate_limit.admin_mutation" class="btn btn-sm btn-outline-light">View</a>
                    </div>
                    <div class="card-body">
                        <div class="d-flex gap-4 mb-3">
                            <div><small class="text-muted">Today</small><div class="fw-bold text-warning"><?= (int) ($rateLimitSecurityStats['today'] ?? 0) ?></div></div>
                            <div><small class="text-muted">Week</small><div class="fw-bold text-warning"><?= (int) ($rateLimitSecurityStats['week'] ?? 0) ?></div></div>
                            <div><small class="text-muted">Month</small><div class="fw-bold text-warning"><?= (int) ($rateLimitSecurityStats['month'] ?? 0) ?></div></div>
                        </div>
                        <?php if (!empty($rateLimitTopProjects)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-sm mb-0">
                                    <thead><tr><th>Project</th><th class="text-end">30d</th></tr></thead>
                                    <tbody>
                                        <?php foreach ($rateLimitTopProjects as $row): ?>
                                            <tr>
                                                <td>
                                                    <?= htmlspecialchars((string) ($row['project_name'] ?? 'Unscoped')) ?>
                                                    <div><code class="small"><?= htmlspecialchars((string) ($row['project_uuid'] ?? 'unscoped')) ?></code></div>
                                                </td>
                                                <td class="text-end fw-semibold"><?= (int) ($row['month_count'] ?? 0) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <p class="text-muted mb-0">No admin mutation rate-limit hits recorded in the last 30 days.</p>
                        <?php endif; ?>
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
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">🧾 My Pending Requests</h5>
                        <a href="/admin/approvals?status=pending" class="btn btn-sm btn-outline-light">Open Queue</a>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($myPendingApprovals)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0 align-middle">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Action</th>
                                            <th>Created</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($myPendingApprovals as $request): ?>
                                            <tr>
                                                <td><code><?= (int) $request['id'] ?></code></td>
                                                <td><code><?= htmlspecialchars((string) $request['action_type']) ?></code></td>
                                                <td class="text-muted"><?= htmlspecialchars((string) $request['created_at']) ?></td>
                                                <td>
                                                    <form method="POST" action="/admin/approvals/<?= (int) $request['id'] ?>/cancel" class="d-inline">
                                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                        <input type="hidden" name="note" value="Cancelled from dashboard widget">
                                                        <button type="submit" class="btn btn-sm btn-outline-secondary">Cancel</button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <p class="text-muted mb-0">You have no pending approval requests.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

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
                                                <td>
                                                    <?php
                                                    $actorUserUuid = (string) ($log['actor_user_uuid'] ?? '');
                                                    $actorUserDisplay = $actorUserUuid !== '' ? ($recentUserDisplayMap[$actorUserUuid] ?? null) : null;
                                                    ?>
                                                    <?php if ($actorUserDisplay !== null): ?>
                                                        <a
                                                            href="<?= htmlspecialchars($actorUserDisplay['href']) ?>"
                                                            class="text-decoration-none link-info"
                                                            title="<?= htmlspecialchars(trim(($actorUserDisplay['name'] !== '' ? $actorUserDisplay['name'] . ' ' : '') . '(' . $actorUserUuid . ')')) ?>"
                                                        >
                                                            <code class="small"><?= htmlspecialchars($actorUserUuid) ?></code>
                                                        </a>
                                                    <?php elseif ($actorUserUuid !== ''): ?>
                                                        <code class="small" title="<?= htmlspecialchars($actorUserUuid) ?>"><?= htmlspecialchars($actorUserUuid) ?></code>
                                                    <?php else: ?>
                                                        -
                                                    <?php endif; ?>
                                                </td>
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
