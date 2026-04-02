<div class="row">
    <div class="col-12">
        <?php
        $formatSeconds = static function (int $seconds): string {
            if ($seconds < 60)   return $seconds . 's';
            if ($seconds < 3600) return (string) round($seconds / 60, 1) . 'm';
            return (string) round($seconds / 3600, 1) . 'h';
        };
        $formatBytesCompact = static function (int $bytes): string {
            if ($bytes < 1024) return $bytes . ' B';
            $units = ['KB', 'MB', 'GB', 'TB'];
            $value = $bytes / 1024;
            foreach ($units as $unit) {
                if ($value < 1024 || $unit === 'TB') return round($value, 1) . ' ' . $unit;
                $value /= 1024;
            }
            return round($value, 1) . ' TB';
        };
        ?>

        <div class="page-header">
            <h2>Dashboard</h2>
        </div>

        <!-- ── Top stats ── -->
        <div class="row g-3 mb-4">
            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100">
                    <div class="card-body">
                        <div class="d-flex align-items-center gap-3 mb-3">
                            <div class="stat-icon stat-icon-blue">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                            </div>
                            <div>
                                <div class="text-muted small mb-0" style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.07em;">Users</div>
                                <div class="display-6"><?= $stats['users'] ?? 0 ?></div>
                            </div>
                        </div>
                        <a href="/admin/users" class="btn btn-sm btn-outline-light w-100">Manage Users</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color:#10b981">
                    <div class="card-body">
                        <div class="d-flex align-items-center gap-3 mb-3">
                            <div class="stat-icon stat-icon-green">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
                            </div>
                            <div>
                                <div class="text-muted small mb-0" style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.07em;">Projects</div>
                                <div class="display-6" style="color:#10b981"><?= $stats['projects'] ?? 0 ?></div>
                            </div>
                        </div>
                        <a href="/admin/projects" class="btn btn-sm btn-outline-light w-100">Manage Projects</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color:#f59e0b">
                    <div class="card-body">
                        <div class="d-flex align-items-center gap-3 mb-3">
                            <div class="stat-icon stat-icon-amber">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>
                            </div>
                            <div>
                                <div class="text-muted small mb-0" style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.07em;">OAuth Clients</div>
                                <div class="display-6" style="color:#f59e0b"><?= $stats['clients'] ?? 0 ?></div>
                            </div>
                        </div>
                        <a href="/admin/projects" class="btn btn-sm btn-outline-light w-100">View Clients</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color:#8b5cf6">
                    <div class="card-body">
                        <div class="d-flex align-items-center gap-3 mb-3">
                            <div class="stat-icon stat-icon-purple">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                            </div>
                            <div>
                                <div class="text-muted small mb-0" style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.07em;">Audit Logs</div>
                                <div class="display-6" style="color:#8b5cf6"><?= $stats['audit_count'] ?? 0 ?></div>
                            </div>
                        </div>
                        <a href="/admin/audit" class="btn btn-sm btn-outline-light w-100">View Logs</a>
                    </div>
                </div>
            </div>
        </div>

        <!-- ── Cryptbin overview ── -->
        <?php if (!empty($cryptbinDashboardStats)): ?>
        <div class="row g-3 mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3">
                        <div class="d-flex align-items-center gap-3">
                            <div class="stat-icon stat-icon-grey" style="flex-shrink:0">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#9ca3af" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                            </div>
                            <div>
                                <div class="fw-600 mb-1">Cryptbin Overview</div>
                                <p class="text-muted mb-0 small">
                                    Items: <strong class="text-white"><?= (int) ($cryptbinDashboardStats['total_items'] ?? 0) ?></strong>
                                    &nbsp;·&nbsp; Active: <strong class="text-success"><?= (int) ($cryptbinDashboardStats['active_items'] ?? 0) ?></strong>
                                    &nbsp;·&nbsp; Expired: <strong class="text-warning"><?= (int) ($cryptbinDashboardStats['expired_items'] ?? 0) ?></strong>
                                    &nbsp;·&nbsp; Stored: <strong class="text-white"><?= htmlspecialchars($formatBytesCompact((int) ($cryptbinDashboardStats['total_bytes'] ?? 0))) ?></strong>
                                </p>
                                <p class="text-muted mb-0" style="font-size:0.75rem;">
                                    Last updated: <?= htmlspecialchars((string) (($cryptbinDashboardStats['last_updated_at'] ?? null) ?: 'Never')) ?>
                                    &nbsp;·&nbsp; Last accessed: <?= htmlspecialchars((string) (($cryptbinDashboardStats['last_accessed_at'] ?? null) ?: 'Never')) ?>
                                </p>
                            </div>
                        </div>
                        <a href="/admin/cryptbin" class="btn btn-sm btn-outline-light">Open Cryptbin</a>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- ── Observability + SLA ── -->
        <div class="row g-3 mb-4">
            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3">
                        <div class="d-flex align-items-center gap-3">
                            <div class="stat-icon stat-icon-blue" style="flex-shrink:0">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            </div>
                            <div>
                                <div class="fw-600 mb-1">Observability Snapshot <span class="text-muted small">(24h)</span></div>
                                <p class="text-muted small mb-0">
                                    Success: <strong class="text-success"><?= (int) ($outcomeStats['success']['today'] ?? 0) ?></strong>
                                    &nbsp;·&nbsp; Fail: <strong class="text-danger"><?= (int) ($outcomeStats['fail']['today'] ?? 0) ?></strong>
                                </p>
                            </div>
                        </div>
                        <div class="d-flex gap-2 flex-shrink-0">
                            <a href="/admin/maintenance" class="btn btn-sm btn-outline-light">Maintenance</a>
                            <a href="/metrics" class="btn btn-sm btn-outline-info">Metrics JSON</a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3">
                        <div class="d-flex align-items-center gap-3">
                            <div class="stat-icon stat-icon-amber" style="flex-shrink:0">
                                <svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                            </div>
                            <div>
                                <div class="fw-600 mb-1">Approval Decision SLA</div>
                                <p class="text-muted small mb-0">
                                    Median: <strong class="text-white"><?= htmlspecialchars($formatSeconds((int) ($approvalSla['median_seconds'] ?? 0))) ?></strong>
                                    &nbsp;·&nbsp; P95: <strong class="text-white"><?= htmlspecialchars($formatSeconds((int) ($approvalSla['p95_seconds'] ?? 0))) ?></strong>
                                    &nbsp;·&nbsp; Decisions: <strong class="text-white"><?= (int) ($approvalSla['decision_count'] ?? 0) ?></strong>
                                </p>
                            </div>
                        </div>
                        <div class="flex-shrink-0">
                            <?php if ((int) ($approvalSla['pending_older_than_threshold'] ?? 0) > 0): ?>
                                <span class="badge bg-danger">
                                    <?= (int) $approvalSla['pending_older_than_threshold'] ?> overdue
                                </span>
                            <?php else: ?>
                                <span class="badge bg-success">SLA OK</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ── Approval breakdown stats ── -->
        <div class="row g-3 mb-4">
            <?php
            $approvalCols = [
                ['label' => 'Pending',   'key' => 'pending',   'color' => '#f59e0b', 'status' => 'pending',   'icon_class' => 'stat-icon-amber'],
                ['label' => 'Approved',  'key' => 'approved',  'color' => '#10b981', 'status' => 'approved',  'icon_class' => 'stat-icon-green'],
                ['label' => 'Rejected',  'key' => 'rejected',  'color' => '#ef4444', 'status' => 'rejected',  'icon_class' => 'stat-icon-red'],
                ['label' => 'Cancelled', 'key' => 'cancelled', 'color' => '#6b7280', 'status' => 'cancelled', 'icon_class' => 'stat-icon-grey'],
            ];
            ?>
            <?php foreach ($approvalCols as $col): ?>
            <div class="col-md-6 col-lg-3">
                <div class="card stat-card h-100" style="border-left-color:<?= $col['color'] ?>">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h6 class="mb-0 text-muted small" style="text-transform:uppercase;letter-spacing:0.07em;font-size:0.7rem;"><?= $col['label'] ?></h6>
                            <a href="/admin/approvals?status=<?= $col['status'] ?>" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row text-center g-0">
                            <?php foreach (['today' => 'Today', 'week' => 'Week', 'month' => 'Month'] as $period => $periodLabel): ?>
                            <div class="col-4">
                                <div class="small text-muted" style="font-size:0.7rem;text-transform:uppercase;"><?= $periodLabel ?></div>
                                <div class="fs-5 fw-bold" style="color:<?= $col['color'] ?>"><?= (int) ($approvalStats[$col['key']][$period] ?? 0) ?></div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- ── Security: CSRF + rate-limit ── -->
        <div class="row g-3 mb-4">
            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="d-flex align-items-center gap-2">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            CSRF Failures <span class="text-muted small ms-1">(scoped)</span>
                        </span>
                        <a href="/admin/audit?event_type=security.csrf.fail" class="btn btn-sm btn-outline-light">View</a>
                    </div>
                    <div class="card-body">
                        <div class="d-flex gap-4 mb-3">
                            <div><div class="small text-muted">Today</div><div class="fw-bold text-danger"><?= (int) ($csrfSecurityStats['today'] ?? 0) ?></div></div>
                            <div><div class="small text-muted">Week</div><div class="fw-bold text-danger"><?= (int) ($csrfSecurityStats['week'] ?? 0) ?></div></div>
                            <div><div class="small text-muted">Month</div><div class="fw-bold text-danger"><?= (int) ($csrfSecurityStats['month'] ?? 0) ?></div></div>
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
                            <p class="text-muted mb-0 small">No CSRF failures in the last 30 days.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="d-flex align-items-center gap-2">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            Rate-Limit Hits <span class="text-muted small ms-1">(scoped)</span>
                        </span>
                        <a href="/admin/audit?event_type=security.rate_limit.admin_mutation" class="btn btn-sm btn-outline-light">View</a>
                    </div>
                    <div class="card-body">
                        <div class="d-flex gap-4 mb-3">
                            <div><div class="small text-muted">Today</div><div class="fw-bold text-warning"><?= (int) ($rateLimitSecurityStats['today'] ?? 0) ?></div></div>
                            <div><div class="small text-muted">Week</div><div class="fw-bold text-warning"><?= (int) ($rateLimitSecurityStats['week'] ?? 0) ?></div></div>
                            <div><div class="small text-muted">Month</div><div class="fw-bold text-warning"><?= (int) ($rateLimitSecurityStats['month'] ?? 0) ?></div></div>
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
                            <p class="text-muted mb-0 small">No rate-limit hits in the last 30 days.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- ── Success / fail activity ── -->
        <div class="row g-3 mb-4">
            <div class="col-lg-6">
                <div class="card stat-card h-100" style="border-left-color:#10b981">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span class="d-flex align-items-center gap-2 fw-600">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
                                Success Activity
                            </span>
                            <a href="/admin/audit?outcome=success" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row g-2">
                            <?php foreach (['today' => 'Today', 'week' => 'Week', 'month' => 'Month'] as $p => $pl): ?>
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.12)">
                                    <div class="small text-muted" style="font-size:0.7rem;text-transform:uppercase"><?= $pl ?></div>
                                    <div class="fs-4 fw-bold" style="color:#10b981"><?= (int) ($outcomeStats['success'][$p] ?? 0) ?></div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card stat-card h-100" style="border-left-color:#ef4444">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span class="d-flex align-items-center gap-2 fw-600">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                                Failed Activity
                            </span>
                            <a href="/admin/audit?outcome=fail" class="btn btn-sm btn-outline-light">View</a>
                        </div>
                        <div class="row g-2">
                            <?php foreach (['today' => 'Today', 'week' => 'Week', 'month' => 'Month'] as $p => $pl): ?>
                            <div class="col-4">
                                <div class="p-3 rounded-3 text-center" style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.12)">
                                    <div class="small text-muted" style="font-size:0.7rem;text-transform:uppercase"><?= $pl ?></div>
                                    <div class="fs-4 fw-bold" style="color:#ef4444"><?= (int) ($outcomeStats['fail'][$p] ?? 0) ?></div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ── Event breakdown tables ── -->
        <div class="row g-3 mb-4">
            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="d-flex align-items-center gap-2">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
                            Success Breakdown
                        </span>
                        <small class="text-muted">Top 12 · 30 days</small>
                    </div>
                    <div class="card-body p-0">
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
                                            <?php $url = '/admin/audit?outcome=success&event_type=' . urlencode((string) $row['event_type']); ?>
                                            <tr style="cursor:pointer" onclick="window.location.href='<?= htmlspecialchars($url, ENT_QUOTES) ?>'">
                                                <td><a href="<?= htmlspecialchars($url) ?>" class="text-decoration-none"><code><?= htmlspecialchars($row['event_type']) ?></code></a></td>
                                                <td class="text-end"><?= (int) $row['today_count'] ?></td>
                                                <td class="text-end"><?= (int) $row['week_count'] ?></td>
                                                <td class="text-end fw-semibold text-success"><?= (int) $row['month_count'] ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <div class="p-3"><p class="text-muted small mb-0">No successful events in the last 30 days.</p></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="d-flex align-items-center gap-2">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            Failure Breakdown
                        </span>
                        <small class="text-muted">Top 12 · 30 days</small>
                    </div>
                    <div class="card-body p-0">
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
                                            <?php $url = '/admin/audit?outcome=fail&event_type=' . urlencode((string) $row['event_type']); ?>
                                            <tr style="cursor:pointer" onclick="window.location.href='<?= htmlspecialchars($url, ENT_QUOTES) ?>'">
                                                <td><a href="<?= htmlspecialchars($url) ?>" class="text-decoration-none"><code><?= htmlspecialchars($row['event_type']) ?></code></a></td>
                                                <td class="text-end"><?= (int) $row['today_count'] ?></td>
                                                <td class="text-end"><?= (int) $row['week_count'] ?></td>
                                                <td class="text-end fw-semibold text-danger"><?= (int) $row['month_count'] ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <div class="p-3"><p class="text-muted small mb-0">No failed events in the last 30 days.</p></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- ── My pending requests + recent activity + system info ── -->
        <div class="row g-3">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="d-flex align-items-center gap-2">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                            My Pending Requests
                        </span>
                        <a href="/admin/approvals?status=pending" class="btn btn-sm btn-outline-light">Open Queue</a>
                    </div>
                    <div class="card-body p-0">
                        <?php if (!empty($myPendingApprovals)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0 align-middle">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Action</th>
                                            <th>Created</th>
                                            <th></th>
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
                            <div class="p-3"><p class="text-muted small mb-0">No pending approval requests.</p></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header d-flex align-items-center gap-2">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                        Recent Activity
                    </div>
                    <div class="card-body p-0">
                        <?php if (!empty($recent_logs)): ?>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0 align-middle">
                                    <thead>
                                        <tr>
                                            <th>Event</th>
                                            <th>Outcome</th>
                                            <th>User</th>
                                            <th>IP</th>
                                            <th>Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recent_logs as $log): ?>
                                            <tr>
                                                <td><code><?= htmlspecialchars($log['event_type']) ?></code></td>
                                                <td>
                                                    <?php $badge = $log['outcome'] === 'success' ? 'bg-success' : ($log['outcome'] === 'fail' ? 'bg-danger' : 'bg-secondary'); ?>
                                                    <span class="badge <?= $badge ?>"><?= htmlspecialchars($log['outcome']) ?></span>
                                                </td>
                                                <td>
                                                    <?php
                                                    $actorUserUuid   = (string) ($log['actor_user_uuid'] ?? '');
                                                    $actorUserDisplay = $actorUserUuid !== '' ? ($recentUserDisplayMap[$actorUserUuid] ?? null) : null;
                                                    ?>
                                                    <?php if ($actorUserDisplay !== null): ?>
                                                        <a href="<?= htmlspecialchars($actorUserDisplay['href']) ?>" class="text-decoration-none link-info" title="<?= htmlspecialchars(trim(($actorUserDisplay['name'] !== '' ? $actorUserDisplay['name'] . ' ' : '') . '(' . $actorUserUuid . ')')) ?>">
                                                            <code class="small"><?= htmlspecialchars($actorUserUuid) ?></code>
                                                        </a>
                                                    <?php elseif ($actorUserUuid !== ''): ?>
                                                        <code class="small" title="<?= htmlspecialchars($actorUserUuid) ?>"><?= htmlspecialchars($actorUserUuid) ?></code>
                                                    <?php else: ?>
                                                        <span class="text-muted">—</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <a href="/admin/audit?ip_address=<?= urlencode($log['ip_address']) ?>" class="text-decoration-none">
                                                        <code class="small"><?= htmlspecialchars($log['ip_address'] ?? '—') ?></code>
                                                    </a>
                                                </td>
                                                <td class="text-muted small"><?= date('M j, H:i', strtotime($log['created_at'])) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <div class="p-3"><p class="text-muted small mb-0">No recent activity.</p></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header d-flex align-items-center gap-2">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        System Info
                    </div>
                    <div class="card-body">
                        <table class="w-100" style="border-collapse:collapse">
                            <tr>
                                <td class="text-muted small py-2" style="width:45%;border-bottom:1px solid var(--border)">Status</td>
                                <td class="py-2" style="border-bottom:1px solid var(--border)">
                                    <span class="badge bg-success"><span class="status-dot online" style="width:6px;height:6px;margin-right:4px"></span>Online</span>
                                </td>
                            </tr>
                            <tr>
                                <td class="text-muted small py-2" style="border-bottom:1px solid var(--border)">WebAuthn</td>
                                <td class="py-2" style="border-bottom:1px solid var(--border)"><span class="badge bg-success">Enabled</span></td>
                            </tr>
                            <tr>
                                <td class="text-muted small py-2" style="border-bottom:1px solid var(--border)">RP ID</td>
                                <td class="py-2" style="border-bottom:1px solid var(--border)"><code><?= htmlspecialchars(\BlackWall\Config::get('WEBAUTHN_RP_ID')) ?></code></td>
                            </tr>
                            <tr>
                                <td class="text-muted small py-2" style="border-bottom:1px solid var(--border)">App URL</td>
                                <td class="py-2" style="border-bottom:1px solid var(--border)"><code><?= htmlspecialchars(\BlackWall\Config::get('APP_URL')) ?></code></td>
                            </tr>
                            <tr>
                                <td class="text-muted small py-2">Version</td>
                                <td class="py-2"><span class="badge bg-secondary">v1.0.0</span></td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>
