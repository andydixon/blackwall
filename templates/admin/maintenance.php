<div class="row">
    <div class="col-12">
        <div class="page-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h2>🧹 Maintenance Jobs</h2>
                    <p class="text-muted mb-0">Recent cleanup runs and outcomes</p>
                </div>
                <div>
                    <code>php bin/maintenance cleanup:all</code>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-body">
                <?php if (empty($runs)): ?>
                    <p class="text-muted mb-0">No maintenance runs recorded yet.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0 align-middle">
                            <thead>
                                <tr>
                                    <th>Started</th>
                                    <th>Job</th>
                                    <th>Status</th>
                                    <th>Duration</th>
                                    <th>Message</th>
                                    <th>Stats</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($runs as $run): ?>
                                    <?php
                                    $status = strtolower((string) ($run['status'] ?? ''));
                                    $badge = $status === 'success'
                                        ? 'bg-success'
                                        : ($status === 'fail' ? 'bg-danger' : ($status === 'running' ? 'bg-warning text-dark' : 'bg-secondary'));
                                    $stats = null;
                                    if (!empty($run['stats_json'])) {
                                        $decoded = json_decode((string) $run['stats_json'], true);
                                        $stats = is_array($decoded) ? $decoded : null;
                                    }
                                    ?>
                                    <tr>
                                        <td class="text-nowrap"><?= htmlspecialchars((string) $run['started_at']) ?></td>
                                        <td><code><?= htmlspecialchars((string) $run['job_name']) ?></code></td>
                                        <td><span class="badge <?= $badge ?>"><?= htmlspecialchars((string) $run['status']) ?></span></td>
                                        <td><?= isset($run['duration_ms']) ? (int) $run['duration_ms'] . ' ms' : '-' ?></td>
                                        <td class="text-muted"><?= htmlspecialchars((string) ($run['message'] ?? '-')) ?></td>
                                        <td>
                                            <?php if ($stats): ?>
                                                <pre class="mb-0 small"><?= htmlspecialchars(json_encode($stats, JSON_PRETTY_PRINT)) ?></pre>
                                            <?php else: ?>
                                                <span class="text-muted">-</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
