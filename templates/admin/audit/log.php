<div class="row">
    <div class="col-12">
        <h2>Audit Log</h2>

        <?php if (isset($_GET['error']) && $_GET['error'] === 'rate_limited'): ?>
            <div class="alert alert-danger">Too many admin changes in a short period. Please wait and retry.</div>
        <?php endif; ?>

        <div class="card bg-dark mb-3">
            <div class="card-body">
                <form method="GET" action="/admin/audit" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" name="date_from" class="form-control" value="<?= htmlspecialchars($filters['date_from'] ?? '') ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" name="date_to" class="form-control" value="<?= htmlspecialchars($filters['date_to'] ?? '') ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Event Type</label>
                        <input type="text" name="event_type" class="form-control" placeholder="oauth.token" value="<?= htmlspecialchars($filters['event_type'] ?? '') ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Outcome</label>
                        <select name="outcome" class="form-select">
                            <option value="">All</option>
                            <option value="success" <?= ($filters['outcome'] ?? '') === 'success' ? 'selected' : '' ?>>Success</option>
                            <option value="fail" <?= ($filters['outcome'] ?? '') === 'fail' ? 'selected' : '' ?>>Fail</option>
                            <option value="info" <?= ($filters['outcome'] ?? '') === 'info' ? 'selected' : '' ?>>Info</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">IP Address</label>
                        <input type="text" name="ip_address" class="form-control" value="<?= htmlspecialchars($filters['ip_address'] ?? '') ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Project UUID</label>
                        <input type="text" name="project_uuid" class="form-control" value="<?= htmlspecialchars($filters['project_uuid'] ?? '') ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Correlation ID</label>
                        <input type="text" name="correlation_id" class="form-control" value="<?= htmlspecialchars($filters['correlation_id'] ?? '') ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">&nbsp;</label>
                        <button type="submit" class="btn btn-primary w-100">Search</button>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">&nbsp;</label>
                        <a class="btn btn-outline-light w-100"
                           href="/admin/audit/export?<?= htmlspecialchars(http_build_query(array_filter($filters, fn($v) => $v !== null && $v !== ''))) ?>">
                            Export CSV
                        </a>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">&nbsp;</label>
                        <a class="btn btn-outline-info w-100"
                           href="/admin/audit/export?<?= htmlspecialchars(http_build_query(array_merge(array_filter($filters, fn($v) => $v !== null && $v !== ''), ['detached' => 1]))) ?>">
                            Export Signature Manifest
                        </a>
                    </div>
                </form>
            </div>
        </div>

        <div class="card bg-dark">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-sm">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Event</th>
                                <th>Outcome</th>
                                <th>IP</th>
                                <th>User</th>
                                <th>Project</th>
                                <th>Client</th>
                                <th>Message</th>
                                <th>Correlation</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($logs)): ?>
                                <tr>
                                    <td colspan="9" class="text-center text-muted">No audit logs found</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($logs as $log): ?>
                                    <tr>
                                        <td class="small"><?= htmlspecialchars($log['created_at']) ?></td>
                                        <td class="small"><code><?= htmlspecialchars($log['event_type']) ?></code></td>
                                        <td>
                                            <?php
                                            $badgeClass = match($log['outcome']) {
                                                'success' => 'bg-success',
                                                'fail' => 'bg-danger',
                                                default => 'bg-info'
                                            };
                                            ?>
                                            <span class="badge <?= $badgeClass ?>"><?= htmlspecialchars($log['outcome']) ?></span>
                                        </td>
                                        <td class="small"><?= htmlspecialchars($log['ip_address']) ?></td>
                                        <td class="small">
                                            <?php
                                            $actorUserUuid = (string) ($log['actor_user_uuid'] ?? '');
                                            $actorUserDisplay = $actorUserUuid !== '' ? ($userDisplayMap[$actorUserUuid] ?? null) : null;
                                            ?>
                                            <?php if ($actorUserDisplay !== null): ?>
                                                <a
                                                    href="<?= htmlspecialchars($actorUserDisplay['href']) ?>"
                                                    class="link-info text-decoration-none"
                                                    title="<?= htmlspecialchars(trim(($actorUserDisplay['name'] !== '' ? $actorUserDisplay['name'] . ' ' : '') . '(' . $actorUserUuid . ')')) ?>"
                                                >
                                                    <code><?= htmlspecialchars($actorUserUuid) ?></code>
                                                </a>
                                            <?php elseif ($actorUserUuid !== ''): ?>
                                                <code title="<?= htmlspecialchars($actorUserUuid) ?>"><?= htmlspecialchars($actorUserUuid) ?></code>
                                            <?php else: ?>
                                                -
                                            <?php endif; ?>
                                        </td>
                                        <td class="small">
                                            <?php
                                            $projectUuid = (string) ($log['project_uuid'] ?? '');
                                            $projectDisplay = $projectUuid !== '' ? ($projectDisplayMap[$projectUuid] ?? null) : null;
                                            ?>
                                            <?php if ($projectDisplay !== null): ?>
                                                <a
                                                    href="<?= htmlspecialchars($projectDisplay['href']) ?>"
                                                    class="link-info text-decoration-none"
                                                    title="<?= htmlspecialchars($projectDisplay['name'] . ' (' . $projectUuid . ')') ?>"
                                                >
                                                    <code><?= htmlspecialchars($projectUuid) ?></code>
                                                </a>
                                            <?php elseif ($projectUuid !== ''): ?>
                                                <code title="<?= htmlspecialchars($projectUuid) ?>"><?= htmlspecialchars($projectUuid) ?></code>
                                            <?php else: ?>
                                                -
                                            <?php endif; ?>
                                        </td>
                                        <td class="small">
                                            <?php
                                            $clientPublicId = (string) ($log['oauth_client_public_id'] ?? '');
                                            $clientDisplay = $clientPublicId !== '' ? ($clientDisplayMap[$clientPublicId] ?? null) : null;
                                            ?>
                                            <?php if ($clientDisplay !== null): ?>
                                                <a
                                                    href="<?= htmlspecialchars($clientDisplay['href']) ?>"
                                                    class="link-info text-decoration-none"
                                                    title="<?= htmlspecialchars($clientDisplay['name'] . ' (' . $clientPublicId . ')') ?>"
                                                >
                                                    <code><?= htmlspecialchars($clientPublicId) ?></code>
                                                </a>
                                            <?php elseif ($clientPublicId !== ''): ?>
                                                <code title="<?= htmlspecialchars($clientPublicId) ?>"><?= htmlspecialchars($clientPublicId) ?></code>
                                            <?php else: ?>
                                                -
                                            <?php endif; ?>
                                        </td>
                                        <td class="small"><?= htmlspecialchars($log['message']) ?></td>
                                        <td class="small"><code><?= htmlspecialchars(substr($log['correlation_id'], 0, 8)) ?>...</code></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <?php if ($pages > 1): ?>
                <nav class="mt-3">
                    <ul class="pagination pagination-sm">
                        <?php for ($i = 1; $i <= $pages; $i++): ?>
                            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?><?= http_build_query($filters) ? '&' . http_build_query($filters) : '' ?>">
                                    <?= $i ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                    </ul>
                </nav>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
