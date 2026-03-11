<?php
$filters = is_array($filters ?? null) ? $filters : [];
$formatBytes = static function (int $bytes): string {
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

$sortLink = static function (string $column, string $currentSort, string $currentDir, array $filters): string {
    $dir = ($currentSort === $column && $currentDir === 'asc') ? 'desc' : 'asc';
    $query = array_filter([
        'sort' => $column,
        'dir' => $dir,
        'status' => $filters['status'] ?? '',
        'item_type' => $filters['item_type'] ?? '',
        'activity' => $filters['activity'] ?? '',
    ], static fn($value): bool => $value !== '');
    return '/admin/cryptbin?' . http_build_query($query);
};
?>

<div class="row">
    <div class="col-12">
        <div class="d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-3 mb-4">
            <div>
                <h2 class="mb-1">Cryptbin</h2>
                <p class="text-muted mb-0">Superadmin overview of stored Cryptbin items, access activity, and retention posture.</p>
            </div>
            <div>
                <a href="/admin/dashboard" class="btn btn-outline-light btn-sm">Back to Dashboard</a>
            </div>
        </div>

        <?php if (isset($_GET['success']) && $_GET['success'] === 'deleted'): ?>
            <div class="alert alert-success">Cryptbin item deleted successfully.</div>
        <?php endif; ?>
        <?php if (isset($_GET['error']) && $_GET['error'] === 'csrf'): ?>
            <div class="alert alert-danger">Security validation failed. Please retry.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'invalid'): ?>
            <div class="alert alert-danger">Invalid Cryptbin item identifier.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'not_found'): ?>
            <div class="alert alert-danger">Cryptbin item not found.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'delete'): ?>
            <div class="alert alert-danger">Unable to delete the Cryptbin item.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'rate_limited'): ?>
            <div class="alert alert-danger">Too many admin changes in a short period. Please wait and retry.</div>
        <?php endif; ?>

        <div class="row g-4 mb-4">
            <div class="col-md-6 col-xl-3">
                <div class="card stat-card h-100">
                    <div class="card-body">
                        <div class="text-muted small text-uppercase mb-1">Items</div>
                        <div class="display-6 mb-0"><?= (int) ($cryptbinStats['total_items'] ?? 0) ?></div>
                        <div class="small text-muted mt-2">
                            Active: <?= (int) ($cryptbinStats['active_items'] ?? 0) ?>
                            · Expired: <?= (int) ($cryptbinStats['expired_items'] ?? 0) ?>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6 col-xl-3">
                <div class="card stat-card h-100" style="border-left-color: #f59e0b;">
                    <div class="card-body">
                        <div class="text-muted small text-uppercase mb-1">Stored Size</div>
                        <div class="display-6 mb-0" style="color: #f59e0b;"><?= htmlspecialchars($formatBytes((int) ($cryptbinStats['total_bytes'] ?? 0))) ?></div>
                        <div class="small text-muted mt-2">Ciphertext payload size across all current items.</div>
                    </div>
                </div>
            </div>
            <div class="col-md-6 col-xl-3">
                <div class="card stat-card h-100" style="border-left-color: #10b981;">
                    <div class="card-body">
                        <div class="text-muted small text-uppercase mb-1">Last Updated</div>
                        <div class="fw-semibold" style="font-size: 1.1rem; color: #10b981;">
                            <?= htmlspecialchars((string) (($cryptbinStats['last_updated_at'] ?? null) ?: 'Never')) ?>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6 col-xl-3">
                <div class="card stat-card h-100" style="border-left-color: #3b82f6;">
                    <div class="card-body">
                        <div class="text-muted small text-uppercase mb-1">Last Accessed</div>
                        <div class="fw-semibold" style="font-size: 1.1rem; color: #3b82f6;">
                            <?= htmlspecialchars((string) (($cryptbinStats['last_accessed_at'] ?? null) ?: 'Never')) ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-body">
                <form method="GET" action="/admin/cryptbin" class="row g-3 align-items-end">
                    <div class="col-md-3">
                        <label class="form-label">Status</label>
                        <select name="status" class="form-select">
                            <option value="">All</option>
                            <option value="active" <?= ($filters['status'] ?? '') === 'active' ? 'selected' : '' ?>>Active</option>
                            <option value="expired" <?= ($filters['status'] ?? '') === 'expired' ? 'selected' : '' ?>>Expired</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Type</label>
                        <select name="item_type" class="form-select">
                            <option value="">All</option>
                            <option value="text" <?= ($filters['item_type'] ?? '') === 'text' ? 'selected' : '' ?>>Text</option>
                            <option value="file" <?= ($filters['item_type'] ?? '') === 'file' ? 'selected' : '' ?>>File</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Recent Activity</label>
                        <select name="activity" class="form-select">
                            <option value="">Any time</option>
                            <option value="24h" <?= ($filters['activity'] ?? '') === '24h' ? 'selected' : '' ?>>Last 24 hours</option>
                            <option value="7d" <?= ($filters['activity'] ?? '') === '7d' ? 'selected' : '' ?>>Last 7 days</option>
                            <option value="30d" <?= ($filters['activity'] ?? '') === '30d' ? 'selected' : '' ?>>Last 30 days</option>
                        </select>
                    </div>
                    <div class="col-md-3 d-flex gap-2">
                        <button type="submit" class="btn btn-primary flex-grow-1">Apply Filters</button>
                        <a href="/admin/cryptbin" class="btn btn-outline-light">Reset</a>
                    </div>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-body">
                <?php if (empty($items)): ?>
                    <p class="text-muted mb-0">No Cryptbin items found.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover align-middle mb-0">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Type</th>
                                    <th>Filename / MIME</th>
                                    <th><a class="link-light text-decoration-none" href="<?= htmlspecialchars($sortLink('size_bytes', $sort, $dir, $filters)) ?>">Size</a></th>
                                    <th><a class="link-light text-decoration-none" href="<?= htmlspecialchars($sortLink('created_at', $sort, $dir, $filters)) ?>">Created</a></th>
                                    <th><a class="link-light text-decoration-none" href="<?= htmlspecialchars($sortLink('updated_at', $sort, $dir, $filters)) ?>">Updated</a></th>
                                    <th><a class="link-light text-decoration-none" href="<?= htmlspecialchars($sortLink('last_accessed_at', $sort, $dir, $filters)) ?>">Last Accessed</a></th>
                                    <th><a class="link-light text-decoration-none" href="<?= htmlspecialchars($sortLink('access_count', $sort, $dir, $filters)) ?>">Accesses</a></th>
                                    <th>Status</th>
                                    <th class="text-end">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($items as $item): ?>
                                    <tr>
                                        <td><code><?= htmlspecialchars((string) $item['id']) ?></code></td>
                                        <td>
                                            <span class="badge <?= ($item['item_type'] ?? '') === 'file' ? 'bg-info' : 'bg-secondary' ?>">
                                                <?= htmlspecialchars((string) $item['item_type']) ?>
                                            </span>
                                        </td>
                                        <td>
                                            <div><?= htmlspecialchars((string) (($item['original_filename'] ?? '') !== '' ? $item['original_filename'] : '-')) ?></div>
                                            <div class="small text-muted"><?= htmlspecialchars((string) ($item['mime_type'] ?? '-')) ?></div>
                                        </td>
                                        <td><?= htmlspecialchars($formatBytes((int) ($item['size_bytes'] ?? 0))) ?></td>
                                        <td class="small text-muted"><?= htmlspecialchars((string) (($item['created_at'] ?? '') !== '' ? $item['created_at'] : '-')) ?></td>
                                        <td class="small text-muted"><?= htmlspecialchars((string) (($item['updated_at'] ?? '') !== '' ? $item['updated_at'] : '-')) ?></td>
                                        <td class="small text-muted"><?= htmlspecialchars((string) (($item['last_accessed_at'] ?? '') !== '' ? $item['last_accessed_at'] : '-')) ?></td>
                                        <td><?= (int) ($item['access_count'] ?? 0) ?></td>
                                        <td>
                                            <?php if (!empty($item['is_expired'])): ?>
                                                <span class="badge bg-warning text-dark">Expired</span>
                                            <?php else: ?>
                                                <span class="badge bg-success">Active</span>
                                            <?php endif; ?>
                                            <?php if (!empty($item['requires_webauthn_for_view'])): ?>
                                                <span class="badge bg-dark border border-secondary">WebAuthn</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-end">
                                            <div class="d-flex justify-content-end gap-2">
                                                <a href="/cryptbin/<?= urlencode((string) $item['id']) ?>" class="btn btn-sm btn-outline-light">Open</a>
                                                <form method="POST" action="/admin/cryptbin/<?= urlencode((string) $item['id']) ?>/delete" onsubmit="return confirm('Delete Cryptbin item <?= htmlspecialchars((string) $item['id'], ENT_QUOTES) ?>?');">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                                </form>
                                            </div>
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
