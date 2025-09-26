<div class="row">
    <div class="col-12">
        <div class="page-header">
            <h2>✅ Approval Queue</h2>
            <p class="text-muted mb-0">Pending and historical approval requests.</p>
        </div>

        <div class="card">
            <div class="card-body">
                <?php if (empty($approvals)): ?>
                    <p class="text-muted mb-0">No approval requests found.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover mb-0 align-middle">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                    <th>Requested By</th>
                                    <th>Created</th>
                                    <th>Payload</th>
                                    <th>Decision</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($approvals as $approval): ?>
                                    <?php
                                    $status = (string) $approval['status'];
                                    $badge = $status === 'pending'
                                        ? 'bg-warning text-dark'
                                        : ($status === 'approved' ? 'bg-success' : ($status === 'rejected' ? 'bg-danger' : 'bg-secondary'));
                                    $payloadPretty = json_encode(json_decode((string) $approval['payload_json'], true), JSON_PRETTY_PRINT);
                                    ?>
                                    <tr>
                                        <td><code><?= (int) $approval['id'] ?></code></td>
                                        <td><span class="badge <?= $badge ?>"><?= htmlspecialchars($status) ?></span></td>
                                        <td><code><?= htmlspecialchars((string) $approval['action_type']) ?></code></td>
                                        <td>
                                            <?= htmlspecialchars((string) ($approval['requested_by_display_label'] ?? '-')) ?>
                                            <div><code class="small"><?= htmlspecialchars((string) ($approval['requested_by_uuid'] ?? '-')) ?></code></div>
                                        </td>
                                        <td class="text-muted"><?= htmlspecialchars((string) $approval['created_at']) ?></td>
                                        <td><pre class="mb-0 small"><?= htmlspecialchars((string) $payloadPretty) ?></pre></td>
                                        <td>
                                            <?php if ($status === 'pending' && ($currentAdminRole ?? '') === 'super_admin'): ?>
                                                <div class="d-flex gap-2 flex-wrap">
                                                    <form method="POST" action="/admin/approvals/<?= (int) $approval['id'] ?>/approve" class="d-inline">
                                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                        <input type="hidden" name="note" value="Approved via admin UI">
                                                        <button type="submit" class="btn btn-sm btn-success">Approve</button>
                                                    </form>
                                                    <form method="POST" action="/admin/approvals/<?= (int) $approval['id'] ?>/reject" class="d-inline">
                                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                        <input type="hidden" name="note" value="Rejected via admin UI">
                                                        <button type="submit" class="btn btn-sm btn-outline-danger">Reject</button>
                                                    </form>
                                                    <?php if ((int) $approval['requested_by_user_id'] === (int) \BlackWall\Security\SessionManager::get('user_id')): ?>
                                                        <form method="POST" action="/admin/approvals/<?= (int) $approval['id'] ?>/cancel" class="d-inline">
                                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                            <input type="hidden" name="note" value="Cancelled by requester">
                                                            <button type="submit" class="btn btn-sm btn-outline-secondary">Cancel</button>
                                                        </form>
                                                    <?php endif; ?>
                                                </div>
                                            <?php elseif ($status === 'pending'): ?>
                                                <div class="d-flex gap-2 flex-wrap align-items-center">
                                                    <span class="text-muted small">Pending super-admin decision</span>
                                                    <?php if ((int) $approval['requested_by_user_id'] === (int) \BlackWall\Security\SessionManager::get('user_id')): ?>
                                                        <form method="POST" action="/admin/approvals/<?= (int) $approval['id'] ?>/cancel" class="d-inline">
                                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                            <input type="hidden" name="note" value="Cancelled by requester">
                                                            <button type="submit" class="btn btn-sm btn-outline-secondary">Cancel</button>
                                                        </form>
                                                    <?php endif; ?>
                                                </div>
                                            <?php else: ?>
                                                <div class="text-muted small">
                                                    <?= htmlspecialchars((string) ($approval['decision_note'] ?? '-')) ?>
                                                </div>
                                                <?php if (!empty($approval['approved_by_uuid'])): ?>
                                                    <div><code class="small"><?= htmlspecialchars((string) $approval['approved_by_uuid']) ?></code></div>
                                                <?php endif; ?>
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
