<div class="row">
    <div class="col-12">
        <div class="page-header">
            <h2>✅ Approval Queue</h2>
            <p class="text-muted mb-0">
                <?= ($currentAdminRole ?? '') === 'super_admin'
                    ? 'Pending and historical approval requests.'
                    : 'Approval requests within your admin scope (plus your own unscoped requests).' ?>
            </p>
        </div>

        <?php if (isset($_GET['success']) && $_GET['success'] === 'approved'): ?>
            <div class="alert alert-success">Approval request approved.</div>
        <?php elseif (isset($_GET['success']) && $_GET['success'] === 'rejected'): ?>
            <div class="alert alert-success">Approval request rejected.</div>
        <?php elseif (isset($_GET['success']) && $_GET['success'] === 'cancelled'): ?>
            <div class="alert alert-success">Approval request cancelled.</div>
        <?php endif; ?>

        <?php if (isset($_GET['error']) && $_GET['error'] === 'csrf'): ?>
            <div class="alert alert-danger">Security validation failed. Please retry.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'not_pending'): ?>
            <div class="alert alert-danger">Request is no longer pending.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'self_decide'): ?>
            <div class="alert alert-danger">You cannot approve your own request.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'execution_failed'): ?>
            <div class="alert alert-danger">Approval execution failed and the request was rejected.</div>
        <?php elseif (isset($_GET['error']) && $_GET['error'] === 'rate_limited'): ?>
            <div class="alert alert-danger">Too many admin changes in a short period. Please wait and retry.</div>
        <?php endif; ?>

        <div class="card mb-3">
            <div class="card-body">
                <h6 class="mb-2">Why was a decision denied?</h6>
                <p class="text-muted small mb-2">Use the quick filters below to find denied items by reason.</p>
                <ul class="mb-0 small">
                    <li><code>missing_capability</code>: your current admin role cannot decide approvals. Use a super-admin account.</li>
                    <li><code>out_of_scope</code>: the approval belongs to a project outside your scope. Switch to an account that administers that project.</li>
                    <li><code>self_decision</code>: you requested the action yourself. Another eligible approver must decide it.</li>
                </ul>
            </div>
        </div>

        <div class="card mb-3">
            <div class="card-body">
                <?php if (!empty($failureReasonOptions)): ?>
                    <div class="mb-3 d-flex flex-wrap gap-2">
                        <span class="text-muted small me-2">Decision denial shortcuts:</span>
                        <?php foreach ($failureReasonOptions as $reason): ?>
                            <?php $url = '?' . htmlspecialchars(http_build_query(array_merge($filters ?? [], ['failure_reason' => $reason, 'page' => 1]))); ?>
                            <a class="btn btn-sm <?= (($filters['failure_reason'] ?? '') === $reason) ? 'btn-warning' : 'btn-outline-warning' ?>" href="<?= $url ?>">
                                <?= htmlspecialchars((string) $reason) ?>
                            </a>
                        <?php endforeach; ?>
                        <a class="btn btn-sm btn-outline-secondary" href="?<?= htmlspecialchars(http_build_query(array_merge($filters ?? [], ['failure_reason' => '', 'page' => 1]))) ?>">
                            Clear
                        </a>
                    </div>
                <?php endif; ?>

                <form method="GET" action="/admin/approvals" class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Status</label>
                        <select name="status" class="form-select">
                            <option value="">All</option>
                            <option value="pending" <?= ($filters['status'] ?? '') === 'pending' ? 'selected' : '' ?>>Pending</option>
                            <option value="approved" <?= ($filters['status'] ?? '') === 'approved' ? 'selected' : '' ?>>Approved</option>
                            <option value="rejected" <?= ($filters['status'] ?? '') === 'rejected' ? 'selected' : '' ?>>Rejected</option>
                            <option value="cancelled" <?= ($filters['status'] ?? '') === 'cancelled' ? 'selected' : '' ?>>Cancelled</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Action Type</label>
                        <input type="text" name="action_type" class="form-control" value="<?= htmlspecialchars((string) ($filters['action_type'] ?? '')) ?>" placeholder="change_user_status">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Project UUID</label>
                        <input type="text" name="project_uuid" class="form-control" value="<?= htmlspecialchars((string) ($filters['project_uuid'] ?? '')) ?>" placeholder="Project UUID">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Failure Reason</label>
                        <select name="failure_reason" class="form-select">
                            <option value="">Any</option>
                            <?php foreach (($failureReasonOptions ?? []) as $reason): ?>
                                <option value="<?= htmlspecialchars((string) $reason) ?>" <?= (($filters['failure_reason'] ?? '') === $reason) ? 'selected' : '' ?>>
                                    <?= htmlspecialchars((string) $reason) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <?php if (($currentAdminRole ?? '') === 'super_admin'): ?>
                        <div class="col-md-3">
                            <label class="form-label">Requester UUID</label>
                            <input type="text" name="requested_by_uuid" class="form-control" value="<?= htmlspecialchars((string) ($filters['requested_by_uuid'] ?? '')) ?>" placeholder="User UUID">
                        </div>
                    <?php endif; ?>
                    <div class="col-md-3">
                        <label class="form-label">Date From</label>
                        <input type="date" name="date_from" class="form-control" value="<?= htmlspecialchars((string) ($filters['date_from'] ?? '')) ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Date To</label>
                        <input type="date" name="date_to" class="form-control" value="<?= htmlspecialchars((string) ($filters['date_to'] ?? '')) ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">&nbsp;</label>
                        <button type="submit" class="btn btn-primary w-100">Filter</button>
                    </div>
                </form>
            </div>
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
                                        <th>Project</th>
                                        <th>Requested By</th>
                                        <th>Created</th>
                                        <th>Last Denial</th>
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
                                            <?= htmlspecialchars((string) ($approval['project_name'] ?? '-')) ?>
                                            <div><code class="small"><?= htmlspecialchars((string) ($approval['project_uuid'] ?? '-')) ?></code></div>
                                        </td>
                                        <td>
                                            <?= htmlspecialchars((string) ($approval['requested_by_display_label'] ?? '-')) ?>
                                            <div><code class="small"><?= htmlspecialchars((string) ($approval['requested_by_uuid'] ?? '-')) ?></code></div>
                                        </td>
                                        <td class="text-muted"><?= htmlspecialchars((string) $approval['created_at']) ?></td>
                                        <td>
                                            <?php if (!empty($approval['latest_denial_reason'])): ?>
                                                <span class="badge bg-warning text-dark"><?= htmlspecialchars((string) $approval['latest_denial_reason']) ?></span>
                                            <?php else: ?>
                                                <span class="text-muted">-</span>
                                            <?php endif; ?>
                                        </td>
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

                <?php if (($pages ?? 1) > 1): ?>
                    <nav class="mt-3">
                        <ul class="pagination pagination-sm">
                            <?php for ($i = 1; $i <= (int) ($pages ?? 1); $i++): ?>
                                <li class="page-item <?= $i === (int) ($page ?? 1) ? 'active' : '' ?>">
                                    <a class="page-link" href="?<?= htmlspecialchars(http_build_query(array_merge($filters ?? [], ['page' => $i]))) ?>">
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
