<h4>Key Admin Routes</h4>
<ul>
    <li><code>/admin/dashboard</code>: overview and operational cards</li>
    <li><code>/admin/scope</code>: scope diagnostics</li>
    <li><code>/admin/users</code>: user administration</li>
    <li><code>/admin/projects</code>: project administration</li>
    <li><code>/admin/approvals</code>: approval queue</li>
    <li><code>/admin/audit</code>: audit search and export</li>
    <li><code>/admin/maintenance</code>: maintenance status</li>
    <li><code>/admin/docs</code>: documentation centre</li>
</ul>

<h4>Important Environment Variables</h4>
<ul>
    <li><code>ADMIN_SUPER_PROJECT_NAME</code></li>
    <li><code>ADMIN_SUPER_PROJECT_UUID</code></li>
    <li><code>ADMIN_MUTATION_RATE_LIMIT_ATTEMPTS</code></li>
    <li><code>ADMIN_MUTATION_RATE_LIMIT_WINDOW_SECONDS</code></li>
    <li><code>ADMIN_APPROVAL_PENDING_WARNING_DAYS</code></li>
    <li><code>EVENT_METRICS_PUSH_ENABLED</code></li>
    <li><code>EVENT_METRICS_PUSH_URL</code></li>
    <li><code>EVENT_METRICS_PUSH_METRIC_NAME</code></li>
    <li><code>EVENT_METRICS_PUSH_STATIC_LABELS</code></li>
</ul>

<h4>Glossary</h4>
<ul>
    <li><strong>Scope</strong>: the projects an admin session can access.</li>
    <li><strong>Super admin</strong>: actor with global project scope.</li>
    <li><strong>Approval decision SLA</strong>: latency targets for request decisions.</li>
    <li><strong>Denial reason</strong>: structured reason for blocked approval decision.</li>
    <li><strong>vmagent importer</strong>: endpoint accepting Prometheus exposition input.</li>
</ul>

<h4>Cross-Document References</h4>
<ul>
    <li>Repository docs index: <code>docs/README.md</code></li>
    <li>Operational runbook: <code>docs/RUNBOOK.md</code></li>
    <li>User manual: <code>docs/USER_MANUAL.md</code></li>
</ul>
