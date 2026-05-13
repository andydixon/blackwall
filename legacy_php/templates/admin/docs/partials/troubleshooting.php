<h4>Diagnostic Order</h4>
<ol>
    <li>Check <code>/admin/scope</code> for capability and scope alignment.</li>
    <li>Check dashboard security widgets for abnormal spikes.</li>
    <li>Check <code>/admin/audit</code> for event chronology and failure reasons.</li>
    <li>Check approval queue for blocked or denied actions.</li>
    <li>Check application logs for transport/infrastructure errors.</li>
</ol>

<h4>Frequent Issues</h4>

<h5>Issue: <code>403</code> on known admin route</h5>
<ul>
    <li>Confirm actor has Level 1 on relevant project.</li>
    <li>Confirm route target is in actor scope.</li>
    <li>Confirm super-admin matching configuration is correct.</li>
</ul>

<h5>Issue: Approval cannot be decided</h5>
<ul>
    <li>Check request status is still <code>pending</code>.</li>
    <li>Check actor is not the requester.</li>
    <li>Check denial reason filter for repeated pattern.</li>
</ul>

<h5>Issue: Event metrics not visible in vmagent</h5>
<ul>
    <li>Check event push is enabled and URL is reachable.</li>
    <li>Check timeout and vmagent importer endpoint path.</li>
    <li>Check application logs for push failures.</li>
</ul>

<h5>Issue: CSRF failures increasing</h5>
<ul>
    <li>Check client/session handling, stale forms, and navigation patterns.</li>
    <li>Inspect affected projects and actors via audit filters.</li>
    <li>Review reverse proxy/session configuration changes.</li>
</ul>

<h4>Escalation Trigger Examples</h4>
<ul>
    <li>Repeated out-of-scope denial bursts.</li>
    <li>Sustained admin mutation rate-limit hits.</li>
    <li>Approval backlog beyond defined SLA.</li>
    <li>Unexpected scope expansion or role drift.</li>
</ul>
