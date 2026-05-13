<h4>Audit Log Operations</h4>
<p>
    Use <code>/admin/audit</code> for event investigation and evidence extraction.
    Audit entries include event type, outcome, actor, target, project context, and metadata.
</p>

<h4>Typical Audit Filters</h4>
<ul>
    <li>date range for incident windows;</li>
    <li>project UUID for scoped review;</li>
    <li>event type partial match (for pattern hunting);</li>
    <li>outcome and correlation ID for precise tracing.</li>
</ul>

<h4>Security Signals on Dashboard</h4>
<ul>
    <li><strong>CSRF failures</strong> with scoped counts and top projects (30-day).</li>
    <li><strong>Admin mutation rate-limit hits</strong> with scoped counts and top projects (30-day).</li>
</ul>

<h4>Decision-Denial Audit Events</h4>
<p>Approval decision denials are logged with structured failure reasons. These events support:</p>
<ul>
    <li>policy adherence checks;</li>
    <li>scope misconfiguration detection;</li>
    <li>training feedback for admin operators.</li>
</ul>

<h4>Export Guidance</h4>
<ul>
    <li>Use filtered export where possible to minimise data handling.</li>
    <li>Retain exported data in controlled storage.</li>
    <li>Record export rationale and consumer in incident/change records.</li>
</ul>

<h4>Response Procedure (Suspected Abuse)</h4>
<ol>
    <li>Identify pattern in dashboard security cards.</li>
    <li>Correlate with audit records and actor scope.</li>
    <li>Contain by restricting risky operations if required.</li>
    <li>Escalate with evidence pack (filters, timestamps, correlation IDs).</li>
    <li>Capture post-incident control improvements.</li>
</ol>
