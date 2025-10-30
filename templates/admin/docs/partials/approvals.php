<h4>Purpose of Approvals</h4>
<p>
    Approvals provide controlled execution for high-impact administrative actions.
    They reduce accidental change risk and enforce separation of duties.
</p>

<h4>Queue Access</h4>
<ul>
    <li>Open queue: <code>/admin/approvals</code></li>
    <li>Super admins: full queue and decision controls.</li>
    <li>Scoped admins/auditors: in-scope requests plus own unscoped requests.</li>
</ul>

<h4>Filters</h4>
<p>Available filters include:</p>
<ul>
    <li>status</li>
    <li>action type</li>
    <li>project UUID</li>
    <li>requester UUID (super admin)</li>
    <li>date range</li>
    <li>denial failure reason</li>
</ul>

<h4>Denial Reasons</h4>
<ul>
    <li><code>missing_capability</code>: actor lacks decision capability.</li>
    <li><code>out_of_scope</code>: request belongs to project outside actor scope.</li>
    <li><code>self_decision</code>: actor attempted to decide own request.</li>
</ul>

<h4>Decision SLA</h4>
<p>
    Dashboard SLA indicators provide median and P95 decision latency.
    Overdue pending requests are highlighted using your configured warning threshold.
</p>

<h4>Operational Pattern</h4>
<ol>
    <li>Review pending items by age and risk.</li>
    <li>Validate payload and target scope.</li>
    <li>Decide with concise note quality suitable for audit review.</li>
    <li>Investigate repeated denials by reason trend.</li>
</ol>

<h4>Anti-Patterns to Avoid</h4>
<ul>
    <li>Routine blind approvals without payload verification.</li>
    <li>Using approval notes that cannot be interpreted later.</li>
    <li>Allowing queue backlog to grow without owner accountability.</li>
</ul>
