<h4>First 15 Minutes Checklist</h4>
<ol>
    <li>Sign in at <code>/admin/login</code> with your enrolled WebAuthn authenticator.</li>
    <li>Open <code>/admin/scope</code> and verify:
        <ul>
            <li>your session is recognised as admin;</li>
            <li>super-admin status is correct;</li>
            <li>project UUID scope matches expected assignments.</li>
        </ul>
    </li>
    <li>Open <code>/admin/dashboard</code> and review:
        <ul>
            <li>approval backlog and SLA badges;</li>
            <li>CSRF failure counts;</li>
            <li>admin mutation rate-limit hits.</li>
        </ul>
    </li>
    <li>Open <code>/admin/approvals</code>:
        <ul>
            <li>inspect pending requests;</li>
            <li>use denial filters to check recurring control failures.</li>
        </ul>
    </li>
    <li>Open <code>/admin/audit</code>:
        <ul>
            <li>confirm your login events are present;</li>
            <li>check for unusual fail outcomes in the last 24 hours.</li>
        </ul>
    </li>
</ol>

<h4>Super Admin Additional Checks</h4>
<ul>
    <li>Confirm at least one other active super-admin route exists (avoid single-point lockout).</li>
    <li>Confirm maintenance and error trace tools are reachable and functioning.</li>
    <li>Review pending requests older than your configured warning threshold.</li>
</ul>

<h4>Project Admin Additional Checks</h4>
<ul>
    <li>Confirm only scoped projects are visible in <code>/admin/projects</code>.</li>
    <li>Confirm only scoped users are visible in <code>/admin/users</code>.</li>
    <li>Confirm out-of-scope direct URLs return <code>403</code>.</li>
</ul>

<h4>Immediate Incident Triage Sequence</h4>
<ol>
    <li>Check dashboard security cards for spikes.</li>
    <li>Filter audit by relevant event type and time window.</li>
    <li>Correlate actor, project, and IP address.</li>
    <li>Freeze risky changes by operational procedure if necessary.</li>
    <li>Record decisions and evidence in your incident log.</li>
</ol>
