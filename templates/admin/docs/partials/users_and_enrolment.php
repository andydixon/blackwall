<h4>User Lifecycle</h4>
<ol>
    <li>Create user record (super admin).</li>
    <li>Generate enrolment link for WebAuthn registration.</li>
    <li>Assign user to one or more projects with defined privilege level.</li>
    <li>Maintain status and credentials over time.</li>
</ol>

<h4>Creating and Enrolling Users</h4>
<ul>
    <li>Create at <code>/admin/users/create</code>.</li>
    <li>Generate enrolment link from <code>/admin/users/{userUuid}</code>.</li>
    <li>Enrolment links should be treated as sensitive and time-bound operational secrets.</li>
</ul>

<h4>Credential Management</h4>
<ul>
    <li>Users may hold multiple WebAuthn credentials.</li>
    <li>Credential deletions may be direct or approval-gated depending on capability.</li>
    <li>Minimum retained key policy prevents accidental lockout.</li>
</ul>

<h4>Status Management</h4>
<p>Supported statuses:</p>
<ul>
    <li><code>active</code></li>
    <li><code>disabled</code></li>
</ul>
<p>
    Disabling highly privileged accounts can be approval-gated and is constrained by
    super-admin safety rules.
</p>

<h4>Scoped Visibility Considerations</h4>
<ul>
    <li>Project admins can only see users allocated to their projects.</li>
    <li>Direct links to out-of-scope users must return <code>403</code>.</li>
    <li>User assignments shown on detail pages are filtered by scope for non-super admins.</li>
</ul>

<h4>Operational Advice</h4>
<ol>
    <li>Keep display labels clear and unique for audit readability.</li>
    <li>Prefer assigning users before sharing enrolment links in production workflows.</li>
    <li>Review disabled users quarterly for clean-up or reactivation decisions.</li>
    <li>Use audit filters to review credential-related actions by project and actor.</li>
</ol>
