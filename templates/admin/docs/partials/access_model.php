<h4>Admin Eligibility</h4>
<p>
    A user can access <code>/admin</code> only when they hold <code>privilege_level = 1</code>
    on at least one project.
</p>

<h4>Super Admin Resolution</h4>
<p>
    Super-admin scope is inferred when a user is Level 1 on the configured admin project.
    Matching is controlled by environment configuration:
</p>
<ul>
    <li><code>ADMIN_SUPER_PROJECT_NAME</code> (default: <code>BlackWall Admin</code>)</li>
    <li><code>ADMIN_SUPER_PROJECT_UUID</code> (optional explicit override)</li>
</ul>

<h4>Scope Rules</h4>
<ul>
    <li><strong>Super admin</strong>: global visibility and management rights across all projects.</li>
    <li><strong>Project admin</strong>: visibility and management limited to scoped projects.</li>
    <li><strong>Auditor</strong>: read-oriented functions within allowed capability matrix.</li>
</ul>

<h4>Practical Visibility Boundaries</h4>
<p>For non-super admins, scope is enforced for:</p>
<ul>
    <li>project listing and project detail pages;</li>
    <li>user listing and user detail pages;</li>
    <li>client listing and client detail pages;</li>
    <li>audit log search and export;</li>
    <li>approval queue visibility and filtering.</li>
</ul>

<h4>Scope Diagnostics</h4>
<p>
    Use <code>/admin/scope</code> as the first check whenever an access issue is reported.
    It exposes current session scope and super-admin matching inputs.
</p>

<h4>Safety Controls</h4>
<ul>
    <li>Protection against removing the last active super-admin path.</li>
    <li>Approval gating for high-risk non-direct actions.</li>
    <li>Rate limiting for admin mutation endpoints.</li>
</ul>

<h4>Recommended Governance Practice</h4>
<ol>
    <li>Use named operational groups in your identity management process.</li>
    <li>Review Level 1 memberships monthly.</li>
    <li>Retain evidence of scope changes through audit records.</li>
    <li>Run the acceptance checklist after each role/scope change.</li>
</ol>
