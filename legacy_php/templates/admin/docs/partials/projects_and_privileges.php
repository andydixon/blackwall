<h4>Project Administration</h4>
<p>
    Projects define tenancy boundaries, privilege labels, client ownership, and audit segmentation.
    Project UUIDs are first-class identifiers in admin URLs and filters.
</p>

<h4>Privilege Model</h4>
<ul>
    <li>Level 1: <strong>Admin</strong></li>
    <li>Level 2: <strong>User</strong></li>
    <li>Level 3: <strong>Restricted User</strong></li>
    <li>Other levels: <strong>Custom Rules (level n)</strong></li>
</ul>

<h4>Privilege Level Management</h4>
<p>At <code>/admin/projects/{projectUuid}/privileges</code> you can:</p>
<ul>
    <li>define custom labels and descriptions;</li>
    <li>keep defaults where no override is needed;</li>
    <li>delete unused levels (directly or via approval path).</li>
</ul>

<h4>Assignments</h4>
<p>At <code>/admin/projects/{projectUuid}/assignments</code> you can:</p>
<ul>
    <li>assign users to project scope;</li>
    <li>change privilege levels;</li>
    <li>remove assignments;</li>
    <li>trigger approval requests where policy requires review.</li>
</ul>

<h4>Scope Integrity Expectations</h4>
<ul>
    <li>Project admins must not assign users outside visible scope via tampered requests.</li>
    <li>Out-of-scope project pages must return <code>403</code>.</li>
    <li>Assignment updates/deletes should remain project-bound.</li>
</ul>

<h4>Recommended Control Practice</h4>
<ol>
    <li>Keep Level 1 membership minimal and intentional.</li>
    <li>Use privilege names that map clearly to internal policy language.</li>
    <li>Review assignment churn monthly through audit records.</li>
    <li>Route sensitive reassignment through approval when operationally appropriate.</li>
</ol>
