<h4>Routine Maintenance</h4>
<ul>
    <li>Review maintenance job runs at <code>/admin/maintenance</code>.</li>
    <li>Monitor approval backlog age and stale pending requests.</li>
    <li>Review security indicators weekly for trend drift.</li>
</ul>

<h4>Backup Standards</h4>
<ul>
    <li>Automated database backups with retention and integrity checks.</li>
    <li>Secure backup of configuration secrets and keys with strict access controls.</li>
    <li>Documented recovery objectives (RPO/RTO) agreed with stakeholders.</li>
</ul>

<h4>Recovery Rehearsal</h4>
<ol>
    <li>Restore backup into isolated environment.</li>
    <li>Run health checks and admin login verification.</li>
    <li>Verify key routes, audit visibility, and scope controls.</li>
    <li>Record restoration duration and deviations.</li>
</ol>

<h4>Change Safety</h4>
<ul>
    <li>Run acceptance checklist after scope/role logic changes.</li>
    <li>Use approvals and audit evidence for high-risk operations.</li>
    <li>Retain rollback plans for database and configuration updates.</li>
</ul>

<h4>Disaster Recovery Essentials</h4>
<ul>
    <li>Keep restoration runbooks version-controlled and tested.</li>
    <li>Ensure key personnel can execute recovery without tribal knowledge.</li>
    <li>Validate external dependencies (database, vmagent, TLS assets) during drills.</li>
</ul>
