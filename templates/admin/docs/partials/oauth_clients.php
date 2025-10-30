<h4>Client Administration Surface</h4>
<p>
    OAuth clients are managed per project at
    <code>/admin/projects/{projectUuid}/clients</code>.
    Client detail pages are available at <code>/admin/clients/{clientPublicId}</code>.
</p>

<h4>Core Client Settings</h4>
<ul>
    <li>Client name and status.</li>
    <li>Redirect URI list.</li>
    <li>Scopes and token profiles.</li>
    <li>Access token type and lifetimes.</li>
    <li>Refresh token lifetime.</li>
    <li>OIDC enablement state.</li>
</ul>

<h4>Security Expectations</h4>
<ul>
    <li>Redirect URIs should be exact and minimal.</li>
    <li>Scope sets should follow least-privilege principle.</li>
    <li>Token lifetimes should be conservative for higher-risk clients.</li>
    <li>Status changes and sensitive updates may be approval-gated.</li>
</ul>

<h4>Flow Guidance</h4>
<p>
    BlackWall supports OAuth 2.1 and OIDC flows with modern security expectations.
    For integration-level details, use the engineering documentation in <code>docs/</code>.
</p>

<h4>Operational Review Checklist</h4>
<ol>
    <li>Review inactive or stale clients quarterly.</li>
    <li>Confirm redirect URIs remain valid and owned.</li>
    <li>Verify scope changes are justified and auditable.</li>
    <li>Track client status mutations in approvals and audit logs.</li>
</ol>
