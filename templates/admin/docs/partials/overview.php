<h4>Purpose</h4>
<p>
    This in-application documentation centre is the canonical operational guide for BlackWall administrators.
    It is written in UK English and designed for day-to-day usage, incident handling, and controlled change management.
</p>

<h4>What BlackWall Provides</h4>
<ul>
    <li>OAuth 2.1 and OpenID Connect authorisation services with WebAuthn-centric authentication.</li>
    <li>Scoped administration based on project-level Level 1 membership.</li>
    <li>Approval workflows for sensitive administrative actions.</li>
    <li>Tamper-evident audit logging with filtering and export capabilities.</li>
    <li>Operational telemetry, including optional event push to vmagent.</li>
</ul>

<h4>How To Use This Guide</h4>
<ol>
    <li>Start with <strong>Administrator Quick Start</strong> for immediate platform checks.</li>
    <li>Read <strong>Access Model and Scope</strong> before changing roles or assignments.</li>
    <li>Use <strong>Approvals Workflow</strong> and <strong>Audit and Security Operations</strong> for governance tasks.</li>
    <li>Use <strong>Troubleshooting and Diagnostics</strong> during incidents.</li>
    <li>Use <strong>Reference and Glossary</strong> for route and config lookup.</li>
</ol>

<h4>Principles</h4>
<ul>
    <li><strong>Least privilege</strong>: project admins should only have the minimum required scope.</li>
    <li><strong>Traceability</strong>: every sensitive action should be auditable and attributable.</li>
    <li><strong>Operational safety</strong>: approvals, rate limits, and scope restrictions are safeguards, not inconveniences.</li>
    <li><strong>Repeatability</strong>: maintenance, backup, and recovery tasks should be rehearsed and scripted.</li>
</ul>

<h4>Audience</h4>
<ul>
    <li><strong>Super admins</strong>: global oversight, role management, maintenance, incident control.</li>
    <li><strong>Project admins</strong>: scoped management of users, projects, clients, and approvals.</li>
    <li><strong>Auditors</strong>: read-oriented operations, diagnostics, and evidence gathering.</li>
</ul>

<h4>Document Scope</h4>
<p>
    This guide focuses on the operational and administrative surfaces under <code>/admin</code>.
    Integration-level OAuth implementation details remain available in repository documentation for engineering teams.
</p>
