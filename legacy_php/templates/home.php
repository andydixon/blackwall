<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlackWall - WebAuthn OAuth 2.1 / OIDC Provider</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-10 col-lg-8 col-xl-7">
                <div class="text-center mb-5">
                    <h1 class="display-4 fw-bold mb-3">//BlackWall</h1>
                    <p class="lead text-muted">WebAuthn-Secured OAuth 2.1 / OpenID Connect Provider / Data Security</p>
                </div>

                <div class="d-grid gap-3 mb-4">
                    <div>
                        <a href="/cryptbin" class="text-decoration-none">
                            <div class="card stat-card h-100" style="border-left-color: #f59e0b">
                                <div class="card-body p-4 p-lg-5">
                                    <div class="row g-4 align-items-center">
                                        <div class="col-md-8">
                                            <div class="d-flex align-items-center gap-3 mb-3">
                                                <div class="fs-1">🗄️</div>
                                                <div>
                                                    <h4 class="mb-1">Cryptbin</h4>
                                                    <p class="text-muted mb-0">Encrypted pastebin for sensitive text and file payloads.</p>
                                                </div>
                                            </div>
                                            <div class="d-flex flex-wrap gap-2 small text-muted">
                                                <span class="badge text-bg-warning">Client-side encryption</span>
                                                <span class="badge text-bg-dark border border-secondary">Timed expiry</span>
                                                <span class="badge text-bg-dark border border-secondary">One-time sharing</span>
                                            </div>
                                        </div>
                                        <div class="col-md-4 text-md-end">
                                            <p class="small text-muted mb-3">Use it to hand off logs, tokens, or incident notes without leaving plaintext lying around.</p>
                                            <button class="btn btn-warning">Open Cryptbin →</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </a>
                    </div>

                    <div>
                        <a href="/portal" class="text-decoration-none">
                            <div class="card stat-card h-100" style="border-left-color: #3b82f6">
                                <div class="card-body p-4 p-lg-5">
                                    <div class="row g-4 align-items-center">
                                        <div class="col-md-8">
                                            <div class="d-flex align-items-center gap-3 mb-3">
                                                <div class="fs-1">👤</div>
                                                <div>
                                                    <h4 class="mb-1">Portal</h4>
                                                    <p class="text-muted mb-0">View assigned projects and manage your WebAuthn credentials.</p>
                                                </div>
                                            </div>
                                            <div class="d-flex flex-wrap gap-2 small text-muted">
                                                <span class="badge text-bg-primary">Project access</span>
                                                <span class="badge text-bg-dark border border-secondary">Security keys</span>
                                                <span class="badge text-bg-dark border border-secondary">Account self-service</span>
                                            </div>
                                        </div>
                                        <div class="col-md-4 text-md-end">
                                            <p class="small text-muted mb-3">This is the day-to-day user entry point for authentication, device enrolment, and access checks.</p>
                                            <button class="btn btn-primary">Access Portal →</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </a>
                    </div>

                    <div>
                        <a href="/admin" class="text-decoration-none">
                            <div class="card stat-card h-100" style="border-left-color: #10b981">
                                <div class="card-body p-4 p-lg-5">
                                    <div class="row g-4 align-items-center">
                                        <div class="col-md-8">
                                            <div class="d-flex align-items-center gap-3 mb-3">
                                                <div class="fs-1">⚙️</div>
                                                <div>
                                                    <h4 class="mb-1">Admin</h4>
                                                    <p class="text-muted mb-0">Operate tenants, projects, policies, OAuth clients, and audit controls.</p>
                                                </div>
                                            </div>
                                            <div class="d-flex flex-wrap gap-2 small text-muted">
                                                <span class="badge text-bg-success">User management</span>
                                                <span class="badge text-bg-dark border border-secondary">OAuth clients</span>
                                                <span class="badge text-bg-dark border border-secondary">Audit visibility</span>
                                            </div>
                                        </div>
                                        <div class="col-md-4 text-md-end">
                                            <p class="small text-muted mb-3">Intended for operators and admins who need to manage onboarding, access models, and service health.</p>
                                            <button class="btn btn-success">Admin Login →</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </a>
                    </div>

                    <div>
                        <a href="/organisations/signup" class="text-decoration-none">
                            <div class="card stat-card h-100" style="border-left-color: #22c55e">
                                <div class="card-body p-4 p-lg-5">
                                    <div class="row g-4 align-items-center">
                                        <div class="col-md-8">
                                            <div class="d-flex align-items-center gap-3 mb-3">
                                                <div class="fs-1">🏢</div>
                                                <div>
                                                    <h4 class="mb-1">Create an Organisation</h4>
                                                    <p class="text-muted mb-0">Provision a new tenant and start onboarding users and projects.</p>
                                                </div>
                                            </div>
                                            <div class="d-flex flex-wrap gap-2 small text-muted">
                                                <span class="badge text-bg-success">Tenant setup</span>
                                                <span class="badge text-bg-dark border border-secondary">Developer preview</span>
                                                <span class="badge text-bg-dark border border-secondary">Fast onboarding</span>
                                            </div>
                                        </div>
                                        <div class="col-md-4 text-md-end">
                                            <p class="small text-muted mb-3">Best for greenfield installs or test organisations that need a dedicated space quickly.</p>
                                            <button class="btn btn-success">Start Signup →</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </a>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h6 class="mb-3">🔐 Features</h6>
                        <ul class="list-unstyled mb-0">
                            <li class="mb-2">✓ Passwordless authentication with WebAuthn</li>
                            <li class="mb-2">✓ OAuth 2.1 authorization with PKCE</li>
                            <li class="mb-2">✓ OpenID Connect (OIDC) support</li>
                            <li class="mb-2">✓ Multi-project isolation</li>
                            <li class="mb-2">✓ Fine-grained privilege levels (1-10)</li>
                            <li class="mb-0">✓ Comprehensive audit logging</li>
                        </ul>
                    </div>
                </div>

                <div class="text-center mt-4">
                    <p class="small text-muted mb-2">
                        <a href="/.well-known/openid-configuration" class="text-muted text-decoration-none">
                            OpenID Discovery Document
                        </a>
                    </p>
                    <small class="text-muted">BlackWall v1.1.0 - &copy;2019-2026 <a href="https://dixon.cx/">Andy Dixon</a></small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
