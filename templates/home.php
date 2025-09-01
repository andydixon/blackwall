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
            <div class="col-md-8 col-lg-6">
                <div class="text-center mb-5">
                    <h1 class="display-4 fw-bold mb-3">🔒 BlackWall</h1>
                    <p class="lead text-muted">WebAuthn-Secured OAuth 2.1 / OpenID Connect Provider</p>
                </div>

                <div class="row g-4 mb-4">
                    <div class="col-md-6">
                        <a href="/portal" class="text-decoration-none">
                            <div class="card stat-card h-100" style="border-left-color: #3b82f6">
                                <div class="card-body text-center p-4">
                                    <div class="fs-1 mb-3">👤</div>
                                    <h5 class="mb-2">User Portal</h5>
                                    <p class="text-muted small mb-3">
                                        View your projects and manage security keys
                                    </p>
                                    <button class="btn btn-primary btn-sm">Access Portal →</button>
                                </div>
                            </div>
                        </a>
                    </div>

                    <div class="col-md-6">
                        <a href="/admin" class="text-decoration-none">
                            <div class="card stat-card h-100" style="border-left-color: #10b981">
                                <div class="card-body text-center p-4">
                                    <div class="fs-1 mb-3">⚙️</div>
                                    <h5 class="mb-2">Admin Panel</h5>
                                    <p class="text-muted small mb-3">
                                        Manage users, projects, and OAuth clients
                                    </p>
                                    <button class="btn btn-success btn-sm">Admin Login →</button>
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
                    <small class="text-muted">BlackWall v1.0 • Enterprise OAuth/OIDC</small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
