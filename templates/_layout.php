<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title ?? 'BlackWall Authentication Service') ?> — BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">

    <?php if (!empty($impersonatorUserId)): ?>
    <div class="impersonation-bar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        Switched identity active — actions are attributed to the target user
        <form method="POST" action="/admin/switch/restore" class="ms-auto">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(\BlackWall\Security\CSRFProtection::getToken()) ?>">
            <button class="btn btn-warning btn-sm py-0 px-2" type="submit" style="font-size:0.75rem;">Stop Switch</button>
        </form>
    </div>
    <?php endif; ?>

    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid px-4">

            <a class="navbar-brand" href="/admin">
                <img src="/assets/blackwall.svg" alt="BlackWall">
                <span>BlackWall</span>
            </a>

            <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" style="padding: 0.3rem;">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/dashboard">Dashboard</a>
                    </li>
                    <?php if (in_array($currentAdminRole ?? '', ['super_admin', 'operator'], true)): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/users">Users</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/projects">Projects</a>
                        </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/audit">Audit</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/approvals">Approvals</a>
                    </li>
                    <?php if (($currentAdminRole ?? '') === 'super_admin'): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/roles">Roles</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/organisations">Orgs</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/cryptbin">Cryptbin</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/maintenance">Maintenance</a>
                        </li>
                    <?php endif; ?>
                    <?php if (in_array($currentAdminRole ?? '', ['super_admin', 'auditor'], true)): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/error-trace">Errors</a>
                        </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/scope">Scope</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/docs">Docs</a>
                    </li>
                </ul>

                <div class="d-flex align-items-center gap-2">
                    <?php if (!empty($currentAdminRole)): ?>
                        <span class="badge bg-secondary"><?= htmlspecialchars((string) $currentAdminRole) ?></span>
                    <?php endif; ?>
                    <form method="POST" action="/admin/logout" class="d-flex mb-0">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(\BlackWall\Security\CSRFProtection::getToken()) ?>">
                        <button class="btn btn-outline-light btn-sm" type="submit">Sign out</button>
                    </form>
                </div>
            </div>
        </div>
    </nav>

    <main class="container-fluid px-4">
        <?= $content ?>
    </main>

    <footer class="container-fluid px-4 pb-4">
        <div class="text-center text-muted small">
            <span class="status-dot online"></span>BlackWall Authentication Service
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/js/blackwall.js"></script>
    <script>
        // Mark active nav link based on current path
        (function () {
            const path = window.location.pathname;
            document.querySelectorAll('.navbar-nav .nav-link').forEach(function (link) {
                const href = link.getAttribute('href');
                if (!href) return;
                // Exact match or path starts-with for sub-pages
                if (path === href || (href !== '/admin' && path.startsWith(href))) {
                    link.classList.add('active');
                }
            });
        })();
    </script>
</body>
</html>
