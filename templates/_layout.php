<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title ?? 'BlackWall Authentication Service') ?> - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark border-bottom border-secondary">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold" href="/admin">//BlackWall</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
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
                        <a class="nav-link" href="/admin/audit">Audit Log</a>
                    </li>
                    <?php if (($currentAdminRole ?? '') === 'super_admin'): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/roles">Roles</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/organisations">Organisations</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/cryptbin">Cryptbin</a>
                        </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/approvals">Approvals</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/docs">Docs</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/scope">Scope</a>
                    </li>
                    <?php if (($currentAdminRole ?? '') === 'super_admin'): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/maintenance">Maintenance</a>
                        </li>
                    <?php endif; ?>
                    <?php if (in_array($currentAdminRole ?? '', ['super_admin', 'auditor'], true)): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/error-trace">Error Trace</a>
                        </li>
                    <?php endif; ?>
                </ul>
                <?php if (!empty($currentAdminRole)): ?>
                    <span class="badge bg-secondary me-3"><?= htmlspecialchars((string) $currentAdminRole) ?></span>
                <?php endif; ?>
                <?php if (!empty($impersonatorUserId)): ?>
                    <form method="POST" action="/admin/switch/restore" class="d-flex me-2">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(\BlackWall\Security\CSRFProtection::getToken()) ?>">
                        <button class="btn btn-warning btn-sm" type="submit">Stop Switch</button>
                    </form>
                <?php endif; ?>
                <form method="POST" action="/admin/logout" class="d-flex">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(\BlackWall\Security\CSRFProtection::getToken()) ?>">
                    <button class="btn btn-outline-light btn-sm" type="submit">Logout</button>
                </form>
            </div>
        </div>
    </nav>

    <main class="container-fluid py-4">
        <?= $content ?>
    </main>
    <footer class="container-fluid pb-4">
        <div class="text-center text-muted small">Powered by BlackWall</div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/js/blackwall.js"></script>
</body>
</html>
