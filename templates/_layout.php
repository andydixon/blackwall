<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title ?? 'BlackWall OAuth') ?> - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark border-bottom border-secondary">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold" href="/admin">🔒 BlackWall</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/dashboard">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/users">Users</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/projects">Projects</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin/audit">Audit Log</a>
                    </li>
                </ul>
                <form method="POST" action="/admin/logout" class="d-flex">
                    <button class="btn btn-outline-light btn-sm" type="submit">Logout</button>
                </form>
            </div>
        </div>
    </nav>

    <main class="container-fluid py-4">
        <?= $content ?>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/js/blackwall.js"></script>
</body>
</html>
