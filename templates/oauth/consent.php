<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-6">
                <div class="card shadow-lg bg-dark">
                    <div class="card-body p-4">
                        <div class="text-center mb-4">
                            <h1 class="h4 mb-2">Authorisation Request</h1>
                            <p class="text-muted">//BlackWall</p>
                        </div>

                        <div class="alert alert-info">
                            <strong><?= htmlspecialchars($client->name) ?></strong> is requesting access to:
                        </div>

                        <div class="card bg-secondary mb-3">
                            <div class="card-body">
                                <h6>Project</h6>
                                <p class="mb-1"><strong><?= htmlspecialchars($project->name) ?></strong></p>
                                <small class="text-muted">UUID: <code><?= htmlspecialchars($project->uuid) ?></code></small>
                            </div>
                        </div>

                        <div class="card bg-secondary mb-3">
                            <div class="card-body">
                                <h6>Your Access Level</h6>
                                <p class="mb-0">
                                    <span class="badge bg-primary"><?= htmlspecialchars($privilegeLabel) ?></span>
                                    <small class="text-muted d-block mt-1">Level <?= (int) $privilegeLevelNumber ?></small>
                                </p>
                            </div>
                        </div>

                        <?php if (!empty($scopes)): ?>
                        <div class="card bg-secondary mb-4">
                            <div class="card-body">
                                <h6>Requested Scopes</h6>
                                <ul class="list-unstyled mb-0">
                                    <?php foreach ($scopes as $scope): ?>
                                        <li>✓ <?= htmlspecialchars($scope) ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                        <?php endif; ?>

                        <form method="POST" action="/oauth/authorize">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            
                            <div class="d-grid gap-2">
                                <button type="submit" name="approve" class="btn btn-primary btn-lg">
                                    ✓ Authorize Access
                                </button>
                                <button type="submit" name="deny" class="btn btn-outline-danger">
                                    ✗ Deny Access
                                </button>
                            </div>
                        </form>

                        <div class="mt-3 text-center">
                            <small class="text-muted">
                                This will allow the application to act on your behalf with the privilege level shown above.
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
