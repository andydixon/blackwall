<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create an Organisation - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-lg-6">
                <div class="card bg-dark">
                    <div class="card-header">
                        <h4 class="mb-0">Create an Organisation</h4>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">Currently free during development.</p>

                        <?php if (!empty($success)): ?>
                            <div class="alert alert-success">
                                <div>Organisation <strong><?= htmlspecialchars((string) ($organizationName ?? '')) ?></strong> created.</div>
                                <div class="mt-2">Admin enrollment URL:</div>
                                <code><?= htmlspecialchars((string) ($enrollmentLink ?? '')) ?></code>
                            </div>
                        <?php endif; ?>

                        <form method="POST" action="/organisations/signup">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                            <div class="mb-3">
                                <label class="form-label">Organisation Name</label>
                                <input type="text" name="name" class="form-control" minlength="3" maxlength="120" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Organisation Slug</label>
                                <input type="text" name="slug" class="form-control" pattern="[a-z0-9-]{3,40}" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Admin Display Label</label>
                                <input type="text" name="admin_display_label" class="form-control" required>
                            </div>
                            <div class="d-flex gap-2">
                                <button type="submit" class="btn btn-success">Create Organisation</button>
                                <a href="/" class="btn btn-outline-light">Back</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>

