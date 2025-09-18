<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title ?? 'Error') ?> - BlackWall</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
    <main class="error-page container py-5">
        <div class="error-wrap mx-auto text-center">
            <div class="error-code"><?= (int) ($statusCode ?? 500) ?></div>
            <h1 class="error-headline"><?= htmlspecialchars($headline ?? 'Application Error') ?></h1>
            <h2 class="error-detail text-muted"><?= htmlspecialchars($detail ?? 'An unexpected error occurred.') ?></h2>

            <?php if (!empty($tracePayload)): ?>
                <div class="trace-wrap text-start mt-4">
                    Debug Information:
                    <pre class="error-trace mb-0"><?= htmlspecialchars($tracePayload) ?></pre>
                </div>
            <?php endif; ?>
        </div>
    </main>
</body>
</html>
