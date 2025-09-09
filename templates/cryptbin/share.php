<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cryptbin - Share</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/blackwall.css">
</head>
<body class="bg-charcoal">
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-lg-10">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h1 class="h2 mb-1">Cryptbin Share Link</h1>
                    <p class="text-muted mb-0">ID: <code><?= htmlspecialchars($id) ?></code></p>
                </div>
                <a href="/cryptbin" class="btn btn-outline-light">New Item</a>
            </div>

            <div class="alert alert-danger mb-4" role="alert">
                <strong>Important:</strong> If this full URL is lost, the content is unrecoverable.
                The key in the <code>#fragment</code> is required for update/delete access and practical recovery.
            </div>

            <div class="card mb-4">
                <div class="card-body">
                    <label for="share-url" class="form-label">Copy and store this URL safely</label>
                    <textarea id="share-url" class="form-control" rows="4" readonly></textarea>
                    <div class="d-flex gap-2 mt-3">
                        <button id="copy-url-btn" class="btn btn-primary">Copy URL</button>
                        <a id="open-item-btn" class="btn btn-success" href="#">Open & Decrypt</a>
                    </div>
                    <p id="copy-status" class="text-muted small mt-2 mb-0"></p>
                </div>
            </div>

            <div class="card">
                <div class="card-body">
                    <h5 class="mb-3">How Cryptbin Protects Content</h5>
                    <ul class="mb-0">
                        <li>Encryption/decryption happens in your browser (client-side).</li>
                        <li>The server stores ciphertext and wrapped keys, not plaintext.</li>
                        <li>The fragment key after <code>#</code> is not sent with HTTP requests.</li>
                        <li>Without the key, content cannot be decrypted by the server.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
window.CRYPTBIN_CONFIG = {
    mode: 'share',
    id: <?= json_encode($id) ?>
};
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="/assets/js/cryptbin.js"></script>
</body>
</html>
