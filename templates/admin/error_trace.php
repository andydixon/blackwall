<div class="row">
    <div class="col-12">
        <div class="page-header">
            <h2>🔎 Decode Error Trace</h2>
            <p class="text-muted mb-0">Paste encrypted+base64 payload from the error page to decode it server-side.</p>
        </div>

        <div class="card mb-4">
            <div class="card-body">
                <form method="POST" action="/admin/error-trace">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <div class="mb-3">
                        <label class="form-label">Encoded Payload</label>
                        <textarea name="payload" class="form-control font-monospace" rows="8" required><?= htmlspecialchars($inputPayload ?? '') ?></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Decode</button>
                </form>
            </div>
        </div>

        <?php if (!empty($decodeError)): ?>
            <div class="alert alert-danger">
                <strong>Decode failed:</strong> <?= htmlspecialchars($decodeError) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($decodedTrace)): ?>
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Decoded Trace</h5>
                </div>
                <div class="card-body">
                    <pre class="mb-0"><?= htmlspecialchars($decodedTrace) ?></pre>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>
