<div class="row mb-4">
    <div class="col">
        <h1 class="display-6 mb-3">OAuth Client Details</h1>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="/admin/projects">Projects</a></li>
                <li class="breadcrumb-item"><a href="/admin/projects/<?= $project->id ?>"><?= htmlspecialchars($project->name) ?></a></li>
                <li class="breadcrumb-item"><a href="/admin/projects/<?= $project->id ?>/clients">OAuth Clients</a></li>
                <li class="breadcrumb-item active"><?= htmlspecialchars($client['name']) ?></li>
            </ol>
        </nav>
    </div>
</div>

<?php if ($secret): ?>
    <div class="alert alert-warning border-warning" role="alert">
        <h4 class="alert-heading">⚠️ Save Your Client Secret!</h4>
        <p class="mb-0">This secret will <strong>only be shown once</strong>. Copy it now:</p>
        <div class="input-group mt-3">
            <input type="text" class="form-control bg-dark border-warning text-warning font-monospace" 
                   value="<?= htmlspecialchars($secret) ?>" readonly id="clientSecret">
            <button class="btn btn-outline-warning" type="button" onclick="copySecret()">Copy</button>
        </div>
    </div>
    <script>
    function copySecret() {
        const el = document.getElementById('clientSecret');
        el.select();
        document.execCommand('copy');
        alert('Client secret copied!');
    }
    </script>
<?php endif; ?>

<div class="row">
    <div class="col-lg-8">
        <div class="card bg-dark border-secondary mb-4">
            <div class="card-header fw-bold">Client Information</div>
            <div class="card-body">
                <table class="table table-dark mb-0">
                    <tr>
                        <th style="width: 200px;">Client ID</th>
                        <td><code class="text-info"><?= htmlspecialchars($client['client_id']) ?></code></td>
                    </tr>
                    <tr>
                        <th>Name</th>
                        <td><?= htmlspecialchars($client['name']) ?></td>
                    </tr>
                    <tr>
                        <th>Type</th>
                        <td>
                            <?php if ($client['client_secret_hash']): ?>
                                <span class="badge bg-warning text-dark">Confidential</span>
                            <?php else: ?>
                                <span class="badge bg-success">Public (PKCE)</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th>Status</th>
                        <td>
                            <span class="badge <?= $client['status'] === 'active' ? 'bg-success' : 'bg-secondary' ?>">
                                <?= htmlspecialchars($client['status']) ?>
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>Created</th>
                        <td><?= htmlspecialchars($client['created_at']) ?></td>
                    </tr>
                </table>
            </div>
        </div>
        
        <div class="card bg-dark border-secondary">
            <div class="card-header fw-bold">Redirect URIs</div>
            <div class="card-body">
                <pre class="bg-dark text-light border border-secondary p-3 mb-0"><?= htmlspecialchars($client['redirect_uris']) ?></pre>
            </div>
        </div>
    </div>
    
    <div class="col-lg-4">
        <div class="card bg-dark border-primary">
            <div class="card-header bg-primary text-white fw-bold">Usage Example</div>
            <div class="card-body">
                <p class="small mb-2">Authorization URL:</p>
                <pre class="bg-black text-light p-2 small mb-0" style="overflow-x: auto; font-size: 10px;">https://blackwall.dixon.cx/oauth/authorize?response_type=code&client_id=<?= htmlspecialchars($client['client_id']) ?>&redirect_uri=YOUR_REDIRECT_URI&scope=openid+profile+email&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256&state=YOUR_STATE</pre>
            </div>
        </div>
    </div>
</div>
