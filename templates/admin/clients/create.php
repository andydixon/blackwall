<div class="row mb-4">
    <div class="col">
        <h1 class="display-6 mb-3">Create OAuth Client</h1>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="/admin/projects">Projects</a></li>
                <li class="breadcrumb-item"><a href="/admin/projects/<?= $project->id ?>"><?= htmlspecialchars($project->name) ?></a></li>
                <li class="breadcrumb-item"><a href="/admin/projects/<?= $project->id ?>/clients">OAuth Clients</a></li>
                <li class="breadcrumb-item active">Create</li>
            </ol>
        </nav>
    </div>
</div>

<div class="row">
    <div class="col-lg-8">
        <div class="card bg-dark border-secondary">
            <div class="card-body">
                <form method="POST" action="/admin/projects/<?= $project->id ?>/clients/create">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    
                    <div class="mb-4">
                        <label for="name" class="form-label fw-bold">Client Name</label>
                        <input type="text" class="form-control bg-dark border-secondary text-light" id="name" name="name" required 
                               placeholder="e.g., My Application">
                        <div class="form-text">A descriptive name for this OAuth client</div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="redirect_uris" class="form-label fw-bold">Redirect URIs</label>
                        <textarea class="form-control bg-dark border-secondary text-light font-monospace" id="redirect_uris" 
                                  name="redirect_uris" rows="5" required 
                                  placeholder="https://example.com/callback&#10;https://example.com/oauth/callback"></textarea>
                        <div class="form-text">Enter one redirect URI per line. These must match exactly during OAuth flow.</div>
                    </div>
                    
                    <div class="mb-4">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="is_confidential" value="1" id="is_confidential">
                            <label class="form-check-label" for="is_confidential">
                                <strong>Confidential Client</strong>
                            </label>
                        </div>
                        <div class="form-text ms-4">
                            Check this if your application runs on a server and can securely store a client secret. 
                            Leave unchecked for public clients (mobile/SPA apps using PKCE).
                        </div>
                    </div>
                    
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-primary">Create Client</button>
                        <a href="/admin/projects/<?= $project->id ?>/clients" class="btn btn-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-lg-4">
        <div class="card bg-dark border-info">
            <div class="card-header bg-info text-dark fw-bold">OAuth Client Types</div>
            <div class="card-body">
                <h6 class="fw-bold">Confidential Clients</h6>
                <p class="small">Server-side applications that can securely store secrets. Requires client_secret for token exchange.</p>
                
                <h6 class="fw-bold mt-3">Public Clients</h6>
                <p class="small mb-0">Mobile apps, SPAs, or any client that cannot securely store secrets. Uses PKCE for security.</p>
            </div>
        </div>
    </div>
</div>
