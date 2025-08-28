<div class="row">
    <div class="col-md-6 mx-auto">
        <div class="card bg-dark">
            <div class="card-header">
                <h5>Create User</h5>
            </div>
            <div class="card-body">
                <form method="POST" action="/admin/users/create">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    
                    <div class="mb-3">
                        <label class="form-label">Display Label (e.g., email)</label>
                        <input type="text" name="display_label" class="form-control" placeholder="user@example.com">
                        <small class="form-text text-muted">Optional. NOT used for authentication.</small>
                    </div>

                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-primary">Create User</button>
                        <a href="/admin/users" class="btn btn-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
