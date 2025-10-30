<?php
$currentPageTitle = (string) ($currentPage['title'] ?? 'Documentation');
$currentPageSummary = (string) ($currentPage['summary'] ?? '');
$currentTemplate = basename((string) ($currentPage['template'] ?? ''));
$partialPath = __DIR__ . '/partials/' . $currentTemplate;
?>

<div class="row g-4">
    <div class="col-lg-3">
        <div class="card sticky-top" style="top: 1rem;">
            <div class="card-header">
                <h5 class="mb-0">User Guide</h5>
            </div>
            <div class="list-group list-group-flush">
                <?php foreach (($docsPages ?? []) as $slug => $page): ?>
                    <?php $active = ($slug === ($currentSlug ?? '')); ?>
                    <a
                        href="/admin/docs/<?= rawurlencode((string) $slug) ?>"
                        class="list-group-item list-group-item-action <?= $active ? 'active' : '' ?>"
                    >
                        <div class="fw-semibold"><?= htmlspecialchars((string) ($page['title'] ?? $slug)) ?></div>
                        <div class="small <?= $active ? '' : 'text-muted' ?>">
                            <?= htmlspecialchars((string) ($page['summary'] ?? '')) ?>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-9">
        <div class="card mb-3">
            <div class="card-body">
                <h2 class="mb-2"><?= htmlspecialchars($currentPageTitle) ?></h2>
                <?php if ($currentPageSummary !== ''): ?>
                    <p class="text-muted mb-0"><?= htmlspecialchars($currentPageSummary) ?></p>
                <?php endif; ?>
            </div>
        </div>

        <div class="card mb-3">
            <div class="card-body">
                <?php if (is_file($partialPath)): ?>
                    <?php include $partialPath; ?>
                <?php else: ?>
                    <div class="alert alert-warning mb-0">
                        Documentation page content is unavailable for this section.
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="d-flex justify-content-between">
            <div>
                <?php if (!empty($previousSlug) && isset($docsPages[$previousSlug])): ?>
                    <a class="btn btn-outline-light" href="/admin/docs/<?= rawurlencode((string) $previousSlug) ?>">
                        ← <?= htmlspecialchars((string) $docsPages[$previousSlug]['title']) ?>
                    </a>
                <?php endif; ?>
            </div>
            <div>
                <?php if (!empty($nextSlug) && isset($docsPages[$nextSlug])): ?>
                    <a class="btn btn-outline-light" href="/admin/docs/<?= rawurlencode((string) $nextSlug) ?>">
                        <?= htmlspecialchars((string) $docsPages[$nextSlug]['title']) ?> →
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
