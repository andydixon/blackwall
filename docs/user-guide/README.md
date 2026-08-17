# BlackWall User Guide

The publication files in this directory are the maintained, feature-complete user guide for BlackWall:

- `BlackWall-User-Guide.pdf` is the distributable edition.
- `BlackWall-User-Guide.sla` is the editable Scribus source.
- `screenshots/` contains publication images captured at 1600 × 1000 pixels.

The guide is written for end users, organisation administrators, BlackWall administrators, developers and operators. Its canonical prose comes from [`../MANUAL.md`](../MANUAL.md), so the repository manual and printed guide do not drift apart.

## Rebuilding the publication

Use Scribus 1.6 or later, Go, `curl`, the Playwright Chromium headless shell and a virtual X server. From the repository root:

```bash
./tools/user-guide/capture_screenshots.sh
xvfb-run -a scribus -g -py tools/user-guide/build_guide.py
```

The screenshot tool renders BlackWall's real templates with clearly fictional, synthetic organisation, project, user and licence data. It captures the public landing and portal sign-in pages from `https://blackwall.cx`. It does not bypass authentication, read the production database or place live credentials, licence tokens or personal data in the guide.

The admin sign-in page is rendered locally rather than captured live, because its build-provenance panel must report the release the guide documents. That release string lives in the `exampleVersion`, `exampleCommit`, `exampleBuildDate` and `exampleBuildTime` constants in [`../../tools/user-guide/render_screenshots.go`](../../tools/user-guide/render_screenshots.go) — update them together with the release tag before recapturing.

The layout script creates A4 facing pages, reserves cover, dedication and contents pages, and forces every chapter to begin on an odd-numbered right-hand page. It then exports both the editable `.sla` document and its PDF edition.

## Editorial conventions

- Prose uses British English.
- Protocol field names, endpoint paths, source-code identifiers and standards terminology remain exact even when their spelling differs from British prose.
- Security instructions are fail closed: an unavailable verifier, bad signature, untrusted key, hostname mismatch or invalid time window must deny licensed functionality.
- Screenshots containing administrative information use synthetic examples. Public-page captures may be refreshed before a release when the live presentation changes.
