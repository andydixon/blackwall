#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HTML_DIR="${TMPDIR:-/tmp}/blackwall-user-guide-html"
ASSET_DIR="${TMPDIR:-/tmp}/blackwall-user-guide-assets"
OUTPUT_DIR="${ROOT_DIR}/docs/user-guide/screenshots"
CHROME_BIN="${CHROME_BIN:-/home/andy/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell}"

mkdir -p "${HTML_DIR}" "${ASSET_DIR}" "${OUTPUT_DIR}"
curl --fail --silent --show-error --location \
    https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css \
    --output "${ASSET_DIR}/bootstrap.min.css"
curl --fail --silent --show-error --location \
    https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js \
    --output "${ASSET_DIR}/bootstrap.bundle.min.js"
go run "${ROOT_DIR}/tools/user-guide/render_screenshots.go" "${HTML_DIR}"

capture() {
    local output="$1"
    local target="$2"
    local profile_dir
    local status
    profile_dir="$(mktemp -d)"

    set +e
    timeout --signal=TERM --kill-after=3s 15s \
        "${CHROME_BIN}" --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
        --hide-scrollbars --allow-file-access-from-files --disable-extensions --no-first-run \
        --user-data-dir="${profile_dir}" --force-device-scale-factor=1 \
        --window-size=1600,1000 --screenshot="${output}" "${target}" >/dev/null 2>&1
    status=$?
    set -e

    rm -rf -- "${profile_dir}"
    if [[ ! -s "${output}" ]]; then
        echo "Unable to capture ${target} (Chrome status ${status})" >&2
        return 1
    fi
}

capture_file() {
    local name="$1"
    capture "${OUTPUT_DIR}/${name}.png" "file://${HTML_DIR}/${name}.html"
}

capture_url() {
    local name="$1"
    local url="$2"
    capture "${OUTPUT_DIR}/${name}.png" "${url}"
}

for page in dashboard organisations projects users oauth-clients licences audit-log documentation portal oauth-consent cryptbin-create; do
    capture_file "${page}"
done

capture_url home https://blackwall.cx/
capture_url admin-login https://blackwall.cx/admin/login
capture_url portal-login https://blackwall.cx/portal/login
capture_url organisation-signup https://blackwall.cx/organisations/signup

echo "Screenshots written to ${OUTPUT_DIR}"
