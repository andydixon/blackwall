#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025-2026 Andy Dixon

#
# BlackWall build pipeline.
#
# Default behaviour: compile the binary into ./dist/blackwall AND build a
# Docker image tagged blackwall:<version> + blackwall:latest.
#
# Flags:
#   --binary-only   compile but skip Docker
#   --image-only    build the Docker image but skip the local binary
#   --image NAME    override image repo (default: blackwall)
#   --no-latest     don't also tag :latest (CI / release builds)
#   --push          docker push after tagging (requires credentials)
#   -h, --help
#
# Env vars:
#   VERSION   override the auto-detected version (defaults to `git describe`)
#   GOOS      target OS for the local binary (default: linux)
#   GOARCH    target arch for the local binary (default: amd64)
#   VULNERABILITY_SCAN_DATE       RFC 3339 completion time of the last successful scan
#   VULNERABILITY_SCAN_REFERENCE  opaque CI or report reference for that scan

set -euo pipefail

BINARY="blackwall"
BUILD_DIR="dist"
IMAGE_REPO="blackwall"
DO_BINARY=1
DO_IMAGE=1
TAG_LATEST=1
DO_PUSH=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary-only) DO_IMAGE=0; shift ;;
        --image-only)  DO_BINARY=0; shift ;;
        --image)       IMAGE_REPO="$2"; shift 2 ;;
        --no-latest)   TAG_LATEST=0; shift ;;
        --push)        DO_PUSH=1; shift ;;
        -h|--help)
            sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

GIT_TAG="${GIT_TAG:-$(git describe --tags --abbrev=0 2>/dev/null || echo 'dev')}"
GIT_COMMIT_SHORT="${GIT_COMMIT_SHORT:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
VULNERABILITY_SCAN_DATE="${VULNERABILITY_SCAN_DATE:-unknown}"
VULNERABILITY_SCAN_REFERENCE="${VULNERABILITY_SCAN_REFERENCE:-unknown}"
VERSION="${VERSION:-${GIT_TAG}-${GIT_COMMIT_SHORT}}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"

# Sanity: a tree without git history would otherwise produce VERSION=dev,
# which we want to allow but flag visibly.
if [[ "${VERSION}" == "dev" ]]; then
    echo ">>> WARNING: VERSION=dev (no git tags / commits found)" >&2
fi

echo ">>> BlackWall build"
echo "    version: ${VERSION}"
echo "    tag:     ${GIT_TAG}"
echo "    commit:  ${GIT_COMMIT_SHORT}"
echo "    built:   ${BUILD_DATE}"
echo "    scan:    ${VULNERABILITY_SCAN_DATE} (${VULNERABILITY_SCAN_REFERENCE})"
echo "    binary:  $([[ ${DO_BINARY} -eq 1 ]] && echo yes || echo no)"
echo "    image:   $([[ ${DO_IMAGE}  -eq 1 ]] && echo yes || echo no) (${IMAGE_REPO})"
echo "    push:    $([[ ${DO_PUSH}   -eq 1 ]] && echo yes || echo no)"
echo

# ─── compile binary ──────────────────────────────────────────────────────────
if [[ ${DO_BINARY} -eq 1 ]]; then
    echo ">>> Compiling ${BINARY} for ${GOOS}/${GOARCH}..."
    mkdir -p "${BUILD_DIR}"

    # CGO disabled so the resulting binary is fully static and runs in any
    # libc-free container. -trimpath strips local source paths from the
    # binary so leaked stack traces don't reveal /home/<user>/...
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
        -trimpath \
        -ldflags="-s -w -X blackwall/internal/buildinfo.VersionTag=${GIT_TAG} -X blackwall/internal/buildinfo.CommitShort=${GIT_COMMIT_SHORT} -X blackwall/internal/buildinfo.BuildDate=${BUILD_DATE} -X blackwall/internal/buildinfo.VulnerabilityScanDate=${VULNERABILITY_SCAN_DATE} -X blackwall/internal/buildinfo.VulnerabilityScanReference=${VULNERABILITY_SCAN_REFERENCE}" \
        -o "${BUILD_DIR}/${BINARY}" \
        ./cmd/blackwall

    echo "    ✓ $(ls -lh "${BUILD_DIR}/${BINARY}" | awk '{print $5, $9}')"
fi

# ─── build container ─────────────────────────────────────────────────────────
if [[ ${DO_IMAGE} -eq 1 ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo ">>> ERROR: docker CLI not found in PATH" >&2
        exit 1
    fi

    echo
    echo ">>> Building Docker image ${IMAGE_REPO}:${VERSION}..."
    docker build \
        --build-arg "VERSION=${VERSION}" \
        --build-arg "GIT_TAG=${GIT_TAG}" \
        --build-arg "GIT_COMMIT_SHORT=${GIT_COMMIT_SHORT}" \
        --build-arg "BUILD_DATE=${BUILD_DATE}" \
        --build-arg "VULNERABILITY_SCAN_DATE=${VULNERABILITY_SCAN_DATE}" \
        --build-arg "VULNERABILITY_SCAN_REFERENCE=${VULNERABILITY_SCAN_REFERENCE}" \
        --tag "${IMAGE_REPO}:${VERSION}" \
        --file Dockerfile \
        .

    if [[ ${TAG_LATEST} -eq 1 ]]; then
        echo "    ✓ also tagging :latest"
        docker tag "${IMAGE_REPO}:${VERSION}" "${IMAGE_REPO}:latest"
    fi

    echo
    echo ">>> Image:"
    docker images --filter "reference=${IMAGE_REPO}" \
        --format "table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"

    if [[ ${DO_PUSH} -eq 1 ]]; then
        echo
        echo ">>> Pushing ${IMAGE_REPO}:${VERSION}..."
        docker push "${IMAGE_REPO}:${VERSION}"
        if [[ ${TAG_LATEST} -eq 1 ]]; then
            docker push "${IMAGE_REPO}:latest"
        fi
    fi
fi

echo
echo ">>> Done."
