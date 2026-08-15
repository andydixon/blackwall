# syntax=docker/dockerfile:1.7
#
# BlackWall container image — runs the blackwall binary directly as PID 1
# under an unprivileged user. Process supervision is the host's job (see the
# example docker/blackwall.supervisor.conf for a supervisord unit that runs
# `docker run` with the right environment).
#
# Stage 1 compiles a fully-static binary (CGO disabled) so the runtime layer
# can be a tiny Alpine image with no glibc dependency.

# ─── builder ─────────────────────────────────────────────────────────────────
FROM golang:1.26.6-alpine AS builder

# git is needed so `git describe` produces a real version string when the
# image is built standalone (build.sh passes VERSION explicitly via --build-arg).
RUN apk add --no-cache git

WORKDIR /build

# Cache module downloads in a separate layer: a code-only edit doesn't
# re-download dependencies on the next build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG GIT_TAG=dev
ARG GIT_COMMIT_SHORT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X blackwall/internal/buildinfo.VersionTag=${GIT_TAG} -X blackwall/internal/buildinfo.CommitShort=${GIT_COMMIT_SHORT} -X blackwall/internal/buildinfo.BuildDate=${BUILD_DATE}" \
    -o /out/blackwall \
    ./cmd/blackwall

# ─── runtime ─────────────────────────────────────────────────────────────────
FROM alpine:3.23.4

# ca-certificates: outbound TLS (event-metrics push, etc.).
# tzdata: correct local-time formatting in audit log entries.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*

# Unprivileged user — blackwall never needs root inside the container.
RUN addgroup -S blackwall \
    && adduser -S -D -h /var/lib/blackwall -G blackwall blackwall \
    && mkdir -p /var/lib/blackwall/cryptbin /etc/blackwall \
    && chown -R blackwall:blackwall /var/lib/blackwall /etc/blackwall

COPY --from=builder /out/blackwall /usr/local/bin/blackwall

USER blackwall

# Mountable surfaces:
#   /etc/blackwall/config.yaml — operator-supplied configuration (read-only)
#   /var/lib/blackwall/cryptbin — encrypted blob storage (must persist)
VOLUME ["/var/lib/blackwall/cryptbin"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/blackwall"]
CMD ["-config", "/etc/blackwall/config.yaml"]
