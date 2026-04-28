# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-29

### Added

- Per-request mTLS to the auth service via two new SPOE message args,
  `client_cert` and `client_key` (both PEM-encoded). When both are
  present, the plugin builds (and caches per cert+key pair) a ureq
  Agent that presents the client certificate. Drives the
  `haproxy-ingress.github.io/auth-tls-cert-secret` annotation on the
  chart side. The cache is bounded with FIFO eviction so cert
  rotation does not leak entries over time; capacity is configurable
  via the new `mtls_cache_capacity` plugin config option (default 64,
  set to 0 to disable caching). Old senders that don't include these
  args see no behaviour change.
- HTTP method dispatch covering `POST`, `PUT`, `PATCH`, `DELETE`, and
  `OPTIONS` in addition to `GET` / `HEAD`. Body-having methods
  (POST/PUT/PATCH) go out with an empty body — the plugin does not
  forward the original request payload. Auth services that need the
  body should read it via sample-fetch args. `OPTIONS` is sent as a
  GET (ureq 3.x has no typed OPTIONS builder); drop it from the
  allowlist if this becomes a real issue.
- Response-header extraction now runs on every response path, not just
  on 2xx. Auth services can return `WWW-Authenticate` on 401 or
  `X-Error-Reason` on 5xx and have those flow through to HAProxy as
  transaction variables. Drives the
  `haproxy-ingress.github.io/auth-headers-fail` annotation on the
  chart side.

## [0.2.0] - 2026-04-28

### Added

- Per-request overrides for `method`, `forward_headers`, and
  `extract_headers` via SPOE message arguments. The plugin reads the
  `method`, `forward_headers`, and `extract_headers` args from each
  message and falls back to plugin-level config when an arg is absent
  or empty. This lets the HAPTIC chart wire the
  `nginx.ingress.kubernetes.io/auth-method`,
  `nginx.ingress.kubernetes.io/auth-response-headers`,
  `haproxy-ingress.github.io/auth-headers-pass`, and equivalent
  per-ingress annotations without redeploying the sidecar. Old
  senders that don't include these args see no behaviour change.
- `RequestParams::from_config(&config)` helper that borrows all three
  fields from the plugin-level config. Used by tests and by the
  plugin's "no override" fast path.

### Changed

- Public `send_auth_request` signature now takes a `&RequestParams`
  parameter between `&PluginConfig` and `auth_url`. Anyone using this
  crate as a Rust library (rather than via the plugin ABI) needs to
  update call sites — see the new `RequestParams::from_config` helper
  for the no-override case. The SPOE protocol contract is unchanged
  for old senders.

## [0.1.1] - 2026-04-28

### Added

- Release artifacts (`.so` files for amd64, arm64, armv7) published to the
  GitLab Generic Package Registry under
  `packages/generic/external-auth/<tag>/` with stable URLs
- Per-file `<artifact>.sha256` sidecars and a combined `SHA256SUMS` for
  batch verification with `sha256sum -c SHA256SUMS`
- Cosign keyless signatures (`<artifact>.cosign.bundle`) for every release
  artifact, signed via the GitLab OIDC id token (Sigstore Fulcio + Rekor)
- `make verify-release VERSION=vX.Y.Z` target plus `scripts/verify-release.sh`
  for end-to-end consumer verification (downloads `SHA256SUMS`, checks all
  hashes, runs `cosign verify-blob` against the project's tag identity)
- Unsigned SLSA v0.2 provenance metadata emitted next to build artifacts
  via `RUNNER_GENERATE_ARTIFACTS_METADATA` (free SLSA-L1)

### Changed

- Release builds now use `cargo auditable build --release`, embedding a
  compressed `Cargo.lock`-equivalent in the `.so` so SBOM tools can
  enumerate Rust dependencies without source access

## [0.1.0] - 2026-04-09

### Added

- External auth subrequest plugin for haproxy-spoa-hub, replicating nginx `auth_request` behavior
- Dynamic `auth_url` via SPOE message argument, enabling per-request routing to different auth services from HAProxy ACLs
- Configurable header forwarding with sensible defaults (Authorization, Cookie, X-Forwarded-*)
- Configurable response header extraction from auth service (e.g., X-Auth-User, X-Auth-Roles) returned as HAProxy transaction variables
- Fail-closed (default) and fail-open policies for auth service unavailability
- TLS support via rustls (HTTPS enforced by default, plaintext requires explicit `allow_plaintext = true`)
- 3xx responses treated as denials with Location header captured for HAProxy-side redirects
- Configurable auth subrequest timeout independent of hub per-plugin timeout
- JSON schema for hub-side configuration validation
- Connection pooling via ureq Agent for efficient repeated subrequests
- 22 unit and integration tests covering all user stories
- Criterion benchmarks: to_variables ~137ns, full localhost round-trip ~244us
- Example configurations for hub, SPOE, and HAProxy frontend
- GitLab CI pipeline (fmt, clippy, test, bench, multi-arch build, release)
- Release builds use LTO and single codegen unit for optimal performance
