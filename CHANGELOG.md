# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
