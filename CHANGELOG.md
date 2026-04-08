# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
