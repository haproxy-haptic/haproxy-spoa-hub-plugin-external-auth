# Research: External Auth Subrequest Plugin

**Date**: 2026-04-09
**Branch**: `001-external-auth-plugin`

## HTTP Client Library

**Decision**: `ureq 3.3` with default features (includes rustls for TLS)

**Rationale**:
- Pure synchronous I/O — no async runtime, safe inside `spawn_blocking`
  without risk of nested tokio runtime conflicts
- Connection pooling via `Agent` type — `Clone + Send + Sync` via internal
  `Arc`, connections reused with HTTP keep-alive across auth subrequests
- TLS via rustls (pure Rust, no system OpenSSL dependency) — fits cdylib
  builds without requiring system libraries on the build host
- Granular timeout configuration (global, per-call, connect, resolve)

**Alternatives considered**:
- `reqwest::blocking`: Disqualified — spawns its own tokio `current_thread`
  runtime internally. Debug-mode assertion panics when called from within
  an existing tokio context (which `spawn_blocking` is). 92 dependencies.
- `minreq`: Lightest (zero transitive deps) but lacks connection pooling.
  Every request opens a new TCP connection — unacceptable for per-request
  auth subrequests at high throughput.
- `attohttpc`: Misleadingly heavy (51 deps due to ICU4X in `url` crate).
  No connection pooling despite `Session` type.

## HAProxy External Auth Landscape

**Decision**: SPOA plugin is the correct approach for external auth in
HAProxy.

**Rationale**:
- HAProxy has no native `auth_request` directive (unlike nginx).
- The Lua-based `haproxy-auth-request` by TimWolla exists but is
  synchronous, lacks TLS to auth backend, and has no connection pooling.
- SPOA is HAProxy's official extension mechanism: async, non-blocking,
  supports pipelining, with proper health checking and connection pooling.
- Existing SPOA auth solutions (e.g., criteo/haproxy-spoe-auth in Go)
  validate the pattern but are standalone agents, not hub plugins.

**Alternatives considered**:
- Lua `auth_request` script: Synchronous, blocks HAProxy worker thread,
  no TLS, no load balancing — unsuitable for production at scale.
- Standalone SPOA auth agent: Works but loses the benefits of the hub's
  plugin multiplexing, parallel execution, dependency chaining, and
  unified observability.

## Plugin Architecture

**Decision**: Follow the fingerprinting plugin structure exactly.

**Rationale**:
- Proven pattern with the hub's `define_plugin!` macro and `SpoePlugin` trait
- Same Cargo.toml settings (cdylib + rlib, LTO, single codegen unit)
- Same `abi_stable` integration for ABI-safe dynamic loading
- Consistent with operator expectations for hub plugin installation

**Key difference from fingerprinting plugin**: This plugin performs I/O
(HTTP subrequest) in `process()`, whereas fingerprinting is pure
computation. The `ureq::Agent` must be initialized in `init()` and
stored in `self` for connection reuse. Since `process(&self)` takes a
shared reference, the `Agent` is inherently safe (`Clone + Send + Sync`).

## SPOE Message Design

**Decision**: Use a single SPOE message `check-auth` with request
metadata as arguments.

**Rationale**:
- Mirrors the fingerprinting plugin's single-message approach
- HAProxy sends method, path, and headers as SPOE arguments
- Plugin reconstructs the auth subrequest from these arguments
- Header values are sent as individual string arguments keyed by
  header name

**SPOE arguments needed from HAProxy**:
- `method`: HTTP method (string)
- `path`: Request URI path + query string (string)
- `host`: Host header value (string)
- `hdr_*`: Individual header values, keyed with `hdr_` prefix
  (e.g., `hdr_authorization`, `hdr_cookie`)

## TLS

**Decision**: v1 ships with TLS support via rustls (ureq default features).

**Rationale**:
- Constitution requires TLS by default for auth service communication
- ureq's default features include rustls — pure Rust, no system OpenSSL
  dependency, suitable for cross-compilation and cdylib builds
- `auth_url` accepts both `https://` (default, recommended) and
  `http://` (requires explicit opt-in — see config `allow_plaintext`)
- Adds ~20 transitive dependencies (rustls, webpki, ring) but these are
  well-audited, widely used crates

## Connection Pooling Strategy

**Decision**: Single `ureq::Agent` per plugin instance, created in `init()`.

**Rationale**:
- `Agent` is `Clone + Send + Sync` — safe to use from `process(&self)`
- Internal connection pool handles keep-alive and reuse automatically
- No explicit pool size configuration needed — ureq manages this
- One plugin instance is shared across all connections via `Arc<PluginBox>`
  in the hub, so one `Agent` serves all concurrent auth requests
