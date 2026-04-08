# Implementation Plan: External Auth Subrequest Plugin

**Branch**: `001-external-auth-plugin` | **Date**: 2026-04-09 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-external-auth-plugin/spec.md`

## Summary

Implement a haproxy-spoa-hub plugin that replicates nginx's `auth_request`
behavior: for each incoming request, make an HTTP subrequest to an
external auth service and return the auth decision (allow/deny) plus
extracted response headers as HAProxy transaction variables. Uses `ureq`
for synchronous HTTP with connection pooling, matching the fingerprinting
plugin's project structure and build settings.

## Technical Context

**Language/Version**: Rust 1.86, edition 2024
**Primary Dependencies**: haproxy-spoa-hub-plugin-api 0.1, abi_stable 0.11, ureq 3.3 (default features, rustls TLS), log 0.4
**Storage**: N/A
**Testing**: cargo test, criterion benchmarks
**Target Platform**: Linux (x86_64, aarch64, armv7) — glibc 2.36+
**Project Type**: Dynamic library (cdylib + rlib) — SPOA hub plugin
**Performance Goals**: <1ms p99 plugin processing overhead (excluding auth service latency)
**Constraints**: <10ms p99 end-to-end auth decision (constitution), bounded memory
**Scale/Scope**: Single plugin, ~500-800 LOC

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Single-responsibility modules (config, auth, plugin). Idiomatic Rust. Clippy + rustfmt enforced. Dependencies pinned and justified. |
| II. Testing Standards | PASS | Unit tests for config parsing, auth decision logic, header extraction. Integration tests with mock HTTP server. Criterion benchmarks for process() hot path. |
| III. User Experience Consistency | PASS | Config follows HAProxy naming patterns. Structured logging via `log` crate. Error messages include component + remediation. Secure defaults (fail-closed). |
| IV. Performance Requirements | PASS | ureq Agent with connection pooling. No unbounded state. Benchmarks track regression. Concurrent-safe via &self + Agent's internal Arc. |
| Security & Reliability | PASS | TLS via rustls by default. Plaintext requires explicit `allow_plaintext = true`. Fail-closed default. No secrets in logs. Input validated. |

## Project Structure

### Documentation (this feature)

```text
specs/001-external-auth-plugin/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── plugin-interface.md
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```text
src/
├── lib.rs               # Module declarations, define_plugin! invocation
├── plugin.rs            # SpoePlugin trait implementation (process, init)
├── config.rs            # PluginConfig parsing + JSON schema + validation
└── auth.rs              # AuthDecision, HTTP subrequest logic, header extraction

tests/
├── plugin_test.rs       # Plugin init, config schema, end-to-end process()
├── config_test.rs       # Config parsing, defaults, validation edge cases
└── auth_test.rs         # Auth decision logic, header forwarding, error handling

benches/
└── auth_bench.rs        # Criterion: process() with mock HTTP server

examples/
├── hub.toml             # Hub configuration example
├── spoe-external-auth.conf  # HAProxy SPOE configuration
└── haproxy.cfg          # HAProxy frontend/backend example
```

**Structure Decision**: Single-crate Rust project matching the
fingerprinting plugin layout. Four source modules (lib, plugin, config,
auth) with clear separation: config handles parsing, auth handles HTTP
logic and decisions, plugin wires them together via the SpoePlugin trait.

## Complexity Tracking

> No constitution violations. All gates pass.
