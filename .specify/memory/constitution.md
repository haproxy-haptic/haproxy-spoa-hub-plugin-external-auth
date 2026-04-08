<!--
Sync Impact Report
- Version change: N/A → 1.0.0 (initial adoption)
- Added principles:
  - I. Code Quality
  - II. Testing Standards
  - III. User Experience Consistency
  - IV. Performance Requirements
- Added sections:
  - Security & Reliability
  - Development Workflow
- Templates requiring updates:
  - .specify/templates/plan-template.md ✅ no updates needed (Constitution Check section is generic)
  - .specify/templates/spec-template.md ✅ no updates needed (structure aligns with principles)
  - .specify/templates/tasks-template.md ✅ no updates needed (phase structure compatible)
  - .specify/templates/commands/*.md ✅ no command files exist
- Follow-up TODOs: none
-->

# HAProxy SPOA Hub Plugin External Auth Constitution

## Core Principles

### I. Code Quality

All code MUST be clear, maintainable, and idiomatic for the language in use.

- Every function, module, and interface MUST have a single, well-defined
  responsibility. Avoid god objects and monolithic functions.
- Public APIs MUST use precise, descriptive naming that reflects intent.
  Abbreviations are acceptable only when they are universally understood
  within the domain (e.g., SPOA, HAProxy, HTTP).
- Dead code, unused imports, and commented-out code MUST NOT be committed.
- Linting and formatting tools MUST be configured and enforced in CI.
  Code that fails lint checks MUST NOT be merged.
- Dependencies MUST be explicitly declared and version-pinned.
  New dependencies require justification in the PR description.

### II. Testing Standards

All changes MUST be accompanied by appropriate tests. Test-Driven
Development (TDD) is the preferred workflow.

- Bug fixes MUST include a regression test that reproduces the bug before
  the fix is applied (red-green-refactor).
- New features MUST have tests covering the documented acceptance criteria
  from the specification.
- Integration tests MUST validate the SPOA protocol communication path
  and external auth service interactions using realistic configurations.
- Unit tests MUST be deterministic, isolated, and fast. No test may depend
  on network access, wall-clock time, or execution order.
- Test coverage MUST NOT decrease with any change. Coverage gaps in
  critical paths (auth decisions, error handling) MUST be addressed before
  merge.

### III. User Experience Consistency

The plugin MUST behave predictably and provide clear, actionable feedback
to operators integrating it with HAProxy.

- Configuration options MUST follow HAProxy naming conventions and
  patterns familiar to HAProxy operators.
- Error messages MUST identify the failing component, the nature of the
  failure, and a suggested remediation when possible.
- Logging MUST use structured formats with consistent severity levels.
  Auth decisions MUST be logged at a level that enables audit and
  troubleshooting without excessive verbosity at default log levels.
- Breaking changes to configuration or behavior MUST be documented in
  release notes and require a major version bump.
- Default configuration values MUST be secure and production-ready.
  Insecure defaults (e.g., disabled TLS verification) MUST NOT ship.

### IV. Performance Requirements

The plugin MUST NOT become a bottleneck in the HAProxy request processing
pipeline.

- Auth decision latency MUST remain below 10ms at p99 under normal
  operating conditions (excluding external auth service response time).
- The plugin MUST handle connection failures to the external auth service
  gracefully, with configurable timeout and fallback behavior.
- Memory usage MUST remain bounded regardless of request volume.
  No unbounded caches, queues, or connection pools.
- The plugin MUST support concurrent request processing without
  introducing data races or lock contention that degrades throughput.
- Performance-sensitive code paths MUST be benchmarked, and benchmark
  results MUST be tracked across changes to detect regressions.

## Security & Reliability

- All communication with external auth services MUST use TLS by default.
  Plaintext connections MUST require explicit opt-in configuration.
- Sensitive data (tokens, credentials, auth responses) MUST NOT appear in
  logs at any severity level.
- The plugin MUST fail closed: if the external auth service is unreachable
  and no fallback policy is configured, requests MUST be denied.
- Input from HAProxy (SPOA messages) and from external auth services MUST
  be validated before processing. Malformed input MUST be rejected with
  an appropriate error, never silently ignored.

## Development Workflow

- All changes enter through pull requests. Direct pushes to the main
  branch are prohibited.
- PRs MUST pass all CI checks (tests, linting, formatting) before merge.
- Commit messages MUST follow conventional commits format.
- Each PR SHOULD address a single concern. Mixing unrelated changes in
  one PR is discouraged.
- Release versions follow semantic versioning (MAJOR.MINOR.PATCH).

## Governance

This constitution defines the non-negotiable standards for the project.
All contributions MUST comply with these principles.

- Amendments to this constitution require a PR with clear rationale.
  The version MUST be incremented according to semantic versioning:
  MAJOR for principle removals or incompatible redefinitions, MINOR for
  new principles or material expansions, PATCH for clarifications.
- Compliance with these principles MUST be verified during code review.
  Reviewers SHOULD reference the relevant principle when requesting
  changes.

**Version**: 1.0.0 | **Ratified**: 2026-04-09 | **Last Amended**: 2026-04-09
