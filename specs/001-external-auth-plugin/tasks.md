# Tasks: External Auth Subrequest Plugin

**Input**: Design documents from `/specs/001-external-auth-plugin/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup

**Purpose**: Project initialization and Rust crate scaffolding

- [x] T001 Create Cargo.toml with package metadata (name: external-auth-plugin, version: 0.1.0, edition: 2024, rust-version: 1.86), lib crate-type [cdylib, rlib], dependencies (haproxy-spoa-hub-plugin-api 0.1, abi_stable 0.11, ureq 3.3, log 0.4), dev-dependencies (criterion 0.5 with html_reports, tiny_http for mock server), bench target (auth_bench, harness = false), and release profile (lto = true, codegen-units = 1) in Cargo.toml
- [x] T002 Create src/lib.rs with module declarations (mod config, mod auth, mod plugin) and re-exports
- [x] T003 [P] Configure rustfmt.toml and .clippy.toml at repository root matching fingerprinting plugin settings

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core types and configuration that ALL user stories depend on

**CRITICAL**: No user story work can begin until this phase is complete

- [x] T004 Implement PluginConfig struct in src/config.rs with fields: auth_url (String), forward_headers (Vec<String>), extract_headers (Vec<String>), timeout_ms (u64, default 5000), fail_open (bool, default false), method (String, default "GET"), allow_plaintext (bool, default false); implement from_context() to parse from PluginContext config map; implement defaults for forward_headers (authorization, cookie, x-forwarded-for, x-forwarded-proto, x-forwarded-host, x-forwarded-uri); validate auth_url scheme (reject http:// unless allow_plaintext is true), timeout_ms > 0, method is GET or HEAD; store header names lowercased
- [x] T005 Implement config_schema() in src/config.rs returning the JSON schema string from contracts/plugin-interface.md for hub-side validation
- [x] T006 Implement AuthDecision struct in src/auth.rs with fields: allowed (bool), status_code (u32), redirect_url (Option<String>), extracted_headers (Vec<(String, String)>); implement to_variables() converting AuthDecision to Vec<TxnVariable> with Transaction scope (allowed as Bool, status_code as Uint32, redirect_url as String if Some, error as String if present, each extracted header as String with hyphens replaced by underscores)
- [x] T007 Implement ExternalAuthPlugin struct in src/plugin.rs with fields: config (Option<PluginConfig>), agent (Option<ureq::Agent>); implement new() returning uninitialized struct; implement name() returning "external-auth"; implement version() returning env!("CARGO_PKG_VERSION"); implement shutdown() as no-op; implement config_schema() delegating to config::config_schema(); wrap with define_plugin!() macro
- [x] T008 Implement init() in src/plugin.rs: parse PluginConfig from context via config::from_context(), create ureq::Agent with timeout_global set to config.timeout_ms, store both in self

**Checkpoint**: Foundation ready — PluginConfig, AuthDecision, and plugin scaffold complete

---

## Phase 3: User Story 1 - Forward Auth Decision to External Service (Priority: P1)

**Goal**: Make HTTP subrequest to auth service and return allow/deny decision as HAProxy variables

**Independent Test**: Mock auth service returns 200 for valid Authorization header, 401 otherwise; verify plugin returns correct allowed/status_code variables

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T009 [P] [US1] Unit test in tests/auth_test.rs: test AuthDecision::to_variables() produces correct TxnVariable vec for allowed=true (Bool true, status_code 200) and allowed=false (Bool false, status_code 401)
- [x] T010 [P] [US1] Integration test in tests/plugin_test.rs: start tiny_http server returning 200 with fixed headers; construct SpoeMessage with method, path, host, hdr_authorization args; call plugin process(); assert allowed=true and status_code=200 in result variables
- [x] T011 [P] [US1] Integration test in tests/plugin_test.rs: start tiny_http server returning 401; construct SpoeMessage without credentials; call plugin process(); assert allowed=false and status_code=401 in result variables

### Implementation for User Story 1

- [x] T012 [US1] Implement send_auth_request() in src/auth.rs: take ureq::Agent, PluginConfig, method (str), path (str), host (str), and headers (HashMap<String, String>); build request to auth_url with configured method; set forwarded headers on the request; call agent.request(); match response status: 2xx → AuthDecision { allowed: true, status_code }; 401/403 → AuthDecision { allowed: false, status_code }; 3xx → AuthDecision { allowed: false, status_code, redirect_url: Location header }; return AuthDecision
- [x] T013 [US1] Implement process() in src/plugin.rs: extract method, path, host from SpoeMessage args; extract hdr_* prefixed args into headers map; call auth::send_auth_request() with agent, config, extracted args; convert AuthDecision to ProcessingResult via to_variables(); log auth decision at info level (allowed/denied, status code, path — no sensitive headers)
- [x] T014 [P] [US1] Create example hub configuration in examples/hub.toml with plugin entry for external_auth, messages ["check-auth"], and sample params (auth_url, timeout_ms, extract_headers)
- [x] T015 [P] [US1] Create example SPOE configuration in examples/spoe-external-auth.conf with spoe-agent and spoe-message check-auth definitions including all default forwarded header args
- [x] T016 [P] [US1] Create example HAProxy frontend configuration in examples/haproxy.cfg with SPOE filter, deny/redirect rules based on external_auth variables, and backend definitions

**Checkpoint**: Core auth flow works — plugin makes subrequest, returns allow/deny decision

---

## Phase 4: User Story 2 - Configurable Header Forwarding (Priority: P2)

**Goal**: Forward configurable set of request headers to auth service, with sensible defaults

**Independent Test**: Configure plugin with custom forward_headers list; verify only those headers appear in auth subrequest

### Tests for User Story 2

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T017 [P] [US2] Integration test in tests/auth_test.rs: start tiny_http server that captures received headers; configure plugin with default forward_headers; send SpoeMessage with hdr_authorization and hdr_cookie args; assert auth subrequest contains both Authorization and Cookie headers
- [x] T018 [P] [US2] Integration test in tests/auth_test.rs: configure plugin with forward_headers = ["x-custom-token"]; send SpoeMessage with hdr_authorization and hdr_x_custom_token args; assert auth subrequest contains only X-Custom-Token header (not Authorization)

### Implementation for User Story 2

- [x] T019 [US2] Update send_auth_request() in src/auth.rs to filter forwarded headers: only include headers whose lowercased name matches an entry in config.forward_headers; map hdr_* prefixed SPOE arg names back to HTTP header names (strip hdr_ prefix, replace underscores with hyphens)
- [x] T020 [US2] Add unit test in tests/config_test.rs: verify PluginConfig from_context() with no forward_headers specified uses default list; verify custom forward_headers are stored lowercase

**Checkpoint**: Header forwarding is configurable and correctly filters

---

## Phase 5: User Story 3 - Auth Service Timeout and Error Handling (Priority: P3)

**Goal**: Graceful failure with configurable fail-open/fail-closed policy

**Independent Test**: Point plugin at unreachable auth URL; verify fail-closed returns denied, fail-open returns allowed

### Tests for User Story 3

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T021 [P] [US3] Integration test in tests/auth_test.rs: configure plugin with auth_url pointing to unbound port, fail_open = false; call send_auth_request(); assert AuthDecision { allowed: false, status_code: 0 }
- [x] T022 [P] [US3] Integration test in tests/auth_test.rs: configure plugin with auth_url pointing to unbound port, fail_open = true; call send_auth_request(); assert AuthDecision { allowed: true, status_code: 0 }
- [x] T023 [P] [US3] Integration test in tests/auth_test.rs: start tiny_http server returning 500; call send_auth_request() with fail_open = false; assert AuthDecision { allowed: false, status_code: 500 }
- [x] T024 [P] [US3] Integration test in tests/auth_test.rs: configure plugin with timeout_ms = 100; start tiny_http server that sleeps 500ms before responding; call send_auth_request(); assert timeout error, AuthDecision reflects failure policy

### Implementation for User Story 3

- [x] T025 [US3] Update send_auth_request() in src/auth.rs: wrap ureq call in error handling; on connection error or timeout, if config.fail_open return AuthDecision { allowed: true, status_code: 0, error: description }; if !config.fail_open return AuthDecision { allowed: false, status_code: 0, error: description }; on 5xx, apply same failure policy; log errors at warn level (fail_open) or error level (fail_closed) with component name, auth_url, and error description (no sensitive data)
- [x] T026 [US3] Update to_variables() in src/auth.rs to include error String variable when error field is present in AuthDecision; add error field (Option<String>) to AuthDecision struct

**Checkpoint**: Plugin handles all failure modes gracefully with configurable policy

---

## Phase 6: User Story 4 - Response Header Extraction (Priority: P4)

**Goal**: Extract configurable response headers from auth service and return as HAProxy variables

**Independent Test**: Configure extract_headers = ["x-auth-user", "x-auth-roles"]; mock auth service returns those headers; verify they appear as transaction variables

### Tests for User Story 4

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T027 [P] [US4] Integration test in tests/auth_test.rs: start tiny_http server returning 200 with X-Auth-User: alice and X-Auth-Roles: admin,editor headers; configure extract_headers = ["x-auth-user", "x-auth-roles"]; call send_auth_request(); assert extracted_headers contains both pairs
- [x] T028 [P] [US4] Integration test in tests/auth_test.rs: start tiny_http server returning 200 without X-Auth-User header; configure extract_headers = ["x-auth-user"]; call send_auth_request(); assert extracted_headers is empty (missing header silently skipped)
- [x] T029 [P] [US4] Unit test in tests/auth_test.rs: verify to_variables() converts extracted_headers with hyphen-to-underscore name mapping (x-auth-user → x_auth_user)

### Implementation for User Story 4

- [x] T030 [US4] Update send_auth_request() in src/auth.rs: on 2xx response, iterate config.extract_headers; for each header name, look up value in response headers (case-insensitive); if found, add (name, value) to AuthDecision.extracted_headers
- [x] T031 [US4] Update to_variables() in src/auth.rs: for each entry in extracted_headers, create TxnVariable with name = header name with hyphens replaced by underscores, value = SpoeValue::String, scope = Transaction

**Checkpoint**: All user stories complete — full auth_request feature parity with nginx

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Benchmarks, validation, CI, and documentation

- [x] T032 [P] Create Criterion benchmark in benches/auth_bench.rs: bench process() with tiny_http mock server returning 200; measure plugin processing overhead excluding network (use localhost); track as baseline for regression detection
- [x] T033 [P] Add config validation tests in tests/config_test.rs: reject http:// URL when allow_plaintext = false; accept http:// when allow_plaintext = true; reject timeout_ms = 0; reject invalid method; verify header names stored lowercase
- [x] T034 [P] Create .gitlab-ci.yml with stages: check (fmt, clippy, test, bench), build (parallel matrix for amd64, arm64, armv7 using cross-compilation), release (triggered by v* tags) — matching fingerprinting plugin CI structure
- [x] T035 Run quickstart.md validation: verify all example configs are syntactically correct and consistent with plugin implementation
- [x] T036 Code cleanup: run clippy with all warnings denied, verify no dead code or unused imports, verify all module and function names accurately reflect their purpose

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3-6)**: All depend on Foundational phase completion
  - US1 (Phase 3): No dependencies on other stories
  - US2 (Phase 4): Depends on US1 (extends send_auth_request header logic)
  - US3 (Phase 5): Depends on US1 (extends send_auth_request error handling)
  - US4 (Phase 6): Depends on US1 (extends send_auth_request response processing)
- **Polish (Phase 7)**: Depends on all user stories being complete

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Implementation tasks follow test tasks
- Example configs can be created in parallel with implementation

### Parallel Opportunities

- T002 and T003 can run in parallel (different files)
- T004, T005, T006 can run in parallel (different functions in different files)
- T007 and T008 are sequential (T008 depends on T007)
- All test tasks within a story marked [P] can run in parallel
- Example config tasks T014, T015, T016 can run in parallel
- Phase 7 tasks T032, T033, T034 can run in parallel

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test auth allow/deny flow with mock server
5. Plugin is functional for basic auth forwarding

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. Add User Story 1 → Basic auth works (MVP)
3. Add User Story 2 → Configurable headers
4. Add User Story 3 → Production-ready error handling
5. Add User Story 4 → Full nginx auth_request parity
6. Polish → Benchmarks, CI, cleanup

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- US2, US3, US4 all extend US1's send_auth_request() — they build incrementally on the same function
- tiny_http crate is used as dev-dependency for lightweight mock HTTP servers in tests
- All tests use localhost connections to avoid network dependency
- Commit after each task or logical group
