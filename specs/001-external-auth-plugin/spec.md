# Feature Specification: External Auth Subrequest Plugin

**Feature Branch**: `001-external-auth-plugin`
**Created**: 2026-04-09
**Status**: Draft
**Input**: User description: "Implement a haproxy-spoa-hub plugin for auth via external subrequests like nginx auth_request"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Forward Auth Decision to External Service (Priority: P1)

An operator configures the plugin with a URL pointing to an external
authentication service (e.g., oauth2-proxy, Authelia, a custom auth
endpoint). When a client request arrives at HAProxy, the SPOE filter
forwards request metadata to the hub, which invokes this plugin. The
plugin makes an HTTP subrequest to the configured auth URL, forwarding
relevant headers from the original request (e.g., `Authorization`,
`Cookie`, `X-Forwarded-*`). If the auth service responds with 2xx, the
plugin returns a success variable and optionally extracts response
headers (e.g., `X-Auth-User`, `X-Auth-Groups`) as transaction variables
so HAProxy can inject them into the upstream request. If the auth
service responds with 401 or 403, the plugin returns a denial variable
and the redirect URL from the auth service's response, allowing HAProxy
to deny or redirect the client.

**Why this priority**: This is the core value proposition — replicating
nginx's `auth_request` behavior in HAProxy. Without this, the plugin
has no purpose.

**Independent Test**: Configure the plugin with a mock auth service
that returns 200 for requests with a valid `Authorization` header and
401 otherwise. Verify that HAProxy allows authenticated requests
through and returns 401 for unauthenticated ones.

**Acceptance Scenarios**:

1. **Given** a plugin configured with an auth URL pointing to a running auth service, **When** HAProxy receives a request with a valid session cookie, **Then** the auth subrequest returns 2xx and the original request is forwarded to the upstream with auth response headers injected.
2. **Given** the same configuration, **When** HAProxy receives a request without credentials, **Then** the auth subrequest returns 401 and the plugin sets denial variables that HAProxy uses to reject or redirect the client.
3. **Given** the auth service returns custom headers (e.g., `X-Auth-User: alice`), **When** the subrequest succeeds, **Then** those headers are available as transaction variables in HAProxy (e.g., `txn.spoe.external_auth.x_auth_user`).

---

### User Story 2 - Configurable Header Forwarding (Priority: P2)

An operator configures which headers from the original client request
are forwarded to the auth service. By default, the plugin forwards
`Authorization`, `Cookie`, `X-Forwarded-For`, `X-Forwarded-Proto`,
`X-Forwarded-Host`, and `X-Forwarded-Uri`. The operator can override
this list via plugin configuration to add or restrict headers based on
their auth service's requirements.

**Why this priority**: Different auth services require different headers.
Without configurability, operators must modify the HAProxy SPOE
configuration to pass exactly the right fields, which is error-prone.

**Independent Test**: Configure the plugin with a custom header list.
Verify that only the specified headers are forwarded to the auth
service, and that no additional headers leak through.

**Acceptance Scenarios**:

1. **Given** default header configuration, **When** a request with `Authorization` and `Cookie` headers arrives, **Then** both headers are forwarded to the auth service.
2. **Given** a custom configuration forwarding only `X-Custom-Token`, **When** a request with both `Authorization` and `X-Custom-Token` arrives, **Then** only `X-Custom-Token` is forwarded to the auth service.

---

### User Story 3 - Auth Service Timeout and Error Handling (Priority: P3)

When the external auth service is unreachable, responds slowly, or
returns an unexpected status code (e.g., 500), the plugin handles the
failure gracefully according to a configurable policy. The operator
can choose between fail-closed (deny on error, the default) and
fail-open (allow on error) behavior. The plugin reports the failure
via structured logging and metrics so operators can detect auth
service degradation.

**Why this priority**: Production reliability requires graceful
degradation. Without proper error handling, an auth service outage
would either crash the plugin or produce undefined behavior.

**Independent Test**: Configure the plugin with a deliberately
unreachable auth URL. Verify that requests are denied (fail-closed
default) and that error metrics are incremented.

**Acceptance Scenarios**:

1. **Given** the auth service is unreachable and fail-closed policy is configured (default), **When** a request arrives, **Then** the plugin returns a denial variable and logs the connection failure.
2. **Given** the auth service is unreachable and fail-open policy is configured, **When** a request arrives, **Then** the plugin returns a success variable and logs a warning.
3. **Given** the auth service responds with HTTP 500, **When** a request arrives, **Then** the plugin treats it as an error (not as an auth denial) and applies the configured failure policy.

---

### User Story 4 - Response Header Extraction (Priority: P4)

The operator configures a list of response headers to extract from the
auth service's successful (2xx) response. These are returned as
transaction variables so HAProxy can inject them as headers into the
upstream request. This enables the auth service to communicate user
identity, roles, or other metadata to the backend.

**Why this priority**: This is a key feature of nginx's auth_request
pattern — the auth proxy sets headers like `X-Auth-User` that the
backend consumes. Without this, operators lose a significant part of
the auth flow.

**Independent Test**: Configure the plugin to extract `X-Auth-User`
and `X-Auth-Roles`. Verify that when the auth service returns these
headers in its 2xx response, they appear as transaction variables in
HAProxy.

**Acceptance Scenarios**:

1. **Given** the plugin is configured to extract `X-Auth-User` and `X-Auth-Roles`, **When** the auth service returns `200` with `X-Auth-User: alice` and `X-Auth-Roles: admin,editor`, **Then** the variables `external_auth.x_auth_user=alice` and `external_auth.x_auth_roles=admin,editor` are available in HAProxy.
2. **Given** the plugin is configured to extract `X-Auth-User`, **When** the auth service returns `200` without that header, **Then** the variable is not set (no error raised).

---

### Edge Cases

- What happens when the auth service returns a redirect (3xx)? The plugin treats 3xx as a denial and captures the `Location` header as a variable for HAProxy to issue the redirect.
- What happens when the auth service response body is very large? The plugin ignores the response body entirely; only status code and headers are processed.
- What happens when the original request has no headers matching the forwarding list? The subrequest is sent with only the method and path, no additional headers.
- What happens when multiple plugins depend on this plugin's output? Downstream plugins receive the auth variables via the hub's dependency merging mechanism.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The plugin MUST make an HTTP subrequest to a configurable auth URL for each incoming SPOE message.
- **FR-002**: The plugin MUST forward configurable request headers from the original client request to the auth service.
- **FR-003**: The plugin MUST return a boolean transaction variable indicating whether the auth service allowed (2xx) or denied (401/403) the request.
- **FR-004**: The plugin MUST return the HTTP status code from the auth service as a transaction variable.
- **FR-005**: The plugin MUST extract configurable response headers from the auth service's 2xx response and return them as transaction variables.
- **FR-006**: The plugin MUST handle auth service unavailability according to a configurable policy (fail-closed or fail-open).
- **FR-007**: The plugin MUST support a configurable timeout for the auth subrequest, independent of the hub's per-plugin timeout.
- **FR-008**: The plugin MUST treat 3xx responses from the auth service as denials and capture the `Location` header.
- **FR-009**: The plugin MUST expose a JSON schema for configuration validation by the hub.
- **FR-010**: The plugin MUST log auth decisions and errors using structured logging.

### Key Entities

- **Auth Request**: An HTTP subrequest to the external auth service, constructed from the original client request's metadata and the plugin's configuration.
- **Auth Decision**: The outcome of the auth subrequest — allowed (2xx), denied (401/403/3xx), or error (5xx/timeout/unreachable).
- **Auth Variables**: Transaction-scoped SPOE variables returned to HAProxy carrying the auth decision, status code, extracted headers, and redirect URL.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator can configure the plugin and achieve functional external auth with HAProxy in under 15 minutes using the provided documentation and example configurations.
- **SC-002**: Auth subrequest overhead (excluding external auth service response time) remains below 1ms at p99 for the plugin's own processing.
- **SC-003**: The plugin correctly handles all auth service response codes: 2xx (allow), 401/403 (deny), 3xx (deny with redirect), 5xx (error with configurable policy).
- **SC-004**: When the auth service is unavailable, the plugin applies the configured failure policy within the configured timeout, without hanging or crashing.
- **SC-005**: Operators can extract at least 10 custom response headers from the auth service and use them as HAProxy variables.

## Assumptions

- The external auth service speaks HTTP/1.1 and is reachable from the host running the SPOA hub.
- HAProxy is configured with an SPOE filter that sends the necessary request metadata (method, path, headers) to the hub.
- The plugin follows the same project structure, build configuration, and compiler optimizations as the fingerprinting plugin (cdylib + rlib, LTO, single codegen unit, `abi_stable`).
- The plugin uses the `haproxy-spoa-hub-plugin-api` crate for the `SpoePlugin` trait and SPOE types.
- The plugin uses TLS (HTTPS) by default for auth service communication. Plaintext HTTP requires explicit opt-in via configuration.
- The plugin does not forward the request body to the auth service (consistent with nginx's `auth_request` behavior, which sends a subrequest with the same URI but no body by default).
