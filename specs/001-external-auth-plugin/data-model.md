# Data Model: External Auth Subrequest Plugin

**Date**: 2026-04-09
**Branch**: `001-external-auth-plugin`

## Entities

### PluginConfig

Configuration parsed from hub's TOML `[plugins.params]` during `init()`.

| Field                | Type          | Default                          | Description                                                    |
|----------------------|---------------|----------------------------------|----------------------------------------------------------------|
| `auth_url`           | String        | *(required)*                     | URL of the external auth service endpoint (https:// recommended) |
| `forward_headers`    | Vec\<String\> | see below                        | Headers from original request to forward to auth service       |
| `extract_headers`    | Vec\<String\> | `[]`                             | Response headers to extract from auth service and return as variables |
| `timeout_ms`         | u64           | `5000`                           | Timeout for the auth subrequest in milliseconds                |
| `fail_open`          | bool          | `false`                          | If true, allow requests when auth service is unavailable       |
| `method`             | String        | `"GET"`                          | HTTP method for the auth subrequest                            |
| `allow_plaintext`    | bool          | `false`                          | Must be true to use http:// URLs; https:// enforced by default |

**Default `forward_headers`**:
`["authorization", "cookie", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-uri"]`

**Validation rules**:
- `auth_url` MUST be a valid HTTP or HTTPS URL
- `auth_url` with `http://` scheme MUST be rejected unless `allow_plaintext` is `true`
- `timeout_ms` MUST be > 0
- `method` MUST be one of `GET`, `HEAD`
- Header names in `forward_headers` and `extract_headers` are
  case-insensitive (stored lowercase internally)

### AuthDecision

The result of processing a single auth subrequest. Not persisted —
exists only for the duration of a single `process()` call.

| Field            | Type          | Description                                              |
|------------------|---------------|----------------------------------------------------------|
| `allowed`        | bool          | True if auth service returned 2xx                        |
| `status_code`    | u32           | HTTP status code from auth service (0 if unreachable)    |
| `redirect_url`   | Option\<String\> | `Location` header value if 3xx response              |
| `extracted_headers` | Vec\<(String, String)\> | Header name-value pairs from auth service response |

### SpoeMessage Input

Arguments received from HAProxy via the SPOE protocol.

| Argument     | SPOE Type | Description                          |
|--------------|-----------|--------------------------------------|
| `method`     | String    | HTTP request method                  |
| `path`       | String    | Request URI path and query string    |
| `host`       | String    | Host header value                    |
| `auth_url`   | String    | Optional per-request override for auth service URL |
| `hdr_*`      | String    | Individual header values (e.g., `hdr_authorization`) |

### Transaction Variables Output

Variables returned to HAProxy via the SPOE ACK.

| Variable          | Scope       | SPOE Type | Description                                    |
|-------------------|-------------|-----------|------------------------------------------------|
| `allowed`         | Transaction | Bool      | Auth decision: true=allow, false=deny          |
| `status_code`     | Transaction | Uint32    | HTTP status from auth service (0 on error)     |
| `redirect_url`    | Transaction | String    | `Location` header for 3xx responses            |
| `error`           | Transaction | String    | Error description when auth service unreachable |
| `<header_name>`   | Transaction | String    | Each extracted response header (lowercased, hyphens replaced with underscores) |

**Namespace**: All variables are prefixed with the plugin name by the
hub (e.g., `external_auth.allowed`), accessible in HAProxy as
`%[var(txn.spoe.external_auth.allowed)]`.

## State Transitions

```
SpoeMessage received
    │
    ├─ Parse config + extract headers from message args
    │
    ├─ Build HTTP subrequest (method, auth_url, forwarded headers)
    │
    ├─ Send subrequest via ureq::Agent
    │   │
    │   ├─ 2xx → AuthDecision { allowed: true, extract response headers }
    │   │
    │   ├─ 401/403 → AuthDecision { allowed: false }
    │   │
    │   ├─ 3xx → AuthDecision { allowed: false, redirect_url: Location }
    │   │
    │   ├─ 5xx → Apply failure policy (fail_open or fail_closed)
    │   │
    │   └─ Timeout/Error → Apply failure policy (fail_open or fail_closed)
    │
    └─ Convert AuthDecision → Vec<TxnVariable> → ProcessingResult
```
