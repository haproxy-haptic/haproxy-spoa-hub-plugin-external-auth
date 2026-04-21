# HAProxy SPOA Hub — External Auth Plugin

[![Build Status](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-external-auth/badges/main/pipeline.svg)](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-external-auth/-/pipelines)

A [haproxy-spoa-hub](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub) plugin that implements external authentication via HTTP subrequests, similar to nginx's `auth_request` module.

## Overview

HAProxy has no native equivalent to nginx's `auth_request` directive. This plugin fills that gap using the SPOE protocol: for each incoming request, it makes an HTTP subrequest to an external authentication service and returns the auth decision as HAProxy transaction variables. The auth URL is provided dynamically per request from HAProxy, allowing different paths to route to different auth services using ACL rules.

The plugin supports configurable header forwarding, response header extraction (e.g., `X-Auth-User`), fail-open/fail-closed policies, and TLS via rustls.

## Quick Start

### Prerequisites

- [haproxy-spoa-hub](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub) built and running
- HAProxy >= 3.0 with SPOE support
- Rust toolchain (>= 1.86) for building the plugin

### Build

```bash
cargo build --release
```

The output is `target/release/libexternal_auth_plugin.so`. Copy it to the hub's plugin directory.

Pre-built binaries for all supported architectures are available on the [releases page](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-external-auth/-/releases).

### Supported Architectures

| Architecture | Rust Target | Compatible With |
|-------------|-------------|-----------------|
| `amd64` | `x86_64-unknown-linux-gnu` | haproxytech/haproxy-debian (amd64) |
| `arm64` | `aarch64-unknown-linux-gnu` | haproxytech/haproxy-debian (arm64) |
| `armv7` | `armv7-unknown-linux-gnueabihf` | haproxytech/haproxy-debian (arm/v7) |

All binaries are built on Debian bookworm and require **glibc >= 2.36** at runtime.

### Configure the Hub

```toml
[[plugins]]
name = "external_auth"
library = "libexternal_auth_plugin.so"
messages = ["check-auth"]
timeout_ms = 6000

[plugins.params]
timeout_ms = 5000
# fail_open = false
# method = "GET"
# allow_plaintext = false
# forward_headers = ["authorization", "cookie", "x-forwarded-for",
#                    "x-forwarded-proto", "x-forwarded-host",
#                    "x-forwarded-uri"]
# extract_headers = ["x-auth-user", "x-auth-roles"]
```

### Configure HAProxy

The auth URL is passed dynamically from HAProxy as an SPOE message argument. This allows you to route different requests to different auth services using ACL rules.

**SPOE configuration** (`spoe-external-auth.conf`):

The `auth_url` argument can be a literal string via `str()` (for a fixed auth endpoint) or a HAProxy variable via `var()` (for per-path routing). The `path` argument is optional — omit it for auth services like oauth2-proxy that use a fixed check endpoint.

```
[external-auth]
spoe-agent external-auth-agent
    messages check-auth
    option var-prefix spoe
    option continue-on-error
    timeout hello      2s
    timeout idle       5m
    timeout processing 6s
    use-backend spoa-hub-backend

spoe-message check-auth
    args auth_url=str(https://oauth2-proxy.internal/oauth2/auth) \
         path=path \
         hdr_authorization=req.hdr(Authorization) \
         hdr_cookie=req.hdr(Cookie) \
         hdr_x_forwarded_for=req.hdr(X-Forwarded-For) \
         hdr_x_forwarded_proto=req.hdr(X-Forwarded-Proto) \
         hdr_x_forwarded_host=req.hdr(X-Forwarded-Host) \
         hdr_x_forwarded_uri=req.hdr(X-Forwarded-Uri)
    event on-frontend-http-request
```

**HAProxy frontend** (fixed auth URL):

```haproxy
frontend http
    bind *:80

    filter spoe engine external-auth config /etc/haproxy/spoe-external-auth.conf

    # Deny unauthenticated requests
    http-request deny deny_status 401 \
        unless { var(txn.spoe.external_auth.allowed) -m bool }

    # Redirect if auth service provided a redirect URL
    http-request redirect location %[var(txn.spoe.external_auth.redirect_url)] \
        if !{ var(txn.spoe.external_auth.allowed) -m bool } \
           { var(txn.spoe.external_auth.redirect_url) -m found }

    # Forward auth identity to backend
    http-request set-header X-Auth-User %[var(txn.spoe.external_auth.x_auth_user)] \
        if { var(txn.spoe.external_auth.x_auth_user) -m found }

    default_backend app

backend spoa-hub-backend
    mode spop
    server hub /var/run/haproxy-spoa-hub.sock

backend app
    server web 127.0.0.1:8080
```

**Dynamic per-path routing** with `send-spoe-group`:

To route different paths to different auth services, use a `spoe-group` triggered by `http-request send-spoe-group` instead of an event-driven message. This lets you `set-var` the auth URL first, since `send-spoe-group` executes within `http-request` rule processing.

!!! warning
    Do not use `http-request set-var` with event-driven SPOE messages (`on-frontend-http-request`). The event fires **before** `http-request` rules, so variables set with `set-var` are not yet available.

SPOE configuration (`spoe-external-auth.conf`) for dynamic routing:

```
[external-auth]
spoe-agent external-auth-agent
    groups check-auth-group
    option var-prefix spoe
    option continue-on-error
    timeout hello      2s
    timeout idle       5m
    timeout processing 6s
    use-backend spoa-hub-backend

spoe-message check-auth
    args auth_url=var(txn.auth_url) \
         path=path \
         hdr_authorization=req.hdr(Authorization) \
         hdr_cookie=req.hdr(Cookie) \
         hdr_x_forwarded_for=req.hdr(X-Forwarded-For) \
         hdr_x_forwarded_proto=req.hdr(X-Forwarded-Proto) \
         hdr_x_forwarded_host=req.hdr(X-Forwarded-Host) \
         hdr_x_forwarded_uri=req.hdr(X-Forwarded-Uri)

spoe-group check-auth-group
    messages check-auth
```

HAProxy frontend:

```haproxy
frontend http
    bind *:80

    filter spoe engine external-auth config /etc/haproxy/spoe-external-auth.conf

    # Set auth URL per path, then trigger SPOE group
    http-request set-var(txn.auth_url) str(https://oauth2-proxy.internal/oauth2/auth) if { path_beg /dashboard }
    http-request set-var(txn.auth_url) str(https://auth-api.internal/check)          if { path_beg /api }
    http-request send-spoe-group external-auth check-auth-group if { var(txn.auth_url) -m found }

    # Deny unauthenticated requests
    http-request deny deny_status 401 \
        unless { var(txn.spoe.external_auth.allowed) -m bool }

    # Redirect if auth service provided a redirect URL
    http-request redirect location %[var(txn.spoe.external_auth.redirect_url)] \
        if !{ var(txn.spoe.external_auth.allowed) -m bool } \
           { var(txn.spoe.external_auth.redirect_url) -m found }

    # Forward auth identity to backend
    http-request set-header X-Auth-User %[var(txn.spoe.external_auth.x_auth_user)] \
        if { var(txn.spoe.external_auth.x_auth_user) -m found }

    default_backend app

backend spoa-hub-backend
    mode spop
    server hub /var/run/haproxy-spoa-hub.sock

backend app
    server web 127.0.0.1:8080
```

## Configuration Reference

### Plugin Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout_ms` | integer | `5000` | Auth subrequest timeout in milliseconds |
| `fail_open` | boolean | `false` | Allow requests when auth service is unavailable |
| `method` | string | `"GET"` | HTTP method for the auth subrequest (`GET` or `HEAD`) |
| `allow_plaintext` | boolean | `false` | Allow `http://` auth URLs (HTTPS enforced by default) |
| `forward_headers` | string[] | see below | Headers to forward from original request |
| `extract_headers` | string[] | `[]` | Response headers to extract from auth service |

**Default `forward_headers`**: `["authorization", "cookie", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-uri"]`

### SPOE Message Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `auth_url` | string | yes | URL of the auth service (via `str()` or `var()`) |
| `path` | string | no | Request path appended to `auth_url` (omit for fixed-endpoint auth services like oauth2-proxy) |
| `hdr_<name>` | string | no | Header values to forward (e.g., `hdr_authorization`) |

### Output Variables

All variables are transaction-scoped and prefixed with the plugin name by the hub (`external_auth.*`).

| Variable | Type | Always Set | Description |
|----------|------|------------|-------------|
| `allowed` | bool | yes | Auth decision (`true` = allow, `false` = deny) |
| `status_code` | uint32 | yes | HTTP status from auth service (0 on error) |
| `redirect_url` | string | no | `Location` header from 3xx responses |
| `error` | string | no | Error description on failure |
| `<header_name>` | string | no | Each extracted response header (hyphens replaced with underscores) |

### Auth Decision Logic

| Auth Service Response | `allowed` | Notes |
|----------------------|-----------|-------|
| 2xx | `true` | Configured response headers extracted |
| 401, 403 | `false` | Auth denial |
| 3xx | `false` | `redirect_url` set from `Location` header |
| 5xx | depends | `fail_open` policy applied |
| Timeout / unreachable | depends | `fail_open` policy applied |

## Performance

Plugin processing overhead (excluding auth service response time):

| Benchmark | Time |
|-----------|------|
| Variable construction (allow + 2 extracted headers) | ~137 ns |
| Variable construction (deny + redirect) | ~80 ns |
| Full localhost round-trip (HTTP GET + response parsing) | ~244 µs |

## License

Licensed under the [Apache License 2.0](LICENSE).
