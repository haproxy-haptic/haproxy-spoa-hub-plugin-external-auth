# Quickstart: External Auth Subrequest Plugin

**Date**: 2026-04-09
**Branch**: `001-external-auth-plugin`

## Prerequisites

- HAProxy 2.6+ with SPOE support
- haproxy-spoa-hub running with at least one listener configured
- An external auth service accessible via HTTP from the SPOA hub host

## 1. Build the Plugin

```bash
cargo build --release
# Output: target/release/libexternal_auth_plugin.so
```

Copy the shared library to the hub's plugin directory:

```bash
cp target/release/libexternal_auth_plugin.so /opt/spoa-plugins/
```

## 2. Configure the Hub

Add the plugin to the hub's TOML configuration:

```toml
[[plugins]]
name = "external_auth"
library = "libexternal_auth_plugin.so"
messages = ["check-auth"]
timeout_ms = 6000  # should exceed the plugin's internal auth_timeout_ms

[plugins.params]
timeout_ms = 5000
# fail_open = false          # default: deny on auth service error
# method = "GET"             # default: GET
# allow_plaintext = false    # default: require https:// auth URLs
# forward_headers = ["authorization", "cookie", "x-forwarded-for",
#                    "x-forwarded-proto", "x-forwarded-host",
#                    "x-forwarded-uri"]
# extract_headers = ["x-auth-user", "x-auth-roles"]
```

## 3. Configure HAProxy SPOE

Create `spoe-external-auth.conf`:

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
    args auth_url=var(txn.auth_url) \
         path=path \
         hdr_authorization=req.hdr(Authorization) \
         hdr_cookie=req.hdr(Cookie) \
         hdr_x_forwarded_for=req.hdr(X-Forwarded-For) \
         hdr_x_forwarded_proto=req.hdr(X-Forwarded-Proto) \
         hdr_x_forwarded_host=req.hdr(X-Forwarded-Host) \
         hdr_x_forwarded_uri=req.hdr(X-Forwarded-Uri)
    event on-frontend-http-request
```

## 4. Configure HAProxy Frontend

```haproxy
frontend http
    bind *:80

    # Set auth URL dynamically per path
    http-request set-var(txn.auth_url) str(https://auth-service.internal/check)

    filter spoe engine external-auth config /etc/haproxy/spoe-external-auth.conf

    # Deny unauthenticated requests
    http-request deny deny_status 401 \
        unless { var(txn.spoe.external_auth.allowed) -m bool }

    # Redirect if auth service provided a redirect URL
    http-request redirect location %[var(txn.spoe.external_auth.redirect_url)] \
        if !{ var(txn.spoe.external_auth.allowed) -m bool } \
           { var(txn.spoe.external_auth.redirect_url) -m found }

    # Forward auth user to backend
    http-request set-header X-Auth-User %[var(txn.spoe.external_auth.x_auth_user)] \
        if { var(txn.spoe.external_auth.x_auth_user) -m found }

    default_backend app

backend spoa-hub-backend
    mode spop
    server hub /var/run/haproxy-spoa-hub.sock

backend app
    server web 127.0.0.1:8080
```

## 5. Verify

```bash
# Request without credentials (should be denied)
curl -v http://<haproxy-host>/protected
# Expected: HTTP 401

# Request with valid credentials
curl -v -H "Authorization: Bearer <valid-token>" http://<haproxy-host>/protected
# Expected: HTTP 200, X-Auth-User header forwarded to backend
```
