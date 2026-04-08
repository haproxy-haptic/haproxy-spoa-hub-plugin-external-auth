# Contract: SpoePlugin Interface

**Date**: 2026-04-09
**Type**: Dynamic library FFI interface

## Plugin Trait Implementation

The plugin exports the `SpoePlugin` trait via the `define_plugin!` macro
from `haproxy-spoa-hub-plugin-api`.

### Required Methods

| Method          | Signature                                                      | Description                              |
|-----------------|----------------------------------------------------------------|------------------------------------------|
| `new()`         | `fn new() -> Self`                                             | Factory — create uninitialized instance   |
| `init()`        | `fn init(&mut self, ctx: &PluginContext) -> Result<(), Error>` | Parse config, create ureq Agent          |
| `name()`        | `fn name(&self) -> &str`                                      | Returns `"external-auth"`               |
| `version()`     | `fn version(&self) -> &str`                                   | Returns crate version                    |
| `process()`     | `fn process(&self, msg: &SpoeMessage) -> Result<ProcessingResult, Error>` | Auth subrequest + decision    |
| `config_schema()` | `fn config_schema(&self) -> Option<&str>`                   | Returns JSON schema for params validation |
| `shutdown()`    | `fn shutdown(&self)`                                           | No-op (Agent drops cleanly)              |

### SPOE Message Contract

**Message name**: `check-auth`

**Input arguments**:

| Key                | SPOE Type | Required | Description              |
|--------------------|-----------|----------|--------------------------|
| `method`           | String    | Yes      | HTTP method              |
| `path`             | String    | Yes      | Request URI path + query |
| `host`             | String    | No       | Host header              |
| `auth_url`         | String    | No       | Per-request auth URL override (takes precedence over config) |
| `hdr_<name>`       | String    | No       | Forwarded header values  |

**Output variables** (Transaction scope):

| Variable           | SPOE Type | Always set | Description                         |
|--------------------|-----------|------------|-------------------------------------|
| `allowed`          | Bool      | Yes        | Auth decision                       |
| `status_code`      | Uint32    | Yes        | Auth service HTTP status (0=error)  |
| `redirect_url`     | String    | No         | Location header from 3xx response   |
| `error`            | String    | No         | Error description on failure        |
| `<header_name>`    | String    | No         | Extracted auth response headers     |

### Configuration Schema

```json
{
  "type": "object",
  "required": ["auth_url"],
  "properties": {
    "auth_url": {
      "type": "string",
      "description": "URL of the external auth service (https:// by default)"
    },
    "allow_plaintext": {
      "type": "boolean",
      "description": "Allow http:// URLs (default: false, requires explicit opt-in)"
    },
    "forward_headers": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Headers to forward from original request"
    },
    "extract_headers": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Response headers to extract from auth service"
    },
    "timeout_ms": {
      "type": "integer",
      "minimum": 1,
      "description": "Auth subrequest timeout in milliseconds"
    },
    "fail_open": {
      "type": "boolean",
      "description": "Allow requests when auth service is unavailable"
    },
    "method": {
      "type": "string",
      "enum": ["GET", "HEAD"],
      "description": "HTTP method for auth subrequest"
    }
  }
}
```
