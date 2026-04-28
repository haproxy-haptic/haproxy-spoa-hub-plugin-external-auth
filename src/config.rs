use haproxy_spoa_hub_plugin_api::PluginContext;

const DEFAULT_FORWARD_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-uri",
];

/// HTTP methods the plugin will dispatch to the auth service. Used by
/// both the plugin-level config validation and the per-request override
/// path (`method` SPOE arg). The plugin doesn't forward the original
/// request body — POST/PUT/PATCH go out with an empty body, matching
/// nginx-ingress's `auth_request` behaviour where the auth-url is
/// always fetched independently of the original method's payload.
/// Auth services that need the body should read it from sample-fetch
/// args instead (e.g., `body=req.body` in the spoe-message), or use
/// header-based auth (e.g., bearer tokens).
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Validate an HTTP method string. The input must already be uppercased;
/// `PluginConfig::from_context` and `plugin::process` both upper-case
/// before calling.
pub fn validate_method(method: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !ALLOWED_METHODS.contains(&method) {
        return Err(format!("method must be one of {ALLOWED_METHODS:?}, got: {method}").into());
    }
    Ok(())
}

/// Default cap for the mTLS Agent cache. Each entry is a ureq Agent
/// holding a rustls ClientConfig — a few KB. 64 covers realistic
/// per-pod cert variety with headroom; operators with larger
/// fleets (many tenants × distinct cert-using auth services) can
/// override via `mtls_cache_capacity` in the plugin config.
pub const DEFAULT_MTLS_CACHE_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub forward_headers: Vec<String>,
    pub extract_headers: Vec<String>,
    pub timeout_ms: u64,
    pub fail_open: bool,
    pub method: String,
    pub allow_plaintext: bool,
    /// Maximum number of distinct (cert, key) pairs to keep cached
    /// (FIFO eviction past this). 0 disables caching entirely (an
    /// Agent is built fresh for every mTLS request — useful for
    /// tests, expensive in production).
    pub mtls_cache_capacity: usize,
}

impl PluginConfig {
    pub fn from_context(
        context: &PluginContext,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let allow_plaintext = context
            .get_config("allow_plaintext")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let timeout_ms = context
            .get_config("timeout_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64)
            .unwrap_or(5000);

        let fail_open = context
            .get_config("fail_open")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let method = context
            .get_config("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();

        let forward_headers = context
            .get_config("forward_headers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_else(|| {
                DEFAULT_FORWARD_HEADERS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });

        let extract_headers = context
            .get_config("extract_headers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        let mtls_cache_capacity = context
            .get_config("mtls_cache_capacity")
            .and_then(|v| v.as_integer())
            .map(|n| n.max(0) as usize)
            .unwrap_or(DEFAULT_MTLS_CACHE_CAPACITY);

        let config = PluginConfig {
            forward_headers,
            extract_headers,
            timeout_ms,
            fail_open,
            method,
            allow_plaintext,
            mtls_cache_capacity,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be greater than 0".into());
        }
        validate_method(&self.method)?;
        Ok(())
    }

    pub fn validate_auth_url(
        &self,
        url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(format!("auth_url must start with https:// or http://, got: {url}").into());
        }
        if url.starts_with("http://") && !self.allow_plaintext {
            return Err("auth_url uses http:// but allow_plaintext is false; \
                 set allow_plaintext = true to allow plaintext connections"
                .into());
        }
        Ok(())
    }

    pub fn config_schema() -> &'static str {
        r#"{
            "type": "object",
            "properties": {
                "allow_plaintext": {
                    "type": "boolean",
                    "description": "Allow http:// auth URLs (default: false, https:// enforced)"
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
                    "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "description": "Default HTTP method for auth subrequest. Per-request overrides land via the `method` SPOE message arg (auth-method annotation in the chart). Body-having methods (POST/PUT/PATCH) go out with an empty body — the plugin does not forward the original request body."
                },
                "mtls_cache_capacity": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Maximum number of distinct (cert, key) pairs to keep cached for mTLS auth requests. FIFO eviction past this. Each entry is ~few KB. Default 64. 0 disables caching (an Agent is built fresh per mTLS request — useful for tests, expensive in production)."
                }
            },
            "additionalProperties": false
        }"#
    }
}
