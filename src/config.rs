use haproxy_spoa_hub_plugin_api::PluginContext;

const DEFAULT_FORWARD_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-uri",
];

#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub forward_headers: Vec<String>,
    pub extract_headers: Vec<String>,
    pub timeout_ms: u64,
    pub fail_open: bool,
    pub method: String,
    pub allow_plaintext: bool,
}

impl PluginConfig {
    pub fn from_context(
        context: &PluginContext,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let allow_plaintext = context
            .config
            .get("allow_plaintext")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let timeout_ms = context
            .config
            .get("timeout_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64)
            .unwrap_or(5000);

        let fail_open = context
            .config
            .get("fail_open")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let method = context
            .config
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();

        let forward_headers = context
            .config
            .get("forward_headers")
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
            .config
            .get("extract_headers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        let config = PluginConfig {
            forward_headers,
            extract_headers,
            timeout_ms,
            fail_open,
            method,
            allow_plaintext,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be greater than 0".into());
        }
        if self.method != "GET" && self.method != "HEAD" {
            return Err(format!("method must be GET or HEAD, got: {}", self.method).into());
        }
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
                    "enum": ["GET", "HEAD"],
                    "description": "HTTP method for auth subrequest"
                }
            },
            "additionalProperties": false
        }"#
    }
}
