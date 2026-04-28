use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use haproxy_spoa_hub_plugin_api::{
    ProcessingResult, SpoeMessage, SpoeValue, Tuple2, define_plugin,
};

use crate::auth::{self, RequestParams};
use crate::config::{PluginConfig, validate_method};

static CONFIG: OnceLock<PluginConfig> = OnceLock::new();
static AGENT: OnceLock<ureq::Agent> = OnceLock::new();

#[derive(Debug)]
struct ExternalAuthPlugin;

define_plugin!(ExternalAuthPlugin, {
    fn new() -> Self {
        ExternalAuthPlugin
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context)?;

        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(config.timeout_ms)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .new_agent();

        CONFIG.set(config).ok();
        AGENT.set(agent).ok();
        Ok(())
    }

    fn name(&self) -> &str {
        "external-auth"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn process(
        &self,
        message: &SpoeMessage,
    ) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
        let config = CONFIG
            .get()
            .ok_or("plugin not initialized: config missing")?;
        let agent = AGENT.get().ok_or("plugin not initialized: agent missing")?;

        let extracted = extract_message_args(message);

        let auth_url = extracted.auth_url.ok_or(
            "missing required SPOE argument: auth_url — \
             HAProxy must pass auth_url in the spoe-message args",
        )?;

        config.validate_auth_url(&auth_url)?;

        // Per-request overrides (auth-method / auth-headers-request /
        // auth-response-headers annotations) fall back to plugin-level
        // config when the SPOE arg is absent or empty.
        let resolved_method = match extracted.method {
            Some(m) => {
                let upper = m.to_uppercase();
                validate_method(&upper)?;
                upper
            }
            None => config.method.clone(),
        };
        let resolved_forward = extracted
            .forward_headers
            .unwrap_or_else(|| config.forward_headers.clone());
        let resolved_extract = extracted
            .extract_headers
            .unwrap_or_else(|| config.extract_headers.clone());

        let params = RequestParams {
            method: &resolved_method,
            forward_headers: &resolved_forward,
            extract_headers: &resolved_extract,
        };

        let decision = auth::send_auth_request(
            agent,
            config,
            &params,
            &auth_url,
            &extracted.path,
            &extracted.headers,
        );

        log::info!(
            "external-auth: path={} auth_url={} method={} allowed={} status={}",
            extracted.path,
            auth_url,
            resolved_method,
            decision.allowed,
            decision.status_code,
        );

        Ok(ProcessingResult {
            variables: decision.to_variables(),
        })
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }
});

/// Parsed SPOE message contents. Per-request overrides
/// (`method` / `forward_headers` / `extract_headers`) are `Some(...)`
/// only when the message included a non-empty arg; the caller is
/// responsible for falling back to plugin-level config when `None`.
pub struct ExtractedArgs {
    pub auth_url: Option<String>,
    pub path: String,
    pub method: Option<String>,
    pub forward_headers: Option<Vec<String>>,
    pub extract_headers: Option<Vec<String>>,
    pub headers: HashMap<String, String>,
}

fn extract_message_args(message: &SpoeMessage) -> ExtractedArgs {
    let auth_url = message.get_string("auth_url").map(String::from);
    let path = message.get_string("path").unwrap_or_default().to_string();
    let method = message
        .get_string("method")
        .filter(|s| !s.is_empty())
        .map(String::from);
    let forward_headers = message
        .get_string("forward_headers")
        .and_then(parse_header_list);
    let extract_headers = message
        .get_string("extract_headers")
        .and_then(parse_header_list);

    let mut headers = HashMap::new();
    for Tuple2(key, value) in message.args.iter() {
        let k = key.as_str();
        if let Some(header_name) = k.strip_prefix("hdr_") {
            if let SpoeValue::String(s) = value {
                headers.insert(header_name.to_string(), s.as_str().to_string());
            }
        }
    }

    ExtractedArgs {
        auth_url,
        path,
        method,
        forward_headers,
        extract_headers,
        headers,
    }
}

/// Parse a comma-separated header list (e.g. `"X-User, X-Email"`) into
/// lowercase entries, mirroring how plugin-level config normalises names.
/// Returns `None` for an empty input so the caller can fall back to config.
fn parse_header_list(s: &str) -> Option<Vec<String>> {
    let entries: Vec<String> = s
        .split(',')
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_header_list;

    #[test]
    fn parse_header_list_normalises_and_trims() {
        assert_eq!(
            parse_header_list("X-User, X-Email"),
            Some(vec!["x-user".to_string(), "x-email".to_string()])
        );
    }

    #[test]
    fn parse_header_list_drops_empties() {
        assert_eq!(
            parse_header_list("X-User,,  ,X-Email"),
            Some(vec!["x-user".to_string(), "x-email".to_string()])
        );
    }

    #[test]
    fn parse_header_list_returns_none_on_blank() {
        assert!(parse_header_list("").is_none());
        assert!(parse_header_list("   ,  ,").is_none());
    }
}
