use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use abi_stable::std_types::Tuple2;
use haproxy_spoa_hub_plugin_api::{ProcessingResult, SpoeMessage, SpoeValue, define_plugin};

use crate::auth;
use crate::config::PluginConfig;

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

        let (auth_url, path, headers) = extract_message_args(message);

        let auth_url = auth_url.ok_or(
            "missing required SPOE argument: auth_url — \
             HAProxy must pass auth_url in the spoe-message args",
        )?;

        config.validate_auth_url(&auth_url)?;

        let decision = auth::send_auth_request(agent, config, &auth_url, &path, &headers);

        log::info!(
            "external-auth: path={} auth_url={} allowed={} status={}",
            path,
            auth_url,
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

fn extract_message_args(
    message: &SpoeMessage,
) -> (Option<String>, String, HashMap<String, String>) {
    let mut auth_url = None;
    let mut path = String::new();
    let mut headers = HashMap::new();

    for Tuple2(key, value) in message.args.iter() {
        let k = key.as_str();
        match k {
            "auth_url" => {
                if let SpoeValue::String(s) = value {
                    auth_url = Some(s.as_str().to_string());
                }
            }
            "path" => {
                if let SpoeValue::String(s) = value {
                    path = s.as_str().to_string();
                }
            }
            _ if k.starts_with("hdr_") => {
                if let SpoeValue::String(s) = value {
                    let header_name = k.strip_prefix("hdr_").unwrap().to_string();
                    headers.insert(header_name, s.as_str().to_string());
                }
            }
            _ => {}
        }
    }

    (auth_url, path, headers)
}
