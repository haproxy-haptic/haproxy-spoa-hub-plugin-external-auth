use std::collections::HashMap;

use haproxy_spoa_hub_plugin_api::{RVec, SpoeValue, TxnVariable};

use crate::config::PluginConfig;

/// Resolved per-request parameters. Each field is either set by a SPOE
/// message argument or falls back to the plugin-level config. The plugin
/// builds one of these per request before calling `send_auth_request`,
/// which lets HAPTIC chart users set per-ingress overrides for
/// `auth-method` / `auth-headers-request` / `auth-response-headers`
/// without restarting the plugin.
#[derive(Debug)]
pub struct RequestParams<'a> {
    pub method: &'a str,
    pub forward_headers: &'a [String],
    pub extract_headers: &'a [String],
}

impl<'a> RequestParams<'a> {
    /// Borrow all three fields from the plugin-level config — the shape
    /// used when no SPOE message arg overrides them. Convenient for
    /// tests and for the plugin's "no override" fast path.
    #[must_use]
    pub fn from_config(config: &'a PluginConfig) -> Self {
        Self {
            method: &config.method,
            forward_headers: &config.forward_headers,
            extract_headers: &config.extract_headers,
        }
    }
}

#[derive(Debug)]
pub struct AuthDecision {
    pub allowed: bool,
    pub status_code: u32,
    pub redirect_url: Option<String>,
    pub extracted_headers: Vec<(String, String)>,
    pub error: Option<String>,
}

impl AuthDecision {
    pub fn to_variables(&self) -> RVec<TxnVariable> {
        let mut vars = RVec::with_capacity(3 + self.extracted_headers.len());

        vars.push(TxnVariable::transaction(
            "allowed",
            SpoeValue::Bool(self.allowed),
        ));
        vars.push(TxnVariable::transaction(
            "status_code",
            SpoeValue::Uint32(self.status_code),
        ));

        if let Some(ref url) = self.redirect_url {
            vars.push(TxnVariable::transaction(
                "redirect_url",
                SpoeValue::String(url.as_str().into()),
            ));
        }

        if let Some(ref err) = self.error {
            vars.push(TxnVariable::transaction(
                "error",
                SpoeValue::String(err.as_str().into()),
            ));
        }

        for (name, value) in &self.extracted_headers {
            let var_name = name.replace('-', "_");
            vars.push(TxnVariable::transaction(
                var_name.as_str(),
                SpoeValue::String(value.as_str().into()),
            ));
        }

        vars
    }
}

pub fn send_auth_request(
    agent: &ureq::Agent,
    config: &PluginConfig,
    params: &RequestParams<'_>,
    auth_url: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> AuthDecision {
    let url = format!("{auth_url}{path}");

    // Method strings reach us already upper-cased and validated against
    // the allowed list in config.rs (currently GET / HEAD only).
    let mut request = match params.method {
        "HEAD" => agent.head(&url),
        _ => agent.get(&url),
    };

    // Forward configured headers. Keys from extract_message_args are already
    // lowercase (stripped hdr_ prefix), matching forward_headers entries.
    for (name, value) in headers {
        if params.forward_headers.iter().any(|h| h == name) {
            let header_name = name.replace('_', "-");
            request = request.header(&header_name, value);
        }
    }

    // Agent is configured with http_status_as_error(false) and max_redirects(0),
    // so all responses come through Ok() and we handle status codes ourselves.
    match request.call() {
        Ok(response) => classify_response(config, params, response),
        Err(ureq::Error::Timeout(timeout)) => {
            let msg = format!("auth subrequest timed out: {timeout}");
            log_failure(config, &msg);
            apply_failure_policy(config, 0, &msg)
        }
        Err(err) => {
            let msg = format!("auth subrequest failed: {err}");
            log_failure(config, &msg);
            apply_failure_policy(config, 0, &msg)
        }
    }
}

fn classify_response(
    config: &PluginConfig,
    params: &RequestParams<'_>,
    response: http::Response<ureq::Body>,
) -> AuthDecision {
    let status = response.status().as_u16() as u32;
    let headers = response.headers();

    if (200..300).contains(&status) {
        // 2xx — allowed, extract per-request response headers
        let mut extracted = Vec::new();
        for header_name in params.extract_headers {
            let header_key = header_name.replace('_', "-");
            if let Some(value) = headers.get(header_key.as_str()) {
                if let Ok(val_str) = value.to_str() {
                    extracted.push((header_name.clone(), val_str.to_string()));
                }
            }
        }
        AuthDecision {
            allowed: true,
            status_code: status,
            redirect_url: None,
            extracted_headers: extracted,
            error: None,
        }
    } else if (300..400).contains(&status) {
        // 3xx — denial with redirect
        let location = headers
            .get("location")
            .and_then(|v: &http::HeaderValue| v.to_str().ok())
            .map(|s| s.to_string());
        AuthDecision {
            allowed: false,
            status_code: status,
            redirect_url: location,
            extracted_headers: vec![],
            error: None,
        }
    } else if status == 401 || status == 403 {
        // Auth denial
        AuthDecision {
            allowed: false,
            status_code: status,
            redirect_url: None,
            extracted_headers: vec![],
            error: None,
        }
    } else {
        // 5xx or other — apply failure policy
        let msg = format!("auth service returned {status}");
        log_failure(config, &msg);
        apply_failure_policy(config, status, &msg)
    }
}

fn apply_failure_policy(config: &PluginConfig, status_code: u32, error_msg: &str) -> AuthDecision {
    AuthDecision {
        allowed: config.fail_open,
        status_code,
        redirect_url: None,
        extracted_headers: vec![],
        error: Some(error_msg.to_string()),
    }
}

fn log_failure(config: &PluginConfig, msg: &str) {
    if config.fail_open {
        log::warn!("external-auth: {msg} (fail-open: allowing request)");
    } else {
        log::error!("external-auth: {msg} (fail-closed: denying request)");
    }
}
