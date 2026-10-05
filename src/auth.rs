use std::collections::HashMap;

use haproxy_spoa_hub_plugin_api::{RVec, SpoeValue, TxnVariable};

use crate::config::PluginConfig;

/// The one spelling header names are compared in: lowercase, `-` as separator.
/// SPOE argument names cannot contain `-`, so HAProxy captures `X-Api-Key` as
/// `hdr_x_api_key` while `forward_headers` lists it as `X-Api-Key`.
#[must_use]
pub fn canonical_header_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Resolved per-request parameters. Each field is either set by a SPOE
/// message argument or falls back to the plugin-level config. The plugin
/// builds one of these per request before calling `send_auth_request`,
/// which lets HAPTIC chart users set per-ingress overrides for
/// `auth-method` / `auth-headers-request` / `auth-response-headers`
/// without restarting the plugin.
#[derive(Debug)]
pub struct RequestParams<'a> {
    pub method: &'a str,
    /// Entries in [`canonical_header_name`] form.
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

/// `headers` is keyed by [`canonical_header_name`].
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
    // the allowed list in config.rs. Body-less and body-having methods
    // need different ureq builders; for body-having methods we send an
    // empty body since the plugin doesn't forward the original payload.
    // The match on params.method covers each, with .call() / .send(())
    // returning a uniform Result<Response, Error>.
    // Body-having methods (POST/PUT/PATCH) go out with an empty body —
    // the plugin does not forward the original request payload. ureq's
    // WithBody builder requires .send(...), so we pass an empty slice;
    // the WithoutBody builder uses .call(). Each arm applies forward
    // headers via apply_headers_* before calling.
    let response_result = match params.method {
        "HEAD" => apply_headers_no_body(agent.head(&url), params, headers).call(),
        "DELETE" => apply_headers_no_body(agent.delete(&url), params, headers).call(),
        "OPTIONS" => apply_headers_no_body(agent.options(&url), params, headers).call(),
        "POST" => apply_headers_with_body(agent.post(&url), params, headers).send(&[][..]),
        "PUT" => apply_headers_with_body(agent.put(&url), params, headers).send(&[][..]),
        "PATCH" => apply_headers_with_body(agent.patch(&url), params, headers).send(&[][..]),
        _ => apply_headers_no_body(agent.get(&url), params, headers).call(),
    };

    match response_result {
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

/// The request headers listed in `forward_headers`. `headers` is keyed by
/// [`canonical_header_name`].
fn forwarded<'h>(
    params: &RequestParams<'_>,
    headers: &'h HashMap<String, String>,
) -> impl Iterator<Item = (&'h str, &'h str)> {
    headers
        .iter()
        .filter(|(name, _)| params.forward_headers.contains(name))
        .map(|(name, value)| (name.as_str(), value.as_str()))
}

/// Apply forward-headers to a ureq WithoutBody builder (GET/HEAD/DELETE).
fn apply_headers_no_body(
    mut request: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    params: &RequestParams<'_>,
    headers: &HashMap<String, String>,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    for (name, value) in forwarded(params, headers) {
        request = request.header(name, value);
    }
    request
}

/// Apply forward-headers to a ureq WithBody builder (POST/PUT/PATCH).
fn apply_headers_with_body(
    mut request: ureq::RequestBuilder<ureq::typestate::WithBody>,
    params: &RequestParams<'_>,
    headers: &HashMap<String, String>,
) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
    for (name, value) in forwarded(params, headers) {
        request = request.header(name, value);
    }
    request
}

fn classify_response(
    config: &PluginConfig,
    params: &RequestParams<'_>,
    response: http::Response<ureq::Body>,
) -> AuthDecision {
    let status = response.status().as_u16() as u32;
    let headers = response.headers();

    // Extract configured response headers regardless of outcome. Auth
    // services frequently return:
    //   - X-Auth-User / X-Auth-Roles on 2xx (forward to upstream)
    //   - WWW-Authenticate on 401 (forward to client to drive challenge)
    //   - X-Error-Reason on 4xx/5xx (forward to client for diagnostics)
    // The chart side decides which decisions get which headers; the
    // plugin's job is just to surface them. Old senders that don't set
    // extract_headers see this as a no-op (extracted is always empty).
    let extracted = extract_headers(params.extract_headers, headers);

    if (200..300).contains(&status) {
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
            extracted_headers: extracted,
            error: None,
        }
    } else if status == 401 || status == 403 {
        AuthDecision {
            allowed: false,
            status_code: status,
            redirect_url: None,
            extracted_headers: extracted,
            error: None,
        }
    } else {
        // 5xx or other — apply failure policy. Headers extracted above
        // still flow through so operators can wire e.g. X-Error-Reason
        // even on the failure-policy path.
        let msg = format!("auth service returned {status}");
        log_failure(config, &msg);
        let mut decision = apply_failure_policy(config, status, &msg);
        decision.extracted_headers = extracted;
        decision
    }
}

fn extract_headers(names: &[String], response_headers: &http::HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for header_name in names {
        let header_key = header_name.replace('_', "-");
        if let Some(value) = response_headers.get(header_key.as_str()) {
            if let Ok(val_str) = value.to_str() {
                out.push((header_name.clone(), val_str.to_string()));
            }
        }
    }
    out
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
