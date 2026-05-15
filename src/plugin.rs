use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use haproxy_spoa_hub_plugin_api::{
    MetricRecorder, ProcessingResult, SpoeMessage, SpoeValue, Tuple2, define_plugin,
};

use crate::auth::{self, RequestParams};
use crate::config::{PluginConfig, validate_method};

static CONFIG: OnceLock<PluginConfig> = OnceLock::new();
static AGENT: OnceLock<ureq::Agent> = OnceLock::new();

/// Plugin-scoped metric recorder. The `define_plugin!` `metrics_static`
/// arm below binds the hub's v2 recorder here; with a v0.5.x hub the
/// install never fires and emissions are silent no-ops.
static METRICS: MetricRecorder = MetricRecorder::new();

/// Bounded FIFO cache of mTLS-configured ureq Agents. ureq's TLS config
/// is fixed at Agent construction (it owns the rustls ClientConfig),
/// so per-request mTLS means a per-cert Agent. Keyed by the SipHash of
/// the (cert PEM, key PEM) pair — collision-resistant enough for an
/// in-process map (no cryptographic guarantee needed).
///
/// Eviction policy is FIFO with a hard cap supplied by config
/// (`mtls_cache_capacity`, default 64). FIFO is the right shape for
/// the cert-rotation workload: rotated-out certs stop being used and
/// just sit at the head of the queue until new inserts push them out.
/// LRU would behave identically here (old cert is also least-recently-
/// used) but adds bookkeeping cost on the hot read path. There is no
/// time-based TTL: a cert that's still in active use should not be
/// evicted just because it's been around a while, and the pod restart
/// cadence (weeks) bounds long-tail leaks.
///
/// Capacity is fixed at first-use time (when the OnceLock initialises
/// the cache). Changing `mtls_cache_capacity` requires a pod restart.
struct MtlsAgentCache {
    map: HashMap<u64, ureq::Agent>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl MtlsAgentCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&self, key: u64) -> Option<ureq::Agent> {
        self.map.get(&key).cloned()
    }

    /// Insert agent under `key` if absent; evict the oldest entry first
    /// when at capacity. No-op if the key is already present (concurrent
    /// inserters race on the slow path; first writer wins). When
    /// `capacity == 0`, every insert is rejected — the caller's own
    /// freshly-built Agent flows through as `Cow::Owned`.
    fn insert_if_absent(&mut self, key: u64, agent: ureq::Agent) {
        if self.capacity == 0 || self.map.contains_key(&key) {
            return;
        }
        while self.map.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.map.remove(&oldest);
                }
                None => break,
            }
        }
        self.order.push_back(key);
        self.map.insert(key, agent);
    }
}

static MTLS_AGENT_CACHE: OnceLock<RwLock<MtlsAgentCache>> = OnceLock::new();

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

        // mTLS: if the request carries client_cert + client_key SPOE args
        // (set by the chart's auth-tls-cert-secret annotation), build (or
        // reuse a cached) ureq Agent with those creds. Otherwise fall back
        // to the shared default Agent built in init().
        let resolved_agent = agent_for_request(
            agent,
            config,
            extracted.client_cert.as_deref(),
            extracted.client_key.as_deref(),
        )?;

        let started = std::time::Instant::now();
        let decision = auth::send_auth_request(
            &resolved_agent,
            config,
            &params,
            &auth_url,
            &extracted.path,
            &extracted.headers,
        );
        let elapsed = started.elapsed();

        log::info!(
            "external-auth: path={} auth_url={} method={} allowed={} status={}",
            extracted.path,
            auth_url,
            resolved_method,
            decision.allowed,
            decision.status_code,
        );

        // Hub prefixes everything with `plugin_external-auth_`.
        // Outcome captures the boolean decision; status_class buckets
        // the auth backend's HTTP status. Together they answer
        // "is auth working? are denials coming from real 4xx/5xx,
        // an error, or a transient network failure?" in a single
        // counter per outcome.
        let outcome = if decision.allowed {
            "allowed"
        } else {
            "denied"
        };
        let status_class = match decision.status_code {
            0 => "none",
            100..=199 => "1xx",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            500..=599 => "5xx",
            _ => "other",
        };
        METRICS.counter(
            "auth_requests_total",
            &[("outcome", outcome), ("status_class", status_class)],
            1,
        );
        METRICS.histogram("auth_duration_seconds", &[], elapsed.as_secs_f64());

        Ok(ProcessingResult {
            variables: decision.to_variables(),
        })
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }

    metrics_static = METRICS;
});

/// Parsed SPOE message contents. Per-request overrides
/// (`method` / `forward_headers` / `extract_headers`) are `Some(...)`
/// only when the message included a non-empty arg; the caller is
/// responsible for falling back to plugin-level config when `None`.
/// `client_cert` and `client_key` come from the auth-tls-cert-secret
/// annotation on the chart side and drive per-ingress mTLS to the
/// auth service (both must be present to enable mTLS).
pub struct ExtractedArgs {
    pub auth_url: Option<String>,
    pub path: String,
    pub method: Option<String>,
    pub forward_headers: Option<Vec<String>>,
    pub extract_headers: Option<Vec<String>>,
    pub headers: HashMap<String, String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
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
    let client_cert = message
        .get_string("client_cert")
        .filter(|s| !s.is_empty())
        .map(String::from);
    let client_key = message
        .get_string("client_key")
        .filter(|s| !s.is_empty())
        .map(String::from);

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
        client_cert,
        client_key,
    }
}

/// Build (or fetch from cache) a ureq Agent configured with the given
/// client certificate. Returns the default Agent when no cert is set.
fn agent_for_request<'a>(
    default: &'a ureq::Agent,
    config: &PluginConfig,
    client_cert: Option<&str>,
    client_key: Option<&str>,
) -> Result<std::borrow::Cow<'a, ureq::Agent>, Box<dyn std::error::Error + Send + Sync>> {
    let (Some(cert_pem), Some(key_pem)) = (client_cert, client_key) else {
        return Ok(std::borrow::Cow::Borrowed(default));
    };

    let mut hasher = DefaultHasher::new();
    cert_pem.hash(&mut hasher);
    key_pem.hash(&mut hasher);
    let cache_key = hasher.finish();

    let cache = MTLS_AGENT_CACHE
        .get_or_init(|| RwLock::new(MtlsAgentCache::new(config.mtls_cache_capacity)));
    {
        // Recover from a poisoned lock by accepting the inner state.
        // The cache holds clones of Agents that are independently usable;
        // the worst that a poisoned acquisition can do is return a stale
        // entry or miss a recent insert (triggering one extra rebuild).
        // Crashing every subsequent request would be much worse.
        let read = cache.read().unwrap_or_else(|e| e.into_inner());
        if let Some(agent) = read.get(cache_key) {
            return Ok(std::borrow::Cow::Owned(agent));
        }
    }

    // Slow path: parse PEM, build Agent, cache. Holds the write lock
    // briefly enough that contention should be minimal in practice. If
    // a concurrent writer beat us to it, insert_if_absent is a no-op
    // and we return our locally-built Agent (cheap clone of an Arc).
    let agent = build_mtls_agent(config, cert_pem, key_pem)?;
    let mut write = cache.write().unwrap_or_else(|e| e.into_inner());
    write.insert_if_absent(cache_key, agent.clone());
    Ok(std::borrow::Cow::Owned(agent))
}

fn build_mtls_agent(
    config: &PluginConfig,
    cert_pem: &str,
    key_pem: &str,
) -> Result<ureq::Agent, Box<dyn std::error::Error + Send + Sync>> {
    use ureq::tls::{Certificate, ClientCert, PrivateKey, TlsConfig};

    let cert = Certificate::from_pem(cert_pem.as_bytes())
        .map_err(|e| format!("failed to parse client cert PEM: {e}"))?;
    let key = PrivateKey::from_pem(key_pem.as_bytes())
        .map_err(|e| format!("failed to parse client key PEM: {e}"))?;
    let client_cert = ClientCert::new_with_certs(&[cert], key);

    let tls_config = TlsConfig::builder().client_cert(Some(client_cert)).build();

    Ok(ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(config.timeout_ms)))
        .max_redirects(0)
        .http_status_as_error(false)
        .tls_config(tls_config)
        .build()
        .new_agent())
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
    use super::{MtlsAgentCache, agent_for_request, parse_header_list};
    use crate::config::{DEFAULT_MTLS_CACHE_CAPACITY, PluginConfig};
    use std::time::Duration;

    fn test_config() -> PluginConfig {
        PluginConfig {
            forward_headers: vec![],
            extract_headers: vec![],
            timeout_ms: 5000,
            fail_open: false,
            method: "GET".to_string(),
            allow_plaintext: false,
            mtls_cache_capacity: DEFAULT_MTLS_CACHE_CAPACITY,
        }
    }

    fn test_default_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(5000)))
            .build()
            .new_agent()
    }

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

    #[test]
    fn agent_for_request_returns_default_when_no_certs() {
        let default = test_default_agent();
        let config = test_config();
        let resolved = agent_for_request(&default, &config, None, None).unwrap();
        assert!(
            matches!(resolved, std::borrow::Cow::Borrowed(_)),
            "expected the default agent (Borrowed) when no certs are supplied"
        );
    }

    #[test]
    fn agent_for_request_returns_default_when_only_cert_present() {
        // Both cert and key must be present to enable mTLS — having one
        // without the other should silently fall back to the default agent
        // rather than erroring, matching how the chart annotation supplies
        // them as a pair from a single Secret.
        let default = test_default_agent();
        let config = test_config();
        let resolved = agent_for_request(&default, &config, Some("cert"), None).unwrap();
        assert!(matches!(resolved, std::borrow::Cow::Borrowed(_)));
        let resolved = agent_for_request(&default, &config, None, Some("key")).unwrap();
        assert!(matches!(resolved, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn mtls_cache_evicts_oldest_when_full() {
        // Use a small explicit capacity so the test is fast and the
        // assertion pattern is obvious. Same FIFO logic applies at any cap.
        let cap: usize = 4;
        let mut cache = MtlsAgentCache::new(cap);
        let agent = test_default_agent();

        for i in 0..cap as u64 {
            cache.insert_if_absent(i, agent.clone());
        }
        assert_eq!(cache.map.len(), cap);
        assert!(cache.get(0).is_some(), "key 0 present before overflow");

        let overflow_key = cap as u64;
        cache.insert_if_absent(overflow_key, agent.clone());
        assert_eq!(cache.map.len(), cap);
        assert!(
            cache.get(0).is_none(),
            "oldest key should have been evicted"
        );
        assert!(
            cache.get(overflow_key).is_some(),
            "new key should be cached"
        );
        assert!(
            cache.get(cap as u64 - 1).is_some(),
            "second-oldest should remain"
        );
    }

    #[test]
    fn mtls_cache_insert_if_absent_is_idempotent() {
        let mut cache = MtlsAgentCache::new(8);
        cache.insert_if_absent(42, test_default_agent());
        cache.insert_if_absent(42, test_default_agent());
        assert_eq!(cache.map.len(), 1);
        assert_eq!(
            cache.order.len(),
            1,
            "duplicate key must not grow order queue"
        );
    }

    #[test]
    fn mtls_cache_capacity_zero_disables_caching() {
        let mut cache = MtlsAgentCache::new(0);
        cache.insert_if_absent(1, test_default_agent());
        cache.insert_if_absent(2, test_default_agent());
        assert!(cache.get(1).is_none(), "capacity 0 must reject all inserts");
        assert!(cache.get(2).is_none());
        assert_eq!(cache.map.len(), 0);
    }

    #[test]
    fn agent_for_request_errors_on_bad_pem() {
        let default = test_default_agent();
        let config = test_config();
        let err = agent_for_request(
            &default,
            &config,
            Some("not a valid PEM"),
            Some("also not a valid PEM"),
        )
        .expect_err("expected a parse error for bad PEM");
        let msg = err.to_string();
        assert!(
            msg.contains("PEM") || msg.contains("pem"),
            "expected error message to mention PEM, got: {msg}"
        );
    }
}
