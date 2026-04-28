use std::collections::HashMap;
use std::time::Duration;

use external_auth_plugin::auth::{AuthDecision, RequestParams, send_auth_request};
use external_auth_plugin::config::PluginConfig;
use haproxy_spoa_hub_plugin_api::{SpoeValue, VarScope};

fn make_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn make_config() -> PluginConfig {
    PluginConfig {
        forward_headers: vec![
            "authorization".into(),
            "cookie".into(),
            "x-forwarded-for".into(),
            "x-forwarded-proto".into(),
            "x-forwarded-host".into(),
            "x-forwarded-uri".into(),
        ],
        extract_headers: vec![],
        timeout_ms: 5000,
        fail_open: false,
        method: "GET".into(),
        allow_plaintext: true,
        mtls_cache_capacity: 64,
    }
}

// ============================================================================
// US1: AuthDecision::to_variables()
// ============================================================================

#[test]
fn to_variables_allowed() {
    let decision = AuthDecision {
        allowed: true,
        status_code: 200,
        redirect_url: None,
        extracted_headers: vec![],
        error: None,
    };
    let vars = decision.to_variables();
    assert_eq!(vars.len(), 2);
    assert_eq!(vars[0].name.as_str(), "allowed");
    assert!(matches!(vars[0].value, SpoeValue::Bool(true)));
    assert_eq!(vars[0].scope, VarScope::Transaction);
    assert_eq!(vars[1].name.as_str(), "status_code");
    assert!(matches!(vars[1].value, SpoeValue::Uint32(200)));
}

#[test]
fn to_variables_denied() {
    let decision = AuthDecision {
        allowed: false,
        status_code: 401,
        redirect_url: None,
        extracted_headers: vec![],
        error: None,
    };
    let vars = decision.to_variables();
    assert_eq!(vars.len(), 2);
    assert!(matches!(vars[0].value, SpoeValue::Bool(false)));
    assert!(matches!(vars[1].value, SpoeValue::Uint32(401)));
}

#[test]
fn to_variables_with_redirect() {
    let decision = AuthDecision {
        allowed: false,
        status_code: 302,
        redirect_url: Some("https://login.example.com/".into()),
        extracted_headers: vec![],
        error: None,
    };
    let vars = decision.to_variables();
    assert_eq!(vars.len(), 3);
    assert_eq!(vars[2].name.as_str(), "redirect_url");
    if let SpoeValue::String(ref s) = vars[2].value {
        assert_eq!(s.as_str(), "https://login.example.com/");
    } else {
        panic!("expected String");
    }
}

#[test]
fn to_variables_with_error() {
    let decision = AuthDecision {
        allowed: false,
        status_code: 0,
        redirect_url: None,
        extracted_headers: vec![],
        error: Some("connection refused".into()),
    };
    let vars = decision.to_variables();
    assert_eq!(vars.len(), 3);
    assert_eq!(vars[2].name.as_str(), "error");
}

// US4: extracted headers with hyphen-to-underscore mapping
#[test]
fn to_variables_extracted_headers() {
    let decision = AuthDecision {
        allowed: true,
        status_code: 200,
        redirect_url: None,
        extracted_headers: vec![
            ("x-auth-user".into(), "alice".into()),
            ("x-auth-roles".into(), "admin,editor".into()),
        ],
        error: None,
    };
    let vars = decision.to_variables();
    // allowed + status_code + 2 headers
    assert_eq!(vars.len(), 4);
    assert_eq!(vars[2].name.as_str(), "x_auth_user");
    if let SpoeValue::String(ref s) = vars[2].value {
        assert_eq!(s.as_str(), "alice");
    } else {
        panic!("expected String");
    }
    assert_eq!(vars[3].name.as_str(), "x_auth_roles");
}

// ============================================================================
// US1: send_auth_request with mock server — 200 and 401
// ============================================================================

#[test]
fn auth_request_200_allowed() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        req.respond(tiny_http::Response::from_string("ok").with_status_code(200))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(decision.allowed);
    assert_eq!(decision.status_code, 200);
    assert!(decision.error.is_none());

    handle.join().unwrap();
}

#[test]
fn auth_request_401_denied() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        req.respond(tiny_http::Response::from_string("unauthorized").with_status_code(401))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.status_code, 401);
    assert!(decision.error.is_none());

    handle.join().unwrap();
}

#[test]
fn auth_request_403_denied() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        req.respond(tiny_http::Response::from_string("forbidden").with_status_code(403))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.status_code, 403);

    handle.join().unwrap();
}

// ============================================================================
// US2: Header forwarding
// ============================================================================

#[test]
fn forwards_default_headers() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        // Verify authorization and cookie headers were forwarded
        let has_auth = req.headers().iter().any(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("authorization")
                && h.value.as_str() == "Bearer token123"
        });
        let has_cookie = req.headers().iter().any(|h| {
            h.field.as_str().as_str().eq_ignore_ascii_case("cookie")
                && h.value.as_str() == "session=abc"
        });
        assert!(has_auth, "Authorization header not forwarded");
        assert!(has_cookie, "Cookie header not forwarded");
        req.respond(tiny_http::Response::from_string("ok").with_status_code(200))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let mut headers = HashMap::new();
    headers.insert("authorization".into(), "Bearer token123".into());
    headers.insert("cookie".into(), "session=abc".into());

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(decision.allowed);

    handle.join().unwrap();
}

#[test]
fn custom_forward_headers_filters() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        // Only x-custom-token should be forwarded
        let has_custom = req.headers().iter().any(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("x-custom-token")
        });
        let has_auth = req.headers().iter().any(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("authorization")
        });
        assert!(has_custom, "X-Custom-Token should be forwarded");
        assert!(!has_auth, "Authorization should NOT be forwarded");
        req.respond(tiny_http::Response::from_string("ok").with_status_code(200))
            .unwrap();
    });

    let agent = make_agent();
    let mut config = make_config();
    config.forward_headers = vec!["x-custom-token".into()];

    let mut headers = HashMap::new();
    headers.insert("authorization".into(), "Bearer token123".into());
    headers.insert("x-custom-token".into(), "my-token".into());

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(decision.allowed);

    handle.join().unwrap();
}

// ============================================================================
// US3: Error handling and failure policy
// ============================================================================

#[test]
fn unreachable_fail_closed() {
    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    // Use a port that's almost certainly not listening
    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        "http://127.0.0.1:19999",
        "/test",
        &headers,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.status_code, 0);
    assert!(decision.error.is_some());
}

#[test]
fn unreachable_fail_open() {
    let agent = make_agent();
    let mut config = make_config();
    config.fail_open = true;
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        "http://127.0.0.1:19999",
        "/test",
        &headers,
    );
    assert!(decision.allowed);
    assert_eq!(decision.status_code, 0);
    assert!(decision.error.is_some());
}

#[test]
fn server_error_500_fail_closed() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        req.respond(tiny_http::Response::from_string("error").with_status_code(500))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.status_code, 500);
    assert!(decision.error.is_some());

    handle.join().unwrap();
}

#[test]
fn timeout_fail_closed() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    // Server never responds — agent timeout will fire
    let _handle = std::thread::spawn(move || {
        let _req = server.recv().unwrap();
        std::thread::sleep(Duration::from_secs(10));
    });

    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(100)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent();
    let config = make_config();
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(!decision.allowed);
    assert!(decision.error.is_some());
}

// ============================================================================
// US4: Response header extraction
// ============================================================================

#[test]
fn extracts_response_headers() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let response = tiny_http::Response::from_string("ok")
            .with_status_code(200)
            .with_header(tiny_http::Header::from_bytes("X-Auth-User", "alice").unwrap())
            .with_header(tiny_http::Header::from_bytes("X-Auth-Roles", "admin,editor").unwrap());
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let mut config = make_config();
    config.extract_headers = vec!["x-auth-user".into(), "x-auth-roles".into()];

    let headers = HashMap::new();
    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(decision.allowed);
    assert_eq!(decision.extracted_headers.len(), 2);
    assert_eq!(
        decision.extracted_headers[0],
        ("x-auth-user".to_string(), "alice".to_string())
    );
    assert_eq!(
        decision.extracted_headers[1],
        ("x-auth-roles".to_string(), "admin,editor".to_string())
    );

    handle.join().unwrap();
}

#[test]
fn missing_extract_header_silently_skipped() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        req.respond(tiny_http::Response::from_string("ok").with_status_code(200))
            .unwrap();
    });

    let agent = make_agent();
    let mut config = make_config();
    config.extract_headers = vec!["x-auth-user".into()];

    let headers = HashMap::new();
    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(decision.allowed);
    assert!(decision.extracted_headers.is_empty());

    handle.join().unwrap();
}

// ============================================================================
// 3xx redirect handling
// ============================================================================

#[test]
fn redirect_302_denied_with_location() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let response = tiny_http::Response::from_string("")
            .with_status_code(302)
            .with_header(
                tiny_http::Header::from_bytes("Location", "https://login.example.com/oauth2/start")
                    .unwrap(),
            );
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let decision = send_auth_request(
        &agent,
        &config,
        &RequestParams::from_config(&config),
        &auth_url,
        "/test",
        &headers,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.status_code, 302);
    assert_eq!(
        decision.redirect_url.as_deref(),
        Some("https://login.example.com/oauth2/start")
    );

    handle.join().unwrap();
}

// Per-request overrides — these exercise the new RequestParams shape
// independently of the SPOE-message parsing in plugin.rs. The chart
// uses the overrides to wire the auth-method / auth-headers-request /
// auth-response-headers annotations on a per-ingress basis.

#[test]
fn per_request_method_override_uses_head_when_config_says_get() {
    use std::sync::{Arc, Mutex};
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let observed = Arc::new(Mutex::new(String::new()));
    let observed_thread = Arc::clone(&observed);
    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        *observed_thread.lock().unwrap() = req.method().to_string();
        let response = tiny_http::Response::from_string("").with_status_code(204);
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let config = make_config(); // method: GET
    let headers = HashMap::new();

    let params = RequestParams {
        method: "HEAD",
        forward_headers: &config.forward_headers,
        extract_headers: &config.extract_headers,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    assert!(decision.allowed);

    handle.join().unwrap();
    assert_eq!(*observed.lock().unwrap(), "HEAD");
}

#[test]
fn per_request_forward_headers_override_filters_to_subset() {
    use std::sync::{Arc, Mutex};
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let received_auth = Arc::new(Mutex::new(None::<String>));
    let received_cookie = Arc::new(Mutex::new(None::<String>));
    let auth_t = Arc::clone(&received_auth);
    let cookie_t = Arc::clone(&received_cookie);
    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        for h in req.headers() {
            let name = h.field.as_str().as_str().to_lowercase();
            if name == "authorization" {
                *auth_t.lock().unwrap() = Some(h.value.as_str().to_string());
            } else if name == "cookie" {
                *cookie_t.lock().unwrap() = Some(h.value.as_str().to_string());
            }
        }
        let response = tiny_http::Response::from_string("").with_status_code(204);
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), "Bearer abc".to_string());
    headers.insert("cookie".to_string(), "session=xyz".to_string());

    // Override forwards to authorization only — cookie must NOT be sent
    // even though config.forward_headers includes it.
    let forward = vec!["authorization".to_string()];
    let params = RequestParams {
        method: &config.method,
        forward_headers: &forward,
        extract_headers: &config.extract_headers,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    assert!(decision.allowed);

    handle.join().unwrap();
    assert_eq!(received_auth.lock().unwrap().as_deref(), Some("Bearer abc"));
    assert_eq!(*received_cookie.lock().unwrap(), None);
}

#[test]
fn per_request_extract_headers_override_picks_per_request_set() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let response = tiny_http::Response::from_string("")
            .with_status_code(200)
            .with_header(tiny_http::Header::from_bytes("X-Auth-User", "alice").unwrap())
            .with_header(tiny_http::Header::from_bytes("X-Auth-Roles", "admin").unwrap())
            .with_header(tiny_http::Header::from_bytes("X-Auth-Email", "a@e.com").unwrap());
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let config = make_config(); // extract_headers empty
    let headers = HashMap::new();

    let extract = vec!["x-auth-user".to_string(), "x-auth-email".to_string()];
    let params = RequestParams {
        method: &config.method,
        forward_headers: &config.forward_headers,
        extract_headers: &extract,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    assert!(decision.allowed);

    let names: Vec<&str> = decision
        .extracted_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(names.contains(&"x-auth-user"));
    assert!(names.contains(&"x-auth-email"));
    assert!(!names.contains(&"x-auth-roles"));

    handle.join().unwrap();
}

#[test]
fn post_method_dispatches_with_empty_body() {
    use std::sync::{Arc, Mutex};
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let observed_method = Arc::new(Mutex::new(String::new()));
    let observed_body = Arc::new(Mutex::new(String::new()));
    let m_t = Arc::clone(&observed_method);
    let b_t = Arc::clone(&observed_body);
    let handle = std::thread::spawn(move || {
        let mut req = server.recv().unwrap();
        *m_t.lock().unwrap() = req.method().to_string();
        let mut body = String::new();
        req.as_reader().read_to_string(&mut body).unwrap();
        *b_t.lock().unwrap() = body;
        req.respond(tiny_http::Response::from_string("").with_status_code(200))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let params = RequestParams {
        method: "POST",
        forward_headers: &config.forward_headers,
        extract_headers: &config.extract_headers,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    assert!(decision.allowed);

    handle.join().unwrap();
    assert_eq!(*observed_method.lock().unwrap(), "POST");
    // Empty body — the plugin doesn't forward the original payload.
    assert_eq!(*observed_body.lock().unwrap(), "");
}

#[test]
fn options_method_goes_out_as_options() {
    use std::sync::{Arc, Mutex};
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let observed_method = Arc::new(Mutex::new(String::new()));
    let m_t = Arc::clone(&observed_method);
    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        *m_t.lock().unwrap() = req.method().to_string();
        req.respond(tiny_http::Response::from_string("").with_status_code(200))
            .unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let params = RequestParams {
        method: "OPTIONS",
        forward_headers: &config.forward_headers,
        extract_headers: &config.extract_headers,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    assert!(decision.allowed);

    handle.join().unwrap();
    assert_eq!(
        *observed_method.lock().unwrap(),
        "OPTIONS",
        "OPTIONS must dispatch as OPTIONS, not GET"
    );
}

#[test]
fn extract_headers_on_401_for_auth_headers_fail_support() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let response = tiny_http::Response::from_string("")
            .with_status_code(401)
            .with_header(
                tiny_http::Header::from_bytes("WWW-Authenticate", "Bearer realm=\"api\"").unwrap(),
            )
            .with_header(tiny_http::Header::from_bytes("X-Error-Reason", "token-expired").unwrap());
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let config = make_config();
    let headers = HashMap::new();

    let extract = vec!["www-authenticate".to_string(), "x-error-reason".to_string()];
    let params = RequestParams {
        method: &config.method,
        forward_headers: &config.forward_headers,
        extract_headers: &extract,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    assert!(!decision.allowed);
    assert_eq!(decision.status_code, 401);

    let names: Vec<&str> = decision
        .extracted_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(names.contains(&"www-authenticate"));
    assert!(names.contains(&"x-error-reason"));

    handle.join().unwrap();
}

#[test]
fn extract_headers_on_5xx_failure_path() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    let handle = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let response = tiny_http::Response::from_string("")
            .with_status_code(503)
            .with_header(tiny_http::Header::from_bytes("X-Error-Reason", "auth-svc-down").unwrap());
        req.respond(response).unwrap();
    });

    let agent = make_agent();
    let mut config = make_config();
    config.fail_open = true; // so 503 doesn't propagate as denial; we want to inspect headers
    let headers = HashMap::new();

    let extract = vec!["x-error-reason".to_string()];
    let params = RequestParams {
        method: &config.method,
        forward_headers: &config.forward_headers,
        extract_headers: &extract,
    };
    let decision = send_auth_request(&agent, &config, &params, &auth_url, "/test", &headers);
    // fail_open=true → 5xx allows the request, but headers from auth-svc still flow through.
    assert!(decision.allowed);
    assert_eq!(decision.status_code, 503);
    assert_eq!(
        decision
            .extracted_headers
            .iter()
            .find(|(k, _)| k == "x-error-reason")
            .map(|(_, v)| v.as_str()),
        Some("auth-svc-down"),
    );

    handle.join().unwrap();
}
