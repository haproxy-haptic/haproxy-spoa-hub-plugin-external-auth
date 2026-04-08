use std::collections::HashMap;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use external_auth_plugin::auth::{AuthDecision, send_auth_request};
use external_auth_plugin::config::PluginConfig;

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
        extract_headers: vec!["x-auth-user".into(), "x-auth-roles".into()],
        timeout_ms: 5000,
        fail_open: false,
        method: "GET".into(),
        allow_plaintext: true,
    }
}

fn make_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn bench_to_variables(c: &mut Criterion) {
    let decision_allowed = AuthDecision {
        allowed: true,
        status_code: 200,
        redirect_url: None,
        extracted_headers: vec![
            ("x-auth-user".into(), "alice".into()),
            ("x-auth-roles".into(), "admin,editor".into()),
        ],
        error: None,
    };

    let decision_denied = AuthDecision {
        allowed: false,
        status_code: 302,
        redirect_url: Some("https://login.example.com/oauth2/start?rd=%2Fdashboard".into()),
        extracted_headers: vec![],
        error: None,
    };

    c.bench_function("to_variables_allowed_2_headers", |b| {
        b.iter(|| decision_allowed.to_variables());
    });

    c.bench_function("to_variables_denied_redirect", |b| {
        b.iter(|| decision_denied.to_variables());
    });
}

fn bench_send_auth_request(c: &mut Criterion) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let auth_url = format!("http://{addr}");

    // Background thread that responds to every request with 200 + auth headers
    std::thread::spawn(move || {
        loop {
            match server.recv() {
                Ok(req) => {
                    let response = tiny_http::Response::from_string("ok")
                        .with_status_code(200)
                        .with_header(tiny_http::Header::from_bytes("X-Auth-User", "alice").unwrap())
                        .with_header(
                            tiny_http::Header::from_bytes("X-Auth-Roles", "admin,editor").unwrap(),
                        );
                    let _ = req.respond(response);
                }
                Err(_) => break,
            }
        }
    });

    let agent = make_agent();
    let config = make_config();
    let mut headers = HashMap::new();
    headers.insert("authorization".into(), "Bearer bench-token".into());
    headers.insert("cookie".into(), "session=bench123".into());

    c.bench_function("send_auth_request_200_localhost", |b| {
        b.iter(|| {
            let decision = send_auth_request(&agent, &config, &auth_url, "/bench", &headers);
            assert!(decision.allowed);
        });
    });
}

criterion_group!(benches, bench_to_variables, bench_send_auth_request);
criterion_main!(benches);
