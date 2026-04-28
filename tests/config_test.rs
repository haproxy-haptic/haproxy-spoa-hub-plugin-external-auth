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
        extract_headers: vec![],
        timeout_ms: 5000,
        fail_open: false,
        method: "GET".into(),
        allow_plaintext: false,
        mtls_cache_capacity: 64,
    }
}

#[test]
fn validate_https_url_accepted() {
    let config = make_config();
    assert!(
        config
            .validate_auth_url("https://auth.example.com/check")
            .is_ok()
    );
}

#[test]
fn validate_http_url_rejected_without_allow_plaintext() {
    let config = make_config();
    assert!(
        config
            .validate_auth_url("http://auth.example.com/check")
            .is_err()
    );
}

#[test]
fn validate_http_url_accepted_with_allow_plaintext() {
    let mut config = make_config();
    config.allow_plaintext = true;
    assert!(
        config
            .validate_auth_url("http://auth.example.com/check")
            .is_ok()
    );
}

#[test]
fn validate_invalid_scheme_rejected() {
    let config = make_config();
    assert!(
        config
            .validate_auth_url("ftp://auth.example.com/check")
            .is_err()
    );
}

#[test]
fn config_schema_is_valid_json() {
    let schema = PluginConfig::config_schema();
    let parsed: serde_json::Value = serde_json::from_str(schema).unwrap();
    assert_eq!(parsed["type"], "object");
    assert!(parsed["properties"]["timeout_ms"].is_object());
}
