use super::super::*;
use super::*;

#[test]
fn startup_storage_boundary_requires_explicit_single_tenant_or_managed_storage() {
    let mut config = Config::default();
    assert!(!explicit_single_tenant_mode(&config, false));
    assert!(explicit_single_tenant_mode(&config, true));

    config.auth.disabled = true;
    assert!(explicit_single_tenant_mode(&config, false));
    config.auth.disabled = false;
    config.storage.single_tenant = true;
    assert!(explicit_single_tenant_mode(&config, false));

    assert!(validate_storage_boundary_startup(false, true, true).is_err());
    assert!(validate_storage_boundary_startup(false, false, false).is_err());
    assert!(validate_storage_boundary_startup(false, false, true).is_ok());
    assert!(validate_storage_boundary_startup(true, true, false).is_ok());
    assert!(validate_storage_boundary_startup(true, false, false).is_ok());
}

#[test]
fn auto_local_profile_uses_resolved_storage_config_and_operator_inputs() {
    let mut config = Config::default();
    assert!(auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    assert!(!auto_local_appliance_with_operator_state(
        &config, true, false
    ));
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, true
    ));

    config.storage.s3_endpoint = Some("http://minio:9000".to_string());
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    config.storage.s3_endpoint = None;
    config.storage.mode = Some("local".to_string());
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    config.storage.mode = None;
    config.storage.local_dir = Some("./data".to_string());
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    config.storage.local_dir = None;
    config.storage.single_tenant = true;
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
}

#[test]
fn auto_local_defaults_do_not_override_explicit_feature_modes() {
    let defaults = Config::default();
    assert_eq!(
        effective_multipart_mode(&defaults, true),
        MultipartMode::Staged
    );
    assert_eq!(
        effective_streaming_read_mode(&defaults, true),
        StreamingReadMode::Passthrough
    );

    let explicit = Config::from_toml_str(
            "[features]\nmultipart_mode = \"reject\"\nstreaming_read_mode = \"off\"\n\n[wasm]\nfilter_component = \"/tmp/noop.wasm\"\n",
        )
        .unwrap();
    assert_eq!(
        effective_multipart_mode(&explicit, true),
        MultipartMode::Reject
    );
    assert_eq!(
        effective_streaming_read_mode(&explicit, true),
        StreamingReadMode::Off
    );
    assert!(explicit.filter_component_is_explicit());
}

#[test]
fn non_durable_journal_is_global_local_debug_only() {
    let journal: Arc<dyn OperationJournal> =
        Arc::new(crate::transaction::InMemoryOperationJournal::new());
    assert_eq!(
        direct_journal_allowed(BackendKind::GlobalS3, Some(&journal), true, true),
        cfg!(debug_assertions)
    );
    assert!(!direct_journal_allowed(
        BackendKind::GlobalS3,
        Some(&journal),
        false,
        true
    ));
    assert!(!direct_journal_allowed(
        BackendKind::GlobalS3,
        Some(&journal),
        true,
        false
    ));
    assert!(!direct_journal_allowed(
        BackendKind::PerUserS3,
        Some(&journal),
        true,
        true
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn transformed_source_returns_post_finish_fuel_for_spooled_evidence() {
    let component = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/components/noop.component.wasm"),
    )
    .expect("noop.component.wasm; run just build-plugins");
    let registry = PluginRegistry::new();
    registry.import("noop", &component).unwrap();
    let pipeline = registry
        .snapshot()
        .start_streaming_session(
            maskura_wasm_runtime::Session {
                format: "text".to_string(),
                content_type: "text/plain".to_string(),
                policy_version: 0,
                operation: maskura_wasm_runtime::Operation::Read,
                config_json: None,
                public_key_pem: None,
                stable_key: None,
                stable_fields: None,
            },
            maskura_wasm_runtime::CancellationToken::new(),
        )
        .await
        .unwrap();
    let object = OpenedObject::new(
        StatusCode::OK,
        metadata(None, Some("\"source-a\""), "text/plain"),
        Body::from("line\n"),
        BodyLimits::default(),
    );

    let fuel =
        process_transformed_source(object, pipeline, Format::Text, 1024, |_| async { Ok(()) })
            .await
            .unwrap();
    assert!(
        fuel > 0,
        "completed pipeline evidence must use measured fuel"
    );
}
