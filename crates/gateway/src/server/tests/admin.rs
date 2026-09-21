use super::super::*;
use super::*;

#[tokio::test]
async fn dashboard_rejects_workspace_endpoint_before_persistence() {
    let repository = CountingWorkspaceStorageRepository::default();
    let policy = WorkspaceEndpointPolicy::new(
        false,
        ["objects.example".to_string()],
        Vec::<String>::new(),
        Arc::new(PrivateAddressResolver),
    )
    .unwrap();
    let result = validate_and_put_workspace_backend(
        &repository,
        &policy,
        &WorkspaceId::new("workspace").unwrap(),
        BackendConfigRequest {
            backend_type: BackendType::S3Compatible,
            endpoint: "https://objects.example".to_string(),
            access_key: "access".to_string(),
            secret_key: "secret".to_string(),
            region: "us-east-1".to_string(),
            role_arn: String::new(),
            external_id: None,
        },
    )
    .await;

    assert!(matches!(
        result,
        Err(WorkspaceStorageError::InvalidConfig(_))
    ));
    assert_eq!(repository.put_calls.load(Ordering::SeqCst), 0);
}
