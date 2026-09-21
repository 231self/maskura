//! Extracted from `service_storage.rs`; re-exported from `crate::service_storage`.

use super::*;

#[derive(Debug, Clone)]
pub struct ServiceBackend {
    pub provider: String,
    pub provider_instance_id: Option<String>,
    pub provider_account_id: Option<String>,
    pub credential_epoch: Option<u64>,
    pub placement_weight: u64,
    pub placement_capacity_units: u64,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

impl ServiceBackend {
    pub fn provider_kind(&self) -> &str {
        &self.provider
    }

    pub fn provider_instance_id(&self) -> Option<&str> {
        self.provider_instance_id.as_deref()
    }

    pub fn provider_account_id(&self) -> Option<&str> {
        self.provider_account_id.as_deref()
    }

    pub fn credential_epoch(&self) -> Option<u64> {
        self.credential_epoch
    }

    pub fn is_b2(&self) -> bool {
        self.provider_kind().eq_ignore_ascii_case("b2")
    }

    pub fn id(&self) -> String {
        self.provider_instance_id().map_or_else(
            || format!("{}:{}", self.provider, self.bucket),
            |instance_id| format!("{}:{instance_id}", self.provider),
        )
    }

    pub fn placement_weight(&self) -> Option<u64> {
        self.placement_weight
            .checked_mul(self.placement_capacity_units)
    }

    pub fn storage_identity(&self) -> Option<ProviderStorageIdentity> {
        Some(ProviderStorageIdentity {
            provider_kind: self.provider.clone(),
            provider_instance_id: self.provider_instance_id.clone()?,
            provider_account_id: self.provider_account_id.clone()?,
            canonical_endpoint: canonical_provider_endpoint(&self.endpoint)?,
            region: self.region.clone(),
        })
    }

    pub(crate) fn matches_persisted_identity(
        &self,
        identity: &ProviderStorageIdentity,
        credential_epoch: u64,
    ) -> bool {
        self.storage_identity().as_ref() == Some(identity)
            && self
                .credential_epoch()
                .is_some_and(|current| current >= credential_epoch)
    }

    pub async fn build_client(&self) -> Option<Client> {
        let access_key = self.access_key.clone();
        let secret_key = self.secret_key.clone();
        let region = self.region.clone();
        let endpoint = self.endpoint.clone();
        let creds = Credentials::new(access_key, secret_key, None, None, "maskura-service");
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(&endpoint)
            .credentials_provider(creds)
            .retry_config(s3_retry_config())
            .timeout_config(s3_timeout_config())
            .load()
            .await;
        Some(Client::from_conf(
            aws_sdk_s3::config::Builder::from(&config)
                .force_path_style(true)
                .build(),
        ))
    }
}

pub(crate) fn canonical_provider_endpoint(endpoint: &str) -> Option<String> {
    let mut endpoint = reqwest::Url::parse(endpoint).ok()?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return None;
    }
    if endpoint.path().is_empty() {
        endpoint.set_path("/");
    }
    Some(endpoint.to_string())
}

pub fn parse_service_backends(env_value: &str) -> Result<Vec<ServiceBackend>, String> {
    fn valid_identifier(value: &str, max_len: usize) -> bool {
        (1..=max_len).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }

    fn valid_credential(value: &str) -> bool {
        value.len() <= 4096 && value.bytes().all(|byte| byte.is_ascii_graphic())
    }

    let mut backends = Vec::new();
    for (index, definition) in env_value.split(';').enumerate() {
        let entry = index + 1;
        let parts: Vec<&str> = definition.split('|').collect();
        let (
            provider,
            instance,
            account,
            credential_epoch,
            placement_weight,
            placement_capacity_units,
            endpoint,
            region,
            bucket,
            access_key,
            secret_key,
        ) = match parts.as_slice() {
            [provider, endpoint, region, bucket, access_key, secret_key] => (
                *provider,
                None,
                None,
                None,
                None,
                None,
                *endpoint,
                *region,
                *bucket,
                *access_key,
                *secret_key,
            ),
            [
                provider,
                instance,
                account,
                credential_epoch,
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            ] => (
                *provider,
                Some(*instance),
                Some(*account),
                Some(*credential_epoch),
                None,
                None,
                *endpoint,
                *region,
                *bucket,
                *access_key,
                *secret_key,
            ),
            [
                provider,
                instance,
                account,
                credential_epoch,
                placement_weight,
                placement_capacity_units,
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            ] => (
                *provider,
                Some(*instance),
                Some(*account),
                Some(*credential_epoch),
                Some(*placement_weight),
                Some(*placement_capacity_units),
                *endpoint,
                *region,
                *bucket,
                *access_key,
                *secret_key,
            ),
            _ => {
                return Err(format!(
                    "invalid MASKURA_SERVICE_BUCKETS entry {entry}: expected six legacy fields, nine managed identity fields, or eleven managed placement fields"
                ));
            }
        };
        if parts.iter().any(|part| part.trim().is_empty()) {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: fields must be non-empty"
            ));
        }
        if !valid_identifier(provider, 128) {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed provider"
            ));
        }
        let explicit_identity = instance
            .zip(account)
            .zip(credential_epoch)
            .map(|((instance, account), credential_epoch)| {
                if !valid_identifier(instance, 128) {
                    return Err(format!(
                        "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed provider instance ID"
                    ));
                }
                if !valid_identifier(account, 256) {
                    return Err(format!(
                        "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed provider account ID"
                    ));
                }
                let credential_epoch = credential_epoch.parse::<u64>().map_err(|_| {
                    format!(
                        "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed credential epoch"
                    )
                })?;
                if credential_epoch == 0 {
                    return Err(format!(
                        "invalid MASKURA_SERVICE_BUCKETS entry {entry}: credential epoch must be positive"
                    ));
                }
                Ok((instance, account, credential_epoch))
            })
            .transpose()?;
        let placement_policy = placement_weight
            .zip(placement_capacity_units)
            .map(|(weight, capacity_units)| {
                let weight = weight.parse::<u64>().map_err(|_| {
                    format!("invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed placement weight")
                })?;
                let capacity_units = capacity_units.parse::<u64>().map_err(|_| {
                    format!("invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed placement capacity units")
                })?;
                if weight == 0 || capacity_units == 0 || weight.checked_mul(capacity_units).is_none() {
                    return Err(format!(
                        "invalid MASKURA_SERVICE_BUCKETS entry {entry}: placement weight and capacity units must be positive without overflow"
                    ));
                }
                Ok((weight, capacity_units))
            })
            .transpose()?
            // S7a's deployed managed identity form had no placement policy.
            // Its single backend retains the equivalent 1x1 static policy.
            .unwrap_or((1, 1));
        let endpoint_url = reqwest::Url::parse(endpoint).map_err(|_| {
            format!("invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed endpoint")
        })?;
        if endpoint.len() > 2048
            || !endpoint.bytes().all(|byte| byte.is_ascii_graphic())
            || !matches!(endpoint_url.scheme(), "http" | "https")
            || endpoint_url.host_str().is_none()
            || !endpoint_url.username().is_empty()
            || endpoint_url.password().is_some()
            || endpoint_url.query().is_some()
            || endpoint_url.fragment().is_some()
        {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed endpoint"
            ));
        }
        let canonical_endpoint = canonical_provider_endpoint(endpoint).ok_or_else(|| {
            format!("invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed endpoint")
        })?;
        if !valid_identifier(region, 128) {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed region"
            ));
        }
        if !valid_identifier(bucket, 255) {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed bucket"
            ));
        }
        if !valid_credential(access_key) {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed access key"
            ));
        }
        if !valid_credential(secret_key) {
            return Err(format!(
                "invalid MASKURA_SERVICE_BUCKETS entry {entry}: malformed secret key"
            ));
        }
        backends.push(ServiceBackend {
            provider: provider.to_string(),
            provider_instance_id: explicit_identity
                .as_ref()
                .map(|(instance, _, _)| (*instance).to_string()),
            provider_account_id: explicit_identity
                .as_ref()
                .map(|(_, account, _)| (*account).to_string()),
            credential_epoch: explicit_identity.map(|(_, _, epoch)| epoch),
            placement_weight: placement_policy.0,
            placement_capacity_units: placement_policy.1,
            endpoint: canonical_endpoint,
            region: region.to_string(),
            bucket: bucket.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        });
    }
    Ok(backends)
}
