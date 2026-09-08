use std::ffi::OsString;

pub mod config;

pub use config::{Config, ConfigError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvAlias(&'static str);

impl EnvAlias {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn name(self) -> &'static str {
        self.0
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum EnvError {
    #[error("{name} contains non-Unicode data")]
    NotUnicode { name: &'static str },
}

pub mod aliases {
    use super::EnvAlias;

    pub const GATEWAY_URL: EnvAlias = EnvAlias::new("MASKURA_GATEWAY_URL");
    pub const ACCESS_KEY: EnvAlias = EnvAlias::new("MASKURA_ACCESS_KEY");
    pub const SECRET_KEY: EnvAlias = EnvAlias::new("MASKURA_SECRET_KEY");
    pub const MCP_TOKEN: EnvAlias = EnvAlias::new("MASKURA_MCP_TOKEN");
    pub const PORT: EnvAlias = EnvAlias::new("MASKURA_PORT");

    pub const FILTER_COMPONENT: EnvAlias = EnvAlias::new("MASKURA_FILTER_COMPONENT");
    pub const PLUGINS_DIR: EnvAlias = EnvAlias::new("MASKURA_PLUGINS_DIR");
    pub const WASM_FUEL: EnvAlias = EnvAlias::new("MASKURA_WASM_FUEL");
    pub const SOURCE_MAX_FRAME_BYTES: EnvAlias = EnvAlias::new("MASKURA_SOURCE_MAX_FRAME_BYTES");
    pub const MAX_OBJECT_BYTES: EnvAlias = EnvAlias::new("MASKURA_MAX_OBJECT_BYTES");
    pub const MAX_PIPELINE_OUTPUT_BYTES: EnvAlias =
        EnvAlias::new("MASKURA_MAX_PIPELINE_OUTPUT_BYTES");
    pub const STREAMING_READ_MODE: EnvAlias = EnvAlias::new("MASKURA_STREAMING_READ_MODE");
    pub const TRANSFORMED_READ_SPOOL: EnvAlias = EnvAlias::new("MASKURA_TRANSFORMED_READ_SPOOL");
    pub const PREFIX_SAFE_COMPONENT_HASHES: EnvAlias =
        EnvAlias::new("MASKURA_PREFIX_SAFE_COMPONENT_HASHES");
    pub const STREAMING_S3_PROVIDER: EnvAlias = EnvAlias::new("MASKURA_STREAMING_S3_PROVIDER");
    pub const ENABLE_AVRO: EnvAlias = EnvAlias::new("MASKURA_ENABLE_AVRO");
    pub const LEGACY_MAX_OBJECT_BYTES: EnvAlias = EnvAlias::new("MASKURA_LEGACY_MAX_OBJECT_BYTES");
    pub const SINGLE_TENANT: EnvAlias = EnvAlias::new("MASKURA_SINGLE_TENANT");
    pub const LOCAL_STORAGE_DIR: EnvAlias = EnvAlias::new("MASKURA_LOCAL_STORAGE_DIR");
    pub const MULTIPART_MODE: EnvAlias = EnvAlias::new("MASKURA_MULTIPART_MODE");
    pub const SPOOL_DIR: EnvAlias = EnvAlias::new("MASKURA_SPOOL_DIR");
    pub const SPOOL_MAX_OBJECT_BYTES: EnvAlias = EnvAlias::new("MASKURA_SPOOL_MAX_OBJECT_BYTES");
    pub const SPOOL_QUOTA_BYTES: EnvAlias = EnvAlias::new("MASKURA_SPOOL_QUOTA_BYTES");
    pub const DEV_MEMORY_MAX_OBJECT_BYTES: EnvAlias =
        EnvAlias::new("MASKURA_DEV_MEMORY_MAX_OBJECT_BYTES");
    pub const DEV_MEMORY_STREAMING: EnvAlias = EnvAlias::new("MASKURA_DEV_MEMORY_STREAMING");
    pub const KEYS_FILE: EnvAlias = EnvAlias::new("MASKURA_KEYS_FILE");
    pub const BOOTSTRAP_KEY: EnvAlias = EnvAlias::new("MASKURA_BOOTSTRAP_KEY");
    pub const BOOTSTRAP_SECRET: EnvAlias = EnvAlias::new("MASKURA_BOOTSTRAP_SECRET");

    pub const GATEWAY_CUSTOMER_SETTINGS: &[EnvAlias] = &[
        FILTER_COMPONENT,
        PLUGINS_DIR,
        WASM_FUEL,
        SOURCE_MAX_FRAME_BYTES,
        MAX_OBJECT_BYTES,
        MAX_PIPELINE_OUTPUT_BYTES,
        STREAMING_READ_MODE,
        TRANSFORMED_READ_SPOOL,
        PREFIX_SAFE_COMPONENT_HASHES,
        STREAMING_S3_PROVIDER,
        ENABLE_AVRO,
        LEGACY_MAX_OBJECT_BYTES,
        SINGLE_TENANT,
        LOCAL_STORAGE_DIR,
        MULTIPART_MODE,
        SPOOL_DIR,
        SPOOL_MAX_OBJECT_BYTES,
        SPOOL_QUOTA_BYTES,
        DEV_MEMORY_MAX_OBJECT_BYTES,
        DEV_MEMORY_STREAMING,
        KEYS_FILE,
        BOOTSTRAP_KEY,
        BOOTSTRAP_SECRET,
        PORT,
    ];

    pub const CLIENT_CUSTOMER_SETTINGS: &[EnvAlias] =
        &[GATEWAY_URL, ACCESS_KEY, SECRET_KEY, MCP_TOKEN];
}

pub fn resolve(alias: EnvAlias) -> Result<Option<String>, EnvError> {
    resolve_with(alias, |name| std::env::var_os(name))
}

pub fn validate(aliases: &[EnvAlias]) -> Result<(), EnvError> {
    for alias in aliases {
        resolve(*alias)?;
    }
    Ok(())
}

pub fn resolve_with(
    alias: EnvAlias,
    mut read: impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<String>, EnvError> {
    read(alias.name())
        .map(|value| {
            value
                .into_string()
                .map_err(|_| EnvError::NotUnicode { name: alias.name() })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TEST_ALIAS: EnvAlias = EnvAlias::new("MASKURA_VALUE");

    fn resolve_values(values: &[(&str, &str)]) -> Result<Option<String>, EnvError> {
        let values: HashMap<_, _> = values
            .iter()
            .map(|(name, value)| ((*name).to_string(), OsString::from(value)))
            .collect();
        resolve_with(TEST_ALIAS, |name| values.get(name).cloned())
    }

    #[test]
    fn resolves_present_value() {
        assert_eq!(
            resolve_values(&[("MASKURA_VALUE", "value")]),
            Ok(Some("value".to_string()))
        );
    }

    #[test]
    fn preserves_empty_values() {
        assert_eq!(
            resolve_values(&[("MASKURA_VALUE", "")]),
            Ok(Some(String::new()))
        );
    }

    #[test]
    fn returns_none_when_absent() {
        assert_eq!(resolve_values(&[]), Ok(None));
    }

    #[test]
    fn shipped_alias_tables_are_unique_and_customer_only() {
        let aliases = aliases::GATEWAY_CUSTOMER_SETTINGS
            .iter()
            .chain(aliases::CLIENT_CUSTOMER_SETTINGS);
        let mut names = std::collections::HashSet::new();
        for alias in aliases {
            assert!(alias.name().starts_with("MASKURA_"));
            assert!(names.insert(alias.name()));
        }
        for operator_only in [
            "S4_SECRET_KEK",
            "S4_SERVICE_BUCKETS",
            "S4_SIGV4_REGION",
            "S4_WORKSPACE_ENDPOINT_ALLOWLIST",
            "S4_PRESIGNED_HTTP_ALLOWLIST",
            "S4_MANAGED_STREAMING_MODE",
            "S4_MULTIPART_STAGING_BUCKET",
        ] {
            assert!(!names.contains(operator_only));
        }
    }
}
