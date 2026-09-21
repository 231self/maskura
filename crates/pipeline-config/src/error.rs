use maskura_error::codes;

/// Errors surfaced while loading, validating, selecting, or verifying a
/// signed pipeline configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("pipeline config TOML parse failed: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("pipeline config is invalid: {0}")]
    Invalid(String),
    #[error("pipeline config signature is invalid: {0}")]
    Signature(String),
}

impl ConfigError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn signature(message: impl Into<String>) -> Self {
        Self::Signature(message.into())
    }

    /// Stable error code for the shared API envelope.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Toml(_) | Self::Invalid(_) => codes::CONFIG_INVALID,
            Self::Signature(_) => codes::POLICY_TAMPERED,
        }
    }
}
