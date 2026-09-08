use axum::http::{HeaderMap, HeaderValue};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderAlias(&'static str);

impl HeaderAlias {
    const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

pub const ACCESS_KEY: HeaderAlias = HeaderAlias::new("x-maskura-access-key");
pub const SECRET_KEY: HeaderAlias = HeaderAlias::new("x-maskura-secret-key");
pub const MCP_TOKEN: HeaderAlias = HeaderAlias::new("x-maskura-mcp-token");
pub const STORAGE_MODE: HeaderAlias = HeaderAlias::new("x-maskura-storage-mode");
pub const BACKEND_URL: HeaderAlias = HeaderAlias::new("x-maskura-backend-url");
pub const PROCESS: HeaderAlias = HeaderAlias::new("x-maskura-process");
pub const STABLE_FIELDS: HeaderAlias = HeaderAlias::new("x-maskura-stable-fields");
pub const ENCRYPT_FIELDS: HeaderAlias = HeaderAlias::new("x-maskura-encrypt-fields");
pub const PLUGIN_NAME: HeaderAlias = HeaderAlias::new("x-maskura-plugin-name");

pub const ALL: &[HeaderAlias] = &[
    ACCESS_KEY,
    SECRET_KEY,
    MCP_TOKEN,
    STORAGE_MODE,
    BACKEND_URL,
    PROCESS,
    STABLE_FIELDS,
    ENCRYPT_FIELDS,
    PLUGIN_NAME,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderAliasError {
    Duplicate(&'static str),
}

fn unique<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a HeaderValue>, HeaderAliasError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(HeaderAliasError::Duplicate(name));
    }
    Ok(value)
}

pub fn aliased(
    headers: &HeaderMap,
    alias: HeaderAlias,
) -> Result<Option<&HeaderValue>, HeaderAliasError> {
    unique(headers, alias.as_str())
}

pub fn aliased_unique(
    headers: &HeaderMap,
    alias: HeaderAlias,
) -> Result<Option<&HeaderValue>, HeaderAliasError> {
    unique(headers, alias.as_str())
}

pub fn validated(headers: &HeaderMap, alias: HeaderAlias) -> Option<&HeaderValue> {
    aliased(headers, alias).expect("customer headers were validated before use")
}

pub fn validate_all(headers: &HeaderMap) -> Result<(), HeaderAliasError> {
    for alias in ALL {
        aliased(headers, *alias)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_header() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCESS_KEY.as_str(), "value".parse().unwrap());
        assert_eq!(
            aliased(&headers, ACCESS_KEY)
                .unwrap()
                .unwrap()
                .to_str()
                .unwrap(),
            "value"
        );
    }

    #[test]
    fn rejects_duplicate_names() {
        let mut duplicate = HeaderMap::new();
        duplicate.append(PROCESS.as_str(), "read".parse().unwrap());
        duplicate.append(PROCESS.as_str(), "read".parse().unwrap());
        assert_eq!(
            aliased_unique(&duplicate, PROCESS),
            Err(HeaderAliasError::Duplicate(PROCESS.as_str()))
        );
        assert_eq!(
            validate_all(&duplicate),
            Err(HeaderAliasError::Duplicate(PROCESS.as_str()))
        );
    }
}
