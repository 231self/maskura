use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::ConfigError;

const MAX_NAME_LEN: usize = 128;
const DIGEST_LEN: usize = 64;

/// Identity of a pipeline component: `(source, name, version)`.
///
/// Canonical textual form is `<source-uri>:<name>[:<version>]`; an
/// unqualified reference is `name[:<version>]`. An absent source means the
/// local `file://` namespace, and an absent version means "latest".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PluginRef {
    pub source: Option<String>,
    pub name: String,
    pub version: Option<String>,
}

impl PluginRef {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ConfigError::invalid("plugin reference is empty"));
        }

        let (source, name, version) = if let Some((scheme, tail)) = split_scheme(input) {
            parse_qualified(scheme, tail, input)?
        } else {
            parse_unqualified(input)?
        };

        validate_name(name)?;
        let source = source
            .map(|source| canonicalize_source(&source))
            .transpose()?;
        if let Some(version) = &version {
            parse_version_req(version)?;
        }

        Ok(Self {
            source,
            name: name.to_string(),
            version,
        })
    }

    /// True when the reference pins an exact version rather than a range or
    /// "latest".
    pub fn is_exactly_pinned(&self) -> bool {
        self.version
            .as_deref()
            .is_some_and(|version| semver::Version::parse(version).is_ok())
    }

    /// True when `version` satisfies this reference's requirement. A reference
    /// without a version asks for "latest" and accepts any version.
    pub fn accepts_version(&self, version: &str) -> bool {
        let Some(requirement) = &self.version else {
            return true;
        };
        let Ok(parsed) = semver::Version::parse(version) else {
            return false;
        };
        if let Ok(exact) = semver::Version::parse(requirement) {
            return exact == parsed;
        }
        let Ok(requirement) = parse_version_req(requirement) else {
            return false;
        };
        requirement.matches(&parsed)
    }
}

impl std::fmt::Display for PluginRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(source) = &self.source {
            write!(f, "{source}:")?;
        }
        f.write_str(&self.name)?;
        if let Some(version) = &self.version {
            write!(f, ":{version}")?;
        }
        Ok(())
    }
}

impl TryFrom<String> for PluginRef {
    type Error = ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PluginRef> for String {
    fn from(value: PluginRef) -> Self {
        value.to_string()
    }
}

fn parse_qualified<'a>(
    scheme: &str,
    tail: &'a str,
    input: &str,
) -> Result<(Option<String>, &'a str, Option<String>), ConfigError> {
    let segments: Vec<&str> = tail.split(':').collect();
    match segments.as_slice() {
        [] | [_] => Err(ConfigError::invalid(format!(
            "plugin reference {input:?} is missing a plugin name"
        ))),
        [before, name] => Ok((Some(format!("{scheme}://{before}")), *name, None)),
        [.., candidate_name, candidate_version] => {
            let before_len = segments.len() - 2;
            if looks_like_version(candidate_version) {
                Ok((
                    Some(format!("{scheme}://{}", segments[..before_len].join(":"))),
                    *candidate_name,
                    Some((*candidate_version).to_string()),
                ))
            } else {
                Ok((
                    Some(format!(
                        "{scheme}://{}",
                        segments[..before_len + 1].join(":")
                    )),
                    *candidate_version,
                    None,
                ))
            }
        }
    }
}

fn parse_unqualified(input: &str) -> Result<(Option<String>, &str, Option<String>), ConfigError> {
    let segments: Vec<&str> = input.split(':').collect();
    match segments.as_slice() {
        [name] => Ok((None, *name, None)),
        [name, version] => {
            if !looks_like_version(version) {
                return Err(ConfigError::invalid(format!(
                    "plugin reference {input:?} is ambiguous; qualify the source with a URI"
                )));
            }
            Ok((None, *name, Some((*version).to_string())))
        }
        _ => Err(ConfigError::invalid(format!(
            "plugin reference {input:?} has multiple version segments; qualify the source with a URI"
        ))),
    }
}

fn split_scheme(input: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = input.split_once("://")?;
    let mut chars = scheme.chars();
    if !chars.next()?.is_ascii_alphabetic() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    Some((scheme, rest))
}

fn validate_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(ConfigError::invalid(format!(
            "plugin name {name:?} must be 1..={MAX_NAME_LEN} characters"
        )));
    }
    if is_digest(name) {
        return Ok(());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConfigError::invalid(format!(
            "plugin name {name:?} must match [A-Za-z0-9_-] or be a {DIGEST_LEN}-hex digest"
        )));
    }
    Ok(())
}

fn canonicalize_source(source: &str) -> Result<String, ConfigError> {
    let url = Url::parse(source).map_err(|error| {
        ConfigError::invalid(format!(
            "plugin source {source:?} is not an absolute URI: {error}"
        ))
    })?;
    if !matches!(url.scheme(), "file" | "https") {
        return Err(ConfigError::invalid(format!(
            "plugin source {source:?} uses unsupported scheme {:?}; expected file or https",
            url.scheme()
        )));
    }
    if url.scheme() == "file" && url.host_str().is_some_and(|host| !host.is_empty()) {
        return Err(ConfigError::invalid(format!(
            "plugin source {source:?} must use an absolute file:/// URI without a host"
        )));
    }
    if url.scheme() == "https" && url.host_str().is_none() {
        return Err(ConfigError::invalid(format!(
            "plugin source {source:?} must include a host"
        )));
    }
    let mut canonical = url.to_string();
    if canonical.ends_with('/') && canonical != "file:///" {
        canonical.pop();
    }
    Ok(canonical)
}

fn is_digest(name: &str) -> bool {
    name.len() == DIGEST_LEN && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Heuristic used to disambiguate the final segment of a qualified reference:
/// it is a version candidate only when it carries a digit plus a range
/// operator or a dotted shape, or is entirely numeric.
fn looks_like_version(candidate: &str) -> bool {
    if candidate.is_empty() {
        return false;
    }
    if candidate == "*" {
        return true;
    }
    let has_digit = candidate.chars().any(|c| c.is_ascii_digit());
    if !has_digit {
        return false;
    }
    if candidate.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    candidate
        .chars()
        .any(|c| matches!(c, '.' | '*' | '^' | '~' | '<' | '>' | '='))
}

fn parse_version_req(version: &str) -> Result<semver::VersionReq, ConfigError> {
    if let Ok(requirement) = semver::VersionReq::parse(version) {
        return Ok(requirement);
    }
    let mut normalized = version.replace(['x', 'X', 'y', 'Y'], "*");
    while normalized.contains(".*.*") {
        normalized = normalized.replace(".*.*", ".*");
    }
    semver::VersionReq::parse(&normalized).map_err(|error| {
        ConfigError::invalid(format!(
            "version requirement {version:?} is invalid: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unqualified_name_defaults_to_local_latest() {
        let reference = PluginRef::parse("pii-default").unwrap();
        assert_eq!(reference.source, None);
        assert_eq!(reference.name, "pii-default");
        assert_eq!(reference.version, None);
        assert_eq!(reference.to_string(), "pii-default");
    }

    #[test]
    fn unqualified_name_with_exact_version_round_trips() {
        let reference = PluginRef::parse("pii-default:1.2.0").unwrap();
        assert_eq!(reference.source, None);
        assert_eq!(reference.name, "pii-default");
        assert_eq!(reference.version.as_deref(), Some("1.2.0"));
        assert_eq!(reference.to_string(), "pii-default:1.2.0");
        assert!(reference.accepts_version("1.2.0"));
        assert!(!reference.accepts_version("1.2.1"));
        assert!(!reference.accepts_version("1.9.0"));
    }

    #[test]
    fn qualified_https_reference_parses_source_name_and_version() {
        let reference =
            PluginRef::parse("https://github.com/231self/maskura/plugins:pii-default:0.x.y")
                .unwrap();
        assert_eq!(
            reference.source.as_deref(),
            Some("https://github.com/231self/maskura/plugins")
        );
        assert_eq!(reference.name, "pii-default");
        assert_eq!(reference.version.as_deref(), Some("0.x.y"));
        assert_eq!(
            reference.to_string(),
            "https://github.com/231self/maskura/plugins:pii-default:0.x.y"
        );
    }

    #[test]
    fn qualified_file_source_with_omitted_version_parses_name_only() {
        let reference = PluginRef::parse("file:///dir/dirA/plugins:plugin_name").unwrap();
        assert_eq!(
            reference.source.as_deref(),
            Some("file:///dir/dirA/plugins")
        );
        assert_eq!(reference.name, "plugin_name");
        assert_eq!(reference.version, None);
    }

    #[test]
    fn port_bearing_source_without_version_is_unambiguous() {
        let reference = PluginRef::parse("https://host:8443/path:pii-default").unwrap();
        assert_eq!(reference.source.as_deref(), Some("https://host:8443/path"));
        assert_eq!(reference.name, "pii-default");
        assert_eq!(reference.version, None);
    }

    #[test]
    fn port_bearing_source_with_version_keeps_port_in_source() {
        let reference = PluginRef::parse("https://host:8443/path:pii-default:0.2.0").unwrap();
        assert_eq!(reference.source.as_deref(), Some("https://host:8443/path"));
        assert_eq!(reference.name, "pii-default");
        assert_eq!(reference.version.as_deref(), Some("0.2.0"));
    }

    #[test]
    fn digest_name_is_accepted() {
        let digest = "a".repeat(64);
        let reference = PluginRef::parse(&digest).unwrap();
        assert_eq!(reference.name, digest);
    }

    #[test]
    fn x_wildcard_and_semver_forms_are_accepted() {
        for version in ["0.x.y", "^1.2.0", "~1.2.0", "*", ">=1.2.0, <2.0.0"] {
            let input = format!("pii-default:{version}");
            let reference = PluginRef::parse(&input).unwrap();
            assert_eq!(reference.version.as_deref(), Some(version), "{input}");
        }
    }

    #[test]
    fn version_ranges_retain_semver_matching() {
        let reference = PluginRef::parse("pii-default:^1.2.0").unwrap();
        assert!(reference.accepts_version("1.9.0"));
        assert!(!reference.accepts_version("2.0.0"));
    }

    #[test]
    fn qualified_source_must_be_a_supported_absolute_uri() {
        for input in [
            "ftp://example.com/plugins:pii-default:1.2.0",
            "https://:pii-default:1.2.0",
            "custom://registry/plugins:pii-default:1.2.0",
            "file://relative-host/plugins:pii-default:1.2.0",
        ] {
            assert!(PluginRef::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn ambiguous_unqualified_reference_is_rejected() {
        let error = PluginRef::parse("source:name:version").unwrap_err();
        assert_eq!(error.code(), maskura_error::codes::CONFIG_INVALID);
    }

    #[test]
    fn invalid_plugin_name_is_rejected() {
        assert!(PluginRef::parse("bad/name").is_err());
        assert!(PluginRef::parse("").is_err());
    }
}
