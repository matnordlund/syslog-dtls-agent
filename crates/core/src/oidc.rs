//! OIDC settings. Client secrets are persisted in TOML and redacted from Debug.
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "OidcInput")]
pub struct Oidc {
    pub enabled: bool,
    pub discovery_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub public_url: String,
    pub groups_claim: String,
    pub required_group: String,
    pub scopes: Vec<String>,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OidcInput {
    issuer_url: Option<String>,
    client_secret_env: Option<String>,
    enabled: bool,
    discovery_uri: String,
    client_id: String,
    client_secret: String,
    public_url: String,
    groups_claim: String,
    required_group: String,
    scopes: Vec<String>,
}
impl Default for Oidc {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_uri: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            public_url: String::new(),
            groups_claim: "groups".into(),
            required_group: String::new(),
            scopes: vec![],
        }
    }
}
/// HTTP and HTTPS are both supported, including internal providers.
pub fn http_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "Invalid OIDC URL".to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
        || !matches!(url.scheme(), "https" | "http")
    {
        return Err("OIDC URLs require HTTP or HTTPS, without credentials or fragment".into());
    }
    Ok(url)
}
impl Oidc {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        http_url(&self.discovery_uri)?;
        let public = http_url(&self.public_url)?;
        if public.path() != "/" || public.query().is_some() {
            return Err("OIDC public URL must be an origin without a path or query".into());
        }
        if self.client_id.trim().is_empty()
            || self.groups_claim.trim().is_empty()
            || self.required_group.trim().is_empty()
        {
            return Err("OIDC requires a client ID, group claim and required group".into());
        }
        if self.scopes.len() > 32
            || self.scopes.iter().any(|s| {
                s.is_empty()
                    || !s.bytes().all(|c| {
                        c == 0x21 || (0x23..=0x5b).contains(&c) || (0x5d..=0x7e).contains(&c)
                    })
            })
        {
            return Err("OIDC scopes must be nonempty OAuth scope names (at most 32)".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_roundtrip_but_debug_is_redacted_and_legacy_configs_migrate() {
        let config = Oidc {
            client_secret: "  secret-value  ".into(),
            ..Default::default()
        };
        let text = toml::to_string(&config).unwrap();
        let loaded: Oidc = toml::from_str(&text).unwrap();
        assert_eq!(loaded.client_secret, "  secret-value  ");
        assert!(!format!("{loaded:?}").contains("secret-value"));
        let old: Oidc = toml::from_str(
            "issuer_url = 'http://id.internal/realm'\nclient_secret_env = 'OLD_SECRET'",
        )
        .unwrap();
        assert_eq!(
            old.discovery_uri,
            "http://id.internal/realm/.well-known/openid-configuration"
        );
        assert!(old.client_secret.is_empty());
        assert!(
            toml::from_str::<Oidc>("enabled = true\nclient_secret_env = 'OLD_SECRET'").is_err()
        );
    }
    #[test]
    fn accept_http_and_https_and_require_complete_authorization() {
        assert!(Oidc::default().validate().is_ok());
        let mut config = Oidc {
            enabled: true,
            discovery_uri: "https://id.example/realm/.well-known/openid-configuration".into(),
            public_url: "https://agent.example".into(),
            client_id: "agent".into(),
            required_group: "operators".into(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        config.public_url = "http://192.0.2.1:1080".into();
        config.discovery_uri = "http://identity.internal/custom-discovery".into();
        assert!(config.validate().is_ok());
        config.public_url = "http://127.0.0.1:1080".into();
        assert!(config.validate().is_ok());
        config.public_url = "http://agent.internal/?query".into();
        assert!(config.validate().is_err());
        assert!(http_url("http://identity.internal/discovery?appid=agent").is_ok());
        config.required_group.clear();
        assert!(config.validate().is_err());
        for value in [
            "https://user:secret@host/",
            "file:///tmp",
            "https://host/#fragment",
        ] {
            assert!(http_url(value).is_err());
        }
    }
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc")
            .field("enabled", &self.enabled)
            .field("discovery_uri", &self.discovery_uri)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("public_url", &self.public_url)
            .field("groups_claim", &self.groups_claim)
            .field("required_group", &self.required_group)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Default for OidcInput {
    fn default() -> Self {
        let value = Oidc::default();
        Self {
            issuer_url: None,
            client_secret_env: None,
            enabled: value.enabled,
            discovery_uri: value.discovery_uri,
            client_id: value.client_id,
            client_secret: value.client_secret,
            public_url: value.public_url,
            groups_claim: value.groups_claim,
            required_group: value.required_group,
            scopes: value.scopes,
        }
    }
}
impl TryFrom<OidcInput> for Oidc {
    type Error = String;
    fn try_from(value: OidcInput) -> Result<Self, String> {
        if value.enabled
            && value.client_secret.is_empty()
            && value
                .client_secret_env
                .as_ref()
                .is_some_and(|name| !name.is_empty())
        {
            return Err(
                "Replace client_secret_env with client_secret in the OIDC configuration".into(),
            );
        }
        let discovery_uri = if value.discovery_uri.is_empty() {
            value
                .issuer_url
                .map(|issuer| {
                    if issuer.is_empty() {
                        issuer
                    } else {
                        format!(
                            "{}/.well-known/openid-configuration",
                            issuer.trim_end_matches('/')
                        )
                    }
                })
                .unwrap_or_default()
        } else {
            value.discovery_uri
        };
        Ok(Self {
            enabled: value.enabled,
            discovery_uri,
            client_id: value.client_id,
            client_secret: value.client_secret,
            public_url: value.public_url,
            groups_claim: value.groups_claim,
            required_group: value.required_group,
            scopes: value.scopes,
        })
    }
}
