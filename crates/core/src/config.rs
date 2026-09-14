use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub listener: Listener,
    #[serde(default)]
    pub http: Http,
    pub remote: Remote,
    pub identity: Identity,
    pub trust: Trust,
    #[serde(default)]
    pub source_access: SourceAccess,
    #[serde(default)]
    pub queue: Queue,
    #[serde(default)]
    pub dtls: Dtls,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub oidc: crate::oidc::Oidc,
    pub address: IpAddr,
    pub port: u16,
}
impl Default for Http {
    fn default() -> Self {
        Self {
            address: IpAddr::from([127, 0, 0, 1]),
            port: 1080,
            oidc: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SourceAccess {
    pub mode: SourceMode,
    pub allowed_ips: Vec<IpAddr>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    #[default]
    Any,
    Allowlist,
}
/// Treat IPv4 and its mapped IPv6 representation as the same source.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listener {
    pub address: IpAddr,
    pub port: u16,
    pub max_message_bytes: usize,
}
impl Default for Listener {
    fn default() -> Self {
        Self {
            address: IpAddr::from([127, 0, 0, 1]),
            port: 1514,
            max_message_bytes: 8192,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub host: String,
    #[serde(default = "remote_port")]
    pub port: u16,
    pub expected_server_name: Option<String>,
}
fn remote_port() -> u16 {
    6514
}

/// Only references are serialized. Future providers may retain non-exportable keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Pem {
        certificate_chain: PathBuf,
        private_key: PathBuf,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum Trust {
    PemCa { ca_bundle: PathBuf },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Queue {
    pub max_messages: usize,
    pub max_bytes: usize,
}
impl Default for Queue {
    fn default() -> Self {
        Self {
            max_messages: 10_000,
            max_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dtls {
    pub handshake_timeout_ms: u64,
    pub retry_initial_ms: u64,
    pub retry_max_ms: u64,
    /// Maximum UDP payload, including the DTLS record overhead.
    pub datagram_bytes: u32,
    pub messages_per_second: u32,
    pub shutdown_drain_ms: u64,
}
impl Default for Dtls {
    fn default() -> Self {
        Self {
            handshake_timeout_ms: 10_000,
            retry_initial_ms: 1000,
            retry_max_ms: 60_000,
            datagram_bytes: 1200,
            messages_per_second: 1000,
            shutdown_drain_ms: 2000,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            listener: Listener::default(),
            http: Http::default(),
            remote: Remote {
                host: "collector.example.com".into(),
                port: 6514,
                expected_server_name: None,
            },
            identity: Identity::Pem {
                certificate_chain: "client.pem".into(),
                private_key: "client-key.pem".into(),
            },
            trust: Trust::PemCa {
                ca_bundle: "ca.pem".into(),
            },
            queue: Queue::default(),
            source_access: SourceAccess::default(),
            dtls: Dtls::default(),
        }
    }
}

impl Config {
    pub fn parse(text: &str, base: &Path) -> Result<Self, String> {
        // Do not echo TOML input in errors: users may accidentally paste secrets.
        let mut cfg: Self = toml::from_str(text)
            .map_err(|_| "Invalid TOML or unknown/missing configuration field".to_string())?;
        cfg.resolve_paths(base);
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
        let text = std::fs::read_to_string(&absolute)
            .map_err(|e| format!("Cannot read configuration: {e}"))?;
        Self::parse(&text, absolute.parent().unwrap_or(Path::new(".")))
    }
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|_| "Cannot serialize configuration".into())
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        let text = self.to_toml()?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|_| "Cannot save configuration".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "Cannot restrict configuration permissions".to_string())?;
        }
        file.set_len(0)
            .and_then(|_| file.write_all(text.as_bytes()))
            .map_err(|_| "Cannot save configuration".to_string())
    }
    pub fn resolve_paths(&mut self, base: &Path) {
        let Identity::Pem {
            certificate_chain,
            private_key,
        } = &mut self.identity;
        let Trust::PemCa { ca_bundle } = &mut self.trust;
        for path in [certificate_chain, private_key, ca_bundle] {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
    pub fn server_name(&self) -> Result<String, String> {
        normalize_name(
            self.remote
                .expected_server_name
                .as_deref()
                .unwrap_or(&self.remote.host),
        )
    }
    pub fn validate(&self) -> Result<(), String> {
        self.http.oidc.validate()?;
        if self.schema_version != 1 {
            return Err("Unsupported configuration schema version".into());
        }
        if self.source_access.allowed_ips.len() > 4096 {
            return Err("Allowlist supports at most 4096 IP addresses".into());
        }
        if self.listener.port == 0 || self.remote.port == 0 || self.http.port == 0 {
            return Err("Ports must be between 1 and 65535".into());
        }
        normalize_name(&self.remote.host)?;
        self.server_name()?;
        if !(1..=16_378).contains(&self.listener.max_message_bytes) {
            return Err(
                "max_message_bytes must be 1..16378 (space for framing within one record)".into(),
            );
        }
        if !(1..=1_000_000).contains(&self.queue.max_messages)
            || !(1..=1_073_741_824).contains(&self.queue.max_bytes)
        {
            return Err(
                "Queue limits must be positive; maximum is 1,000,000 messages / 1 GiB".into(),
            );
        }
        if !(576..=16_448).contains(&self.dtls.datagram_bytes) {
            return Err("datagram_bytes must be 576..16448".into());
        }
        if !(100..=120_000).contains(&self.dtls.handshake_timeout_ms)
            || !(100..=60_000).contains(&self.dtls.retry_initial_ms)
            || self.dtls.retry_max_ms < self.dtls.retry_initial_ms
            || self.dtls.retry_max_ms > 300_000
            || self.dtls.shutdown_drain_ms > 30_000
            || !(1..=100_000).contains(&self.dtls.messages_per_second)
        {
            return Err("Invalid DTLS timeout, retry, rate, or shutdown limits".into());
        }
        let Identity::Pem {
            certificate_chain,
            private_key,
        } = &self.identity;
        let Trust::PemCa { ca_bundle } = &self.trust;
        for path in [certificate_chain, private_key, ca_bundle] {
            if path.as_os_str().is_empty() {
                return Err("Credential paths cannot be empty".into());
            }
        }
        Ok(())
    }
}

pub fn normalize_name(name: &str) -> Result<String, String> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let name = idna::domain_to_ascii_strict(name).map_err(|_| "Invalid DNS name".to_string())?;
    let name = name.trim_end_matches('.');
    if name.is_empty()
        || name.len() > 253
        || name.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("Expected a hostname or IP address, without scheme or port".into());
    }
    Ok(name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_roundtrip() {
        let c = Config::parse(&Config::default().to_toml().unwrap(), Path::new("/tmp")).unwrap();
        assert_eq!(c.listener.port, 1514);
        assert_eq!(c.remote.port, 6514);
    }
    #[test]
    fn reject_unknown_and_insecure_fields() {
        let t = Config::default().to_toml().unwrap();
        assert!(Config::parse(&format!("verify_server = false\n{t}"), Path::new(".")).is_err());
    }
    #[test]
    fn http_defaults_roundtrip_and_validation() {
        let mut value = toml::Value::try_from(Config::default()).unwrap();
        value.as_table_mut().unwrap().remove("http");
        let old = toml::to_string(&value).unwrap();
        for suffix in ["", "\n[http]\n", "\n[http]\naddress = '::1'\n"] {
            let cfg = Config::parse(&format!("{old}{suffix}"), Path::new(".")).unwrap();
            assert_eq!(cfg.http.port, 1080);
        }
        let cfg = Config::parse(&old, Path::new(".")).unwrap();
        assert_eq!(cfg.http.address.to_string(), "127.0.0.1");
        let mut cfg = cfg;
        cfg.http.address = "192.0.2.1".parse().unwrap();
        cfg.http.port = 2080;
        let loaded = Config::parse(&cfg.to_toml().unwrap(), Path::new(".")).unwrap();
        assert_eq!(loaded.http.port, 2080);
        assert_eq!(loaded.http.address, cfg.http.address);
        cfg.http.port = 0;
        assert!(cfg.validate().is_err());
        assert!(Config::parse(
            &format!("{old}\n[http]\naddress = 'invalid'"),
            Path::new(".")
        )
        .is_err());
    }
    #[test]
    fn names() {
        assert_eq!(
            normalize_name("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert!(normalize_name("https://example.com").is_err());
        assert!(normalize_name("*.example.com").is_err());
    }
    #[test]
    fn source_access_is_backward_compatible_and_validates_addresses() {
        let mut c = Config::default();
        c.source_access.mode = SourceMode::Allowlist;
        c.source_access.allowed_ips = vec!["::1".parse().unwrap(), "192.0.2.1".parse().unwrap()];
        let text = c.to_toml().unwrap();
        let parsed = Config::parse(&text, Path::new(".")).unwrap();
        assert_eq!(parsed.source_access.mode, SourceMode::Allowlist);
        assert_eq!(
            parsed.source_access.allowed_ips,
            c.source_access.allowed_ips
        );
        assert!(Config::parse(&text.replace("192.0.2.1", "192.0.2.0/24"), Path::new(".")).is_err());
        let mut old: toml::Value = toml::from_str(&text).unwrap();
        old.as_table_mut().unwrap().remove("source_access");
        assert_eq!(
            Config::parse(&toml::to_string(&old).unwrap(), Path::new("."))
                .unwrap()
                .source_access
                .mode,
            SourceMode::Any
        );
    }
}
