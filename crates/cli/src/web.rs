//! Local HTTP management adapter; the relay core remains transport-independent.
use serde_json::{json, Value};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use syslog_agent_core::{Config, Relay, Status};
use syslog_agent_dtls_openssl::OpenSslConnector;
use tiny_http::{Header, Method, Request, Response, Server};

pub struct Agent {
    pub config: Config,
    pub path: PathBuf,
    pub relay: Option<Relay>,
    pub last: Status,
}
impl Agent {
    pub fn status(&self) -> Status {
        self.relay
            .as_ref()
            .map(Relay::status)
            .unwrap_or_else(|| self.last.clone())
    }
    pub fn stop(&mut self) -> Status {
        if let Some(mut relay) = self.relay.take() {
            self.last = relay.stop();
        }
        self.last.clone()
    }
    fn command(&mut self, command: &str, args: Value) -> Result<Value, String> {
        match command {
            "status" => Ok(json!(self.status())),
            "default_config" => Ok(json!(self.config)),
            "stop" => Ok(json!(self.stop())),
            "normalize_source_ip" => args["ip"]
                .as_str()
                .unwrap_or("")
                .parse::<std::net::IpAddr>()
                .map(syslog_agent_core::config::canonical_ip)
                .map(|ip| json!(ip.to_string()))
                .map_err(|_| "Enter an exact IPv4 or IPv6 address".into()),
            "load_config" => {
                if self.status().running {
                    return Err("Stop the relay before loading settings".into());
                }
                Ok(json!(Config::load(&self.path)?))
            }
            "start" | "validate" | "save_config" => {
                let mut config: Config = serde_json::from_value(args["config"].clone())
                    .map_err(|_| "Invalid configuration".to_string())?;
                config.resolve_paths(self.path.parent().unwrap());
                config.validate()?;
                if command == "validate" {
                    OpenSslConnector::new(&config).map_err(|e| e.to_string())?;
                    return Ok(json!("Configuration and credentials valid. Connectivity is checked when the relay starts."));
                }
                if self.status().running {
                    return Err("Stop the relay before applying settings".into());
                }
                if command == "save_config" {
                    config.save(&self.path)?;
                    self.config = config;
                    return Ok(json!(true));
                }
                let connector = OpenSslConnector::new(&config).map_err(|e| e.to_string())?;
                self.stop();
                self.relay = Some(Relay::start(config.clone(), Arc::new(connector))?);
                self.config = config;
                Ok(json!(self.status()))
            }
            _ => Err("Unknown management command".into()),
        }
    }
}

pub fn bind(address: SocketAddr) -> Result<Server, String> {
    if address.port() == 0 {
        return Err("HTTP port must be between 1 and 65535".into());
    }
    Server::http(address).map_err(|e| format!("Cannot bind HTTP UI: {e}"))
}
pub(crate) fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}
fn valid_host(host: &str, address: SocketAddr) -> bool {
    if address.ip().is_loopback() && host == format!("localhost:{}", address.port()) {
        return true;
    }
    let Ok(host) = host.parse::<SocketAddr>() else {
        return false;
    };
    host.port() == address.port()
        && (host.ip() == address.ip()
            || (address.ip().is_unspecified() && host.is_ipv4() == address.is_ipv4()))
}
pub fn handle(
    request: Request,
    address: SocketAddr,
    agent: &mut Agent,
    auth: &mut Option<crate::auth::Auth>,
) {
    if request.url().len() > 8192 {
        respond(request, 414, "text/plain", b"Request URL too long".to_vec());
        return;
    }
    let host = header(&request, "Host").unwrap_or("").to_string();
    let valid = auth
        .as_ref()
        .map(|auth| auth.valid_request(&request))
        .unwrap_or_else(|| {
            valid_host(&host, address)
                && header(&request, "Origin").is_none_or(|o| o == format!("http://{host}"))
        });
    if !valid {
        respond(request, 403, "text/plain", b"Forbidden origin".to_vec());
        return;
    }
    let mut request = if let Some(auth) = auth {
        let Some(request) = auth.gate(request) else {
            return;
        };
        request
    } else {
        request
    };
    let path = request.url().to_string();
    if request.method() == &Method::Get {
        let asset: Option<(&str, &[u8])> = match path.as_str() {
            "/" | "/index.html" => Some((
                "text/html; charset=utf-8",
                include_bytes!("../../../ui/index.html"),
            )),
            "/app.js" => Some(("text/javascript", include_bytes!("../../../ui/app.js"))),
            "/style.css" => Some(("text/css", include_bytes!("../../../ui/style.css"))),
            "/icon.svg" => Some(("image/svg+xml", include_bytes!("../../../ui/icon.svg"))),
            "/agent-mode.js" => Some((
                "text/javascript",
                if auth.is_some() {
                    b"window.__SYSLOG_HTTP__ = true; window.__SYSLOG_OIDC__ = true;"
                } else {
                    b"window.__SYSLOG_HTTP__ = true;"
                },
            )),
            _ => None,
        };
        if let Some((mime, body)) = asset {
            respond(request, 200, mime, body.to_vec());
        } else {
            respond(request, 404, "text/plain", b"Not found".to_vec());
        }
        return;
    }
    if request.method() != &Method::Post || !path.starts_with("/api/") {
        respond(request, 405, "text/plain", b"Method not allowed".to_vec());
        return;
    }
    // A custom header and JSON content type prevent cross-site form submissions.
    // No CORS headers are issued. Host validation also prevents DNS rebinding.
    if header(&request, "X-Syslog-UI") != Some("1")
        || header(&request, "Content-Type") != Some("application/json")
    {
        respond(request, 403, "text/plain", b"Forbidden request".to_vec());
        return;
    }
    if request.body_length().is_none_or(|n| n > 65536) {
        respond(
            request,
            413,
            "text/plain",
            b"Request too large or missing length".to_vec(),
        );
        return;
    }
    let mut body = String::new();
    let result = request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|_| "Cannot read request".to_string())
        .and_then(|_| serde_json::from_str(&body).map_err(|_| "Invalid JSON".to_string()))
        .and_then(|args| agent.command(&path[5..], args));
    let (code, value) = match result {
        Ok(value) => (200, value),
        Err(error) => (400, json!({"error":error})),
    };
    respond(
        request,
        code,
        "application/json",
        value.to_string().into_bytes(),
    );
}
pub(crate) fn respond(request: Request, code: u16, mime: &str, body: Vec<u8>) {
    respond_with(request, code, mime, body, &[]);
}
pub(crate) fn respond_with(
    request: Request,
    code: u16,
    mime: &str,
    body: Vec<u8>,
    headers: &[(&str, String)],
) {
    let mut response = Response::from_data(body).with_status_code(code);
    for (name,value) in [("Referrer-Policy","no-referrer"),("Content-Type",mime),("Cache-Control","no-store"),("X-Content-Type-Options","nosniff"),("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'")] {
        response.add_header(Header::from_bytes(name,value).unwrap());
    }
    for (name, value) in headers {
        response.add_header(Header::from_bytes(*name, value.as_bytes()).unwrap());
    }
    let _ = request.respond(response);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_rejects_rebinding_and_other_ports() {
        let address = "127.0.0.1:1080".parse().unwrap();
        assert!(valid_host("127.0.0.1:1080", address));
        assert!(valid_host("localhost:1080", address));
        assert!(!valid_host("evil.example:1080", address));
        assert!(!valid_host("localhost:1081", address));
        assert!(!valid_host(
            "localhost:1080",
            "192.0.2.1:1080".parse().unwrap()
        ));
        assert!(valid_host(
            "192.0.2.1:1080",
            "0.0.0.0:1080".parse().unwrap()
        ));
        assert!(!valid_host(
            "evil.example:1080",
            "0.0.0.0:1080".parse().unwrap()
        ));
        assert!(valid_host("[::1]:1080", "[::]:1080".parse().unwrap()));
        assert!(bind("127.0.0.1:0".parse().unwrap()).is_err());
    }
}
