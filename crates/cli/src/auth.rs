//! Browser OIDC sessions. An ID token is retained only for the provider logout POST; never logged.
use crate::web::{header, respond, respond_with};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJsonWebKeySet,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
    reqwest, AccessTokenHash, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdToken, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    io::Read,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use syslog_agent_core::oidc::{http_url, Oidc};
use tiny_http::{Method, Request};

// Debug builds only. Never pass raw provider errors, bodies, headers or full login URLs.
macro_rules! oidc_debug {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) { eprintln!("[oidc] {}", format_args!($($arg)*)); }
    };
}

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
type GroupToken = IdToken<
    ExtraClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExtraClaims {
    #[serde(flatten)]
    values: Map<String, Value>,
}
impl AdditionalClaims for ExtraClaims {}
struct Flow {
    logout_endpoint: Option<String>,
    issuer: String,
    client: Client,
    state: CsrfToken,
    nonce: Nonce,
    pkce: PkceCodeVerifier,
    expires: Instant,
}
struct ProviderLogout {
    endpoint: String,
    id_token: String,
}
struct Session {
    expires: Instant,
    username: String,
    provider_logout: Option<ProviderLogout>,
}
struct PendingLogout {
    expires: Instant,
    provider: ProviderLogout,
}
struct Login {
    lifetime: u64,
    username: String,
    provider_logout: Option<ProviderLogout>,
}
pub struct Auth {
    config: Oidc,
    secret: Option<ClientSecret>,
    http: reqwest::blocking::Client,
    origin: String,
    authority: String,
    secure: bool,
    flows: HashMap<String, Flow>,
    sessions: HashMap<String, Session>,
    logouts: HashMap<String, PendingLogout>,
}
impl Auth {
    pub fn new(config: &Oidc) -> Result<Option<Self>, String> {
        config
            .validate()
            .inspect_err(|_| oidc_debug!("Configuration validation failed"))?;
        if !config.enabled {
            oidc_debug!("Authentication disabled for this HTTP listener (settings take effect at process startup)");
            return Ok(None);
        }
        let url = http_url(&config.public_url)?;
        let origin = url.origin().ascii_serialization();
        let authority = origin.split_once("://").unwrap().1.to_owned();
        let secret = if config.client_secret.is_empty() {
            None
        } else {
            Some(ClientSecret::new(config.client_secret.clone()))
        };
        let http = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "Cannot initialize OIDC HTTPS client".to_string())?;
        oidc_debug!(
            "Authentication enabled; discovery={:?}; client_id={:?}; client_secret_configured={}",
            diagnostic_url(&config.discovery_uri),
            config.client_id,
            secret.is_some()
        );
        oidc_debug!(
            "redirect_uri={:?}; response_type=code; PKCE=S256; token_auth={}; scopes={:?}",
            format!("{origin}/auth/callback"),
            if secret.is_some() {
                "client_secret_basic"
            } else {
                "public client (no secret)"
            },
            std::iter::once("openid")
                .chain(
                    config
                        .scopes
                        .iter()
                        .map(String::as_str)
                        .filter(|scope| *scope != "openid")
                )
                .collect::<Vec<_>>()
        );
        oidc_debug!(
            "Group authorization: claim={:?}; required_group={:?}; secure_cookies={}",
            config.groups_claim,
            config.required_group,
            url.scheme() == "https"
        );
        Ok(Some(Self {
            config: config.clone(),
            secret,
            http,
            origin,
            authority,
            secure: url.scheme() == "https",
            flows: HashMap::new(),
            sessions: HashMap::new(),
            logouts: HashMap::new(),
        }))
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn valid_request(&self, request: &Request) -> bool {
        let valid = header(request, "Host") == Some(self.authority.as_str())
            && header(request, "Origin").is_none_or(|o| o == self.origin);
        if !valid {
            oidc_debug!(
                "Request rejected: Host/Origin does not match public URL {:?}",
                self.origin
            );
        }
        valid
    }
    fn cookie_name(&self, kind: &str) -> String {
        format!("{}syslog_{kind}", if self.secure { "__Host-" } else { "" })
    }
    fn cookie(&self, kind: &str, value: &str, age: u64) -> String {
        format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{}",
            self.cookie_name(kind),
            if self.secure { "; Secure" } else { "" }
        )
    }
    fn prune(&mut self) {
        let now = Instant::now();
        self.flows.retain(|_, f| f.expires > now);
        self.sessions.retain(|_, session| session.expires > now);
        self.logouts.retain(|_, logout| logout.expires > now);
    }
    fn login(&mut self, request: Request) {
        if self.flows.len() >= 64 {
            respond(
                request,
                503,
                "text/plain",
                b"Too many pending logins. Try again later.".to_vec(),
            );
            return;
        }
        oidc_debug!("Login started; fetching discovery metadata");
        let result = self.begin_login();
        match result {
            Ok((url, key, flow)) => {
                if let Some(old) = cookie_value(&request, &self.cookie_name("flow")) {
                    self.flows.remove(&old);
                }
                self.flows.insert(key.clone(), flow);
                respond_with(
                    request,
                    303,
                    "text/plain",
                    vec![],
                    &[
                        ("Location", url),
                        ("Set-Cookie", self.cookie("flow", &key, 300)),
                    ],
                );
            }
            Err(reason) => {
                oidc_debug!("Login setup failed: {reason}");
                login_error(
                    request,
                    503,
                    "Identity provider is unavailable or misconfigured.",
                );
            }
        }
    }
    fn begin_login(&self) -> Result<(String, String, Flow), String> {
        let client_http = |request| provider_request(&self.http, request, "discovery");
        let request = openidconnect::http::Request::builder()
            .uri(&self.config.discovery_uri)
            .header("Accept", "application/json")
            .body(Vec::new())
            .map_err(|_| "discovery request")?;
        let response = client_http(request).map_err(|_| "discovery")?;
        if response.status() != openidconnect::http::StatusCode::OK {
            return Err("discovery failed".into());
        }
        let document: Value =
            serde_json::from_slice(response.body()).map_err(|_| "discovery metadata")?;
        let logout_endpoint = document
            .get("end_session_endpoint")
            .and_then(Value::as_str)
            .filter(|url| http_url(url).is_ok())
            .map(str::to_owned);
        oidc_debug!(
            "Provider logout endpoint: {:?}",
            logout_endpoint.as_deref().map(diagnostic_url)
        );
        let metadata: CoreProviderMetadata =
            serde_json::from_slice(response.body()).map_err(|_| "discovery metadata")?;
        if http_url(metadata.issuer().as_str())?.query().is_some() {
            return Err("Invalid issuer".into());
        }
        let issuer = metadata.issuer().as_str().to_owned();
        oidc_debug!("Discovery parsed successfully; issuer={:?}; authorization_endpoint={:?}; token_endpoint={:?}; jwks_uri={:?}",
            diagnostic_url(&issuer), diagnostic_url(metadata.authorization_endpoint().as_str()),
            metadata.token_endpoint().map(|url| diagnostic_url(url.as_str())), diagnostic_url(metadata.jwks_uri().as_str()));
        let keys = CoreJsonWebKeySet::fetch(metadata.jwks_uri(), &|request| {
            provider_request(&self.http, request, "JWKS")
        })
        .map_err(|_| "JWKS response invalid or unavailable")?;
        oidc_debug!(
            "JWKS parsed successfully; signing_keys={}",
            keys.keys().len()
        );
        let metadata = metadata.set_jwks(keys);
        http_url(metadata.authorization_endpoint().as_str())?;
        let token_url = metadata.token_endpoint().ok_or("Missing token endpoint")?;
        http_url(token_url.as_str())?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            self.secret.clone(),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/auth/callback", self.origin)).map_err(|_| "redirect")?,
        );
        let (challenge, pkce) = PkceCodeChallenge::new_random_sha256();
        let mut authorization = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.config.scopes {
            if scope != "openid" {
                authorization = authorization.add_scope(Scope::new(scope.clone()));
            }
        }
        let (mut url, state, nonce) = authorization.url();
        order_authorization_parameters(&mut url);
        oidc_debug!("Redirecting browser to authorization endpoint {:?}; waiting for /auth/callback. If the IdP shows HTTP 400 here, check its registered redirect URI, client ID, scopes and PKCE support; that browser response is not visible to the agent.",
            diagnostic_url(url.as_str()));
        Ok((
            url.to_string(),
            CsrfToken::new_random().secret().clone(),
            Flow {
                logout_endpoint,
                issuer,
                client,
                state,
                nonce,
                pkce,
                expires: Instant::now() + Duration::from_secs(300),
            },
        ))
    }
    fn callback(&mut self, request: Request) {
        oidc_debug!("Authorization callback received (parameters withheld)");
        // A state value alone is not sufficient: bind each flow to its initiating browser.
        let flow = cookie_value(&request, &self.cookie_name("flow"))
            .and_then(|key| self.flows.remove(&key));
        let result = flow
            .ok_or("Login expired or not initiated in this browser".to_string())
            .and_then(|flow| self.finish_login(request.url(), flow));
        match result {
            Ok(login) if self.sessions.len() < 128 => {
                let lifetime = login.lifetime;
                oidc_debug!("Login successful; group authorized; session lifetime={lifetime}s");
                if let Some(old) = cookie_value(&request, &self.cookie_name("session")) {
                    self.sessions.remove(&old);
                }
                let key = CsrfToken::new_random().secret().clone();
                self.sessions.insert(
                    key.clone(),
                    Session {
                        expires: Instant::now() + Duration::from_secs(lifetime),
                        username: login.username,
                        provider_logout: login.provider_logout,
                    },
                );
                respond_with(
                    request,
                    303,
                    "text/plain",
                    vec![],
                    &[
                        ("Location", "/".into()),
                        ("Set-Cookie", self.cookie("session", &key, lifetime)),
                        ("Set-Cookie", self.cookie("flow", "", 0)),
                    ],
                );
            }
            Ok(_) => login_error(request, 503, "Session limit reached. Try again later."),
            Err(reason) => {
                oidc_debug!("Login denied: {reason}");
                login_error(request,403,"Login denied. Check your group membership and the provider configuration, then try again.");
            }
        }
    }
    fn finish_login(&self, path: &str, flow: Flow) -> Result<Login, String> {
        let query = path
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or("Missing callback")?;
        let mut params = HashMap::new();
        for (key, value) in openidconnect::url::form_urlencoded::parse(query.as_bytes()) {
            if params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err("Duplicate callback parameter".into());
            }
        }
        if flow.expires <= Instant::now()
            || params
                .get("state")
                .is_none_or(|state| CsrfToken::new(state.clone()) != flow.state)
        {
            return Err("Invalid state".into());
        }
        if let Some(error) = params.get("error") {
            oidc_debug!(
                "Provider rejected authorization: error={}; error_description withheld",
                oauth_error_code(error)
            );
            return Err("Provider rejected authorization".into());
        }
        // RFC 9207 issuer parameter, when supplied, must match the configured issuer.
        if params.get("iss").is_some_and(|iss| iss != &flow.issuer) {
            return Err("Invalid callback issuer".into());
        }
        let code = params
            .remove("code")
            .filter(|c| !c.is_empty())
            .ok_or("Missing code")?;
        let tokens = flow
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| "exchange")?
            .set_pkce_verifier(flow.pkce)
            .request(&|request| provider_request(&self.http, request, "token exchange"))
            .map_err(|_| "token exchange")?;
        // Parse extension claims with the OIDC library, then verify the entire signed token.
        let token: GroupToken = tokens
            .id_token()
            .ok_or("Missing ID token")?
            .to_string()
            .parse()
            .map_err(|_| "Invalid ID token")?;
        let verifier = flow.client.id_token_verifier();
        let claims = token
            .claims(&verifier, &flow.nonce)
            .map_err(|error| claims_failure(&error))?;
        oidc_debug!("ID token signature, issuer, audience and nonce verified");
        oidc_debug!(
            "Verified ID-token claims (sensitive fields redacted): {}",
            diagnostic_claims(claims)
        );
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                tokens.access_token(),
                token.signing_alg().map_err(|_| "algorithm")?,
                token.signing_key(&verifier).map_err(|_| "key")?,
            )
            .map_err(|_| "access token hash")?;
            if actual != *expected {
                return Err("Invalid access token hash".into());
            }
        }
        let additional = &claims.additional_claims().values;
        let group_value = additional.get(&self.config.groups_claim);
        let group_result = group_check(group_value, &self.config.required_group);
        oidc_debug!(
            "Group check: claim={:?}; required_group={:?}; result={}",
            self.config.groups_claim,
            self.config.required_group,
            group_result
        );
        if group_value.is_none() {
            oidc_debug!(
                "Available ID-token extension claim names (values withheld): {:?}",
                additional
                    .keys()
                    .take(32)
                    .map(|name| name.chars().take(128).collect::<String>())
                    .collect::<Vec<_>>()
            );
        }
        if !has_group(group_value, &self.config.required_group) {
            return Err(format!("Required group missing: {group_result}"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock")?
            .as_secs() as i64;
        if claims
            .authorized_party()
            .is_some_and(|party| party.as_str() != self.config.client_id)
            || claims.issue_time().timestamp() > now + 60
        {
            return Err("Invalid token claims".into());
        }
        if let Some(nbf) = claims.additional_claims().values.get("nbf") {
            if nbf.as_i64().is_none_or(|value| value > now + 60) {
                return Err("Token not yet valid".into());
            }
        }
        let seconds = (claims.expiration().timestamp() - now).clamp(0, 3600) as u64;
        if seconds == 0 {
            return Err("Expired token".into());
        }
        let username = claims
            .preferred_username()
            .map(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .or_else(|| {
                claims
                    .email()
                    .map(|value| value.as_str())
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_else(|| claims.subject().as_str())
            .to_owned();
        Ok(Login {
            lifetime: seconds,
            username,
            provider_logout: flow.logout_endpoint.map(|endpoint| ProviderLogout {
                endpoint,
                id_token: token.to_string(),
            }),
        })
    }
    /// All UI assets and API commands pass through this gate.
    pub fn gate(&mut self, request: Request) -> Option<Request> {
        self.prune();
        let path = request.url().split('?').next().unwrap_or("");
        if request.method() == &Method::Get && path == "/auth/login" {
            self.login(request);
            return None;
        }
        if request.method() == &Method::Get && path == "/auth/callback" {
            self.callback(request);
            return None;
        }
        if request.method() == &Method::Get && path == "/auth/end-session" {
            self.end_session(request);
            return None;
        }
        if request.method() == &Method::Get && path == "/auth/logout.js" {
            respond(
                request,
                200,
                "text/javascript",
                b"document.getElementById('provider-logout').submit();".to_vec(),
            );
            return None;
        }
        let session = cookie_value(&request, &self.cookie_name("session"));
        let authenticated = session
            .as_ref()
            .is_some_and(|key| self.sessions.contains_key(key));
        if path == "/auth/logout" && request.method() == &Method::Post {
            if header(&request, "X-Syslog-UI") != Some("1") || !authenticated {
                respond(request, 403, "text/plain", b"Forbidden".to_vec());
            } else {
                let session = self.sessions.remove(session.as_ref().unwrap()).unwrap();
                let mut headers = vec![("Set-Cookie", self.cookie("session", "", 0))];
                let redirect = if let Some(provider) =
                    session.provider_logout.filter(|_| self.logouts.len() < 128)
                {
                    if let Some(old) = cookie_value(&request, &self.cookie_name("logout")) {
                        self.logouts.remove(&old);
                    }
                    let key = CsrfToken::new_random().secret().clone();
                    self.logouts.insert(
                        key.clone(),
                        PendingLogout {
                            expires: Instant::now() + Duration::from_secs(60),
                            provider,
                        },
                    );
                    headers.push(("Set-Cookie", self.cookie("logout", &key, 60)));
                    "/auth/end-session"
                } else {
                    "/auth/signed-out"
                };
                oidc_debug!(
                    "Local session signed out; provider logout available={}",
                    redirect == "/auth/end-session"
                );
                respond_with(
                    request,
                    200,
                    "application/json",
                    serde_json::json!({"redirect":redirect})
                        .to_string()
                        .into_bytes(),
                    &headers,
                );
            }
            return None;
        }
        if request.method() == &Method::Get && path == "/auth/signed-out" {
            login_error(request, 200, "You are signed out of this agent.");
            return None;
        }
        if !authenticated {
            if path == "/auth/session"
                || request.url().starts_with("/api/")
                || request.method() != &Method::Get
            {
                respond(
                    request,
                    401,
                    "application/json",
                    br#"{"error":"Sign in required"}"#.to_vec(),
                );
            } else {
                respond_with(
                    request,
                    303,
                    "text/plain",
                    vec![],
                    &[("Location", "/auth/login".into())],
                );
            }
            return None;
        }
        if path == "/auth/session" && request.method() == &Method::Get {
            let identity = &self.sessions[session.as_ref().unwrap()].username;
            respond(
                request,
                200,
                "application/json",
                serde_json::json!({"username":identity})
                    .to_string()
                    .into_bytes(),
            );
            return None;
        }
        Some(request)
    }
    fn end_session(&mut self, request: Request) {
        let logout = cookie_value(&request, &self.cookie_name("logout"))
            .and_then(|key| self.logouts.remove(&key));
        let Some(logout) = logout else {
            login_error(request,200,"You are signed out of this agent. The provider logout request has expired or was already used.");
            return;
        };
        let provider = logout.provider;
        oidc_debug!(
            "Submitting browser logout to provider {:?}",
            diagnostic_url(&provider.endpoint)
        );
        let html = format!(
            r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Signing out — Syslog DTLS Agent</title><h1>Signing out</h1><form id="provider-logout" method="post" action="{}"><input type="hidden" name="id_token_hint" value="{}"><input type="hidden" name="client_id" value="{}"><input type="hidden" name="post_logout_redirect_uri" value="{}"><button type="submit">Continue signing out at your identity provider</button></form><script src="/auth/logout.js"></script></html>"#,
            html_attribute(&provider.endpoint),
            html_attribute(&provider.id_token),
            html_attribute(&self.config.client_id),
            html_attribute(&format!("{}/auth/signed-out", self.origin))
        );
        let provider_origin = http_url(&provider.endpoint)
            .unwrap()
            .origin()
            .ascii_serialization();
        respond_with(
            request,
            200,
            "text/html; charset=utf-8",
            html.into_bytes(),
            &[
                ("Set-Cookie", self.cookie("logout", "", 0)),
                (
                    "Content-Security-Policy",
                    format!("form-action 'self' {provider_origin}; frame-ancestors 'none'"),
                ),
            ],
        );
    }
}
fn html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
/// Preserve every value while matching providers sensitive to query ordering.
fn order_authorization_parameters(url: &mut openidconnect::url::Url) {
    let order = [
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ];
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.sort_by_key(|(key, _)| {
        order
            .iter()
            .position(|name| *name == key)
            .unwrap_or(order.len())
    });
    url.query_pairs_mut().clear().extend_pairs(pairs);
}
fn diagnostic_claims(claims: &impl Serialize) -> Value {
    fn redact(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for (name, value) in fields {
                    let name = name.to_ascii_lowercase();
                    if matches!(
                        name.as_str(),
                        "nonce"
                            | "sid"
                            | "jti"
                            | "state"
                            | "at_hash"
                            | "c_hash"
                            | "s_hash"
                            | "code"
                            | "authorization"
                            | "cookie"
                            | "set-cookie"
                            | "session_id"
                    ) || name.contains("token")
                        || name.contains("secret")
                        || name.contains("password")
                        || name.contains("private_key")
                        || name.starts_with("code_")
                    {
                        *value = Value::String("[REDACTED]".into());
                    } else {
                        redact(value);
                    }
                }
            }
            Value::Array(values) => values.iter_mut().for_each(redact),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(claims)
        .unwrap_or(Value::String("[claims serialization failed]".into()));
    redact(&mut value);
    value
}
fn group_check(value: Option<&Value>, required: &str) -> &'static str {
    match value {
        None => "configured claim absent from ID token",
        Some(Value::String(group)) if group.contains(',') && string_has_group(group, required) => {
            "matched comma-separated group"
        }
        Some(Value::String(group)) if group == required => "matched string",
        Some(Value::String(group)) if group.contains(',') => {
            if group
                .split(',')
                .map(str::trim)
                .any(|g| !g.is_empty() && g.eq_ignore_ascii_case(required))
            {
                "comma-separated group differs in letter case (matching is case-sensitive)"
            } else {
                "required group not found in comma-separated string"
            }
        }
        Some(Value::String(group)) if group.eq_ignore_ascii_case(required) => {
            "string differs in letter case (matching is case-sensitive)"
        }
        Some(Value::String(_)) => "string does not equal required group",
        Some(Value::Array(groups)) if !groups.iter().all(Value::is_string) => {
            "claim array contains non-string values"
        }
        Some(Value::Array(groups)) if groups.is_empty() => "claim array is empty",
        Some(Value::Array(groups)) if groups.iter().any(|g| g.as_str() == Some(required)) => {
            "matched string-array member"
        }
        Some(Value::Array(groups))
            if groups
                .iter()
                .any(|g| g.as_str().is_some_and(|g| g.eq_ignore_ascii_case(required))) =>
        {
            "array member differs in letter case (matching is case-sensitive)"
        }
        Some(Value::Array(_)) => "required group not found in string array",
        _ => "claim has unsupported type (expected string or string array)",
    }
}
// Some providers encode a group list as a comma-separated string instead of an array.
// Array members remain literal group names; only the scalar string uses this convention.
fn string_has_group(groups: &str, required: &str) -> bool {
    if required.is_empty() {
        return false;
    }
    if groups.contains(',') {
        groups
            .split(',')
            .map(str::trim)
            .any(|group| !group.is_empty() && group == required)
    } else {
        groups == required
    }
}
fn has_group(value: Option<&Value>, required: &str) -> bool {
    match value {
        Some(Value::String(group)) => string_has_group(group, required),
        Some(Value::Array(groups)) => {
            groups.iter().all(Value::is_string)
                && groups.iter().any(|g| g.as_str() == Some(required))
        }
        _ => false,
    }
}
fn cookie_value(request: &Request, name: &str) -> Option<String> {
    let mut values = request
        .headers()
        .iter()
        .filter(|h| h.field.as_str().as_str().eq_ignore_ascii_case("cookie"))
        .flat_map(|h| h.value.as_str().split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| value);
    let value = values.next()?;
    if values.next().is_some() || value.len() > 128 {
        return None;
    }
    Some(value.to_owned())
}
fn login_error(request: Request, code: u16, message: &str) {
    // Callers provide static messages only; never interpolate provider responses.
    respond(request,code,"text/html; charset=utf-8",format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Syslog DTLS Agent — Login</title><h1>Syslog DTLS Agent</h1><p>{message}</p><a href=\"/auth/login\">Sign in</a></html>"
    ).into_bytes());
}
fn provider_request(
    client: &reqwest::blocking::Client,
    request: openidconnect::HttpRequest,
    stage: &str,
) -> Result<openidconnect::HttpResponse, std::io::Error> {
    let error = || std::io::Error::other("OIDC provider request failed");
    let started = Instant::now();
    oidc_debug!(
        "{stage}: {} {:?}",
        request.method(),
        diagnostic_url(&request.uri().to_string())
    );
    http_url(&request.uri().to_string()).map_err(|_| error())?;
    let mut result = client
        .execute(request.try_into().map_err(|_| error())?)
        .map_err(|failure| {
            oidc_debug!(
                "{stage}: request failed after {}ms: {}",
                started.elapsed().as_millis(),
                if failure.is_timeout() {
                    "timeout"
                } else if failure.is_connect() {
                    "connection failed (check DNS, reachability and TLS certificate trust)"
                } else {
                    "HTTP transport error"
                }
            );
            error()
        })?;
    oidc_debug!(
        "{stage}: HTTP {} after {}ms",
        result.status().as_u16(),
        started.elapsed().as_millis()
    );
    let status = result.status();
    let mut response = openidconnect::http::Response::builder().status(result.status());
    *response.headers_mut().ok_or_else(error)? = result.headers().clone();
    let mut body = Vec::new();
    (&mut result)
        .take(1_048_577)
        .read_to_end(&mut body)
        .map_err(|_| error())?;
    if body.len() > 1_048_576 {
        oidc_debug!("{stage}: response exceeded 1 MiB limit");
        return Err(error());
    }
    if !status.is_success() {
        let value = serde_json::from_slice::<Value>(&body).ok();
        let code = value
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(Value::as_str);
        oidc_debug!(
            "{stage}: provider error={}; response body and error_description withheld",
            code.map(oauth_error_code)
                .unwrap_or("not a recognized OAuth JSON error")
        );
    }
    response.body(body).map_err(|_| error())
}
// URL query parameters may contain credentials, codes or provider-specific secrets.
fn diagnostic_url(value: &str) -> String {
    let Ok(mut url) = openidconnect::url::Url::parse(value) else {
        return "[invalid URL]".into();
    };
    let has_query = url.query().is_some();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    format!("{}{}", url, if has_query { " [query omitted]" } else { "" })
}
fn oauth_error_code(value: &str) -> &'static str {
    match value {
        "invalid_request" => "invalid_request",
        "invalid_client" => "invalid_client",
        "invalid_grant" => "invalid_grant",
        "unauthorized_client" => "unauthorized_client",
        "unsupported_grant_type" => "unsupported_grant_type",
        "unsupported_response_type" => "unsupported_response_type",
        "invalid_scope" => "invalid_scope",
        "access_denied" => "access_denied",
        "server_error" => "server_error",
        "temporarily_unavailable" => "temporarily_unavailable",
        "login_required" => "login_required",
        "interaction_required" => "interaction_required",
        _ => "unrecognized provider error (value withheld)",
    }
}
fn claims_failure(error: &openidconnect::ClaimsVerificationError) -> &'static str {
    use openidconnect::ClaimsVerificationError::*;
    match error {
        Expired(_) => "ID token expired",
        InvalidAudience(_) => "ID token audience mismatch",
        InvalidIssuer(_) => "ID token issuer mismatch",
        InvalidNonce(_) => "ID token nonce mismatch",
        SignatureVerification(_) => "ID token signature/key/algorithm verification failed",
        InvalidSubject(_) => "ID token subject invalid",
        _ => "ID token claims validation failed",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn logout_form_attributes_escape_untrusted_text() {
        assert_eq!(
            html_attribute("<x a='b'>&\""),
            "&lt;x a=&#39;b&#39;&gt;&amp;&quot;"
        );
    }
    #[test]
    fn comma_separated_groups_match_whole_case_sensitive_names() {
        let groups = json!("Administrator,Remote_VPN,relay");
        assert!(has_group(Some(&groups), "Administrator"));
        assert!(has_group(Some(&groups), "Remote_VPN"));
        assert!(has_group(Some(&groups), "relay"));
        assert_eq!(
            group_check(Some(&groups), "relay"),
            "matched comma-separated group"
        );
        for required in [
            "Relay",
            "rel",
            "lay",
            "Admin",
            "",
            "Administrator,Remote_VPN,relay",
        ] {
            assert!(!has_group(Some(&groups), required));
        }
        assert!(has_group(
            Some(&json!("Administrator, Remote_VPN, relay ,,")),
            "relay"
        ));
        assert!(!has_group(
            Some(&json!("Administrator,relay-admin")),
            "relay"
        ));
        assert!(!has_group(Some(&json!(["Administrator,relay"])), "relay"));
        assert!(has_group(Some(&json!(["Administrator", "relay"])), "relay"));
        assert!(has_group(Some(&json!("relay")), "relay"));
    }
    #[test]
    fn claim_diagnostics_show_groups_and_identity_but_redact_sensitive_fields() {
        let input = json!({"groups":"Administrator","email":"test@example.invalid","nonce":"nonce-secret",
            "sid":"session-secret","at_hash":"hash-secret","nested":{"client_secret":"client-secret"},
            "items":[{"access_token":"token-secret"}]});
        let result = diagnostic_claims(&input);
        assert_eq!(result["groups"], "Administrator");
        assert_eq!(result["email"], "test@example.invalid");
        for value in [
            "nonce-secret",
            "session-secret",
            "hash-secret",
            "client-secret",
            "token-secret",
        ] {
            assert!(!result.to_string().contains(value));
        }
    }
    #[test]
    fn administrator_claim_and_parameter_order() {
        let extra: ExtraClaims = serde_json::from_value(json!({"groups":"Administrator"})).unwrap();
        assert!(has_group(extra.values.get("groups"), "Administrator"));
        assert_eq!(
            group_check(extra.values.get("group"), "Administrator"),
            "configured claim absent from ID token"
        );
        assert!(!has_group(extra.values.get("groups"), "administrator"));
        assert!(has_group(Some(&json!(["Administrator"])), "Administrator"));
        let mut url = openidconnect::url::Url::parse("https://id.example/login?response_type=code&client_id=client&state=a&code_challenge=b&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A1080%2Fauth%2Fcallback&scope=openid+profile&nonce=c").unwrap();
        let mut before = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        order_authorization_parameters(&mut url);
        assert_eq!(
            url.query_pairs()
                .map(|(k, _)| k.into_owned())
                .collect::<Vec<_>>(),
            [
                "response_type",
                "client_id",
                "redirect_uri",
                "state",
                "code_challenge",
                "code_challenge_method",
                "nonce",
                "scope"
            ]
        );
        let mut after = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        before.sort();
        after.sort();
        assert_eq!(before, after);
    }
    #[test]
    fn diagnostics_redact_url_credentials_and_untrusted_error_values() {
        assert_eq!(
            diagnostic_url("https://user:secret@id.example/discovery?key=sensitive#token"),
            "https://id.example/discovery [query omitted]"
        );
        assert_eq!(oauth_error_code("invalid_client"), "invalid_client");
        assert!(!oauth_error_code("token-secret\nforged-log").contains("token-secret"));
        assert_eq!(
            claims_failure(&openidconnect::ClaimsVerificationError::InvalidNonce(
                "secret nonce".into()
            )),
            "ID token nonce mismatch"
        );
    }
    #[test]
    fn group_membership_is_exact_and_fails_closed() {
        for value in [
            json!(null),
            json!(true),
            json!({"operators":true}),
            json!(["operators", 1]),
            json!(["Operators"]),
            json!(["operators-extra"]),
            json!([]),
        ] {
            assert!(!has_group(Some(&value), "operators"));
        }
        assert!(!has_group(None, "operators"));
        assert!(has_group(Some(&json!(["other", "operators"])), "operators"));
        assert!(has_group(Some(&json!("operators")), "operators"));
    }
}
