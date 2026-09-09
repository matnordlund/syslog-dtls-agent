use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Status {
    pub running: bool,
    pub listener_status: String,
    pub listener_address: String,
    pub dtls_status: String,
    pub remote_destination: String,
    pub remote_address: Option<String>,
    pub messages_received: u64,
    pub messages_forwarded: u64,
    pub messages_dropped: u64,
    pub drops: Drops,
    pub queue_depth: usize,
    pub queue_bytes: usize,
    pub in_flight: bool,
    pub last_received_ms: Option<u64>,
    pub last_forwarded_ms: Option<u64>,
    pub last_handshake_ms: Option<u64>,
    pub last_error: Option<String>,
    pub retry_attempts: u64,
    pub peer_fingerprint: Option<String>,
    pub client_fingerprint: Option<String>,
    pub cipher: Option<String>,
    pub protocol: Option<String>,
    pub sources: Vec<SourceStatus>,
    pub source_tracking_limit: usize,
    pub untracked_source_messages: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct SourceStatus {
    pub ip: std::net::IpAddr,
    pub allowed: bool,
    pub messages_received: u64,
    pub messages_forwarded: u64,
    pub messages_dropped: u64,
    pub messages_per_second: u64,
    pub messages_per_minute: u64,
    pub messages_last_24h: u64,
    pub last_seen_ms: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Drops {
    pub invalid: u64,
    pub oversized: u64,
    pub queue_full: u64,
    pub shutdown: u64,
    pub source_denied: u64,
}
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
