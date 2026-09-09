use crate::Config;
use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);

pub enum WriteOutcome {
    Sent,
    WouldBlock,
}
pub struct PeerInfo {
    pub fingerprint: String,
    pub cipher: String,
    pub protocol: String,
}

pub trait Session: Send {
    fn send(&mut self, frame: &[u8]) -> Result<WriteOutcome, TransportError>;
    fn poll(&mut self) -> Result<(), TransportError>;
    fn max_plaintext(&self) -> usize;
    fn peer_info(&self) -> PeerInfo;
    fn close(&mut self);
}
pub trait Connector: Send + Sync + 'static {
    fn connect(
        &self,
        config: &Config,
        remote: SocketAddr,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Box<dyn Session>, TransportError>;
    fn client_fingerprint(&self) -> String;
}
