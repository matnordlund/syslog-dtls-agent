//! UI-independent, bounded, best-effort syslog relay.
pub mod config;
pub mod framing;
pub mod relay;
mod sources;
pub mod status;
pub mod transport;

pub use config::Config;
pub use relay::Relay;
pub use status::Status;

pub mod oidc;
