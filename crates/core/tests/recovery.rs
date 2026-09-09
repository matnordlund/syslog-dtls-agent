use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use syslog_agent_core::{
    transport::{Connector, PeerInfo, Session, TransportError, WriteOutcome},
    Config, Relay,
};

#[derive(Default)]
struct Control {
    available: AtomicBool,
    fail_next: AtomicBool,
    block: AtomicBool,
    frames: Mutex<Vec<Vec<u8>>>,
}
struct Backend(Arc<Control>);
struct Connection(Arc<Control>);
impl Connector for Backend {
    fn client_fingerprint(&self) -> String {
        "test".into()
    }
    fn connect(
        &self,
        _: &Config,
        _: SocketAddr,
        _: &dyn Fn() -> bool,
    ) -> Result<Box<dyn Session>, TransportError> {
        if self.0.available.load(Ordering::SeqCst) {
            Ok(Box::new(Connection(self.0.clone())))
        } else {
            Err(TransportError("offline".into()))
        }
    }
}
impl Session for Connection {
    fn send(&mut self, frame: &[u8]) -> Result<WriteOutcome, TransportError> {
        if self.0.fail_next.swap(false, Ordering::SeqCst) {
            return Err(TransportError("connection lost".into()));
        }
        if self.0.block.load(Ordering::SeqCst) {
            return Ok(WriteOutcome::WouldBlock);
        }
        self.0.frames.lock().unwrap().push(frame.to_vec());
        Ok(WriteOutcome::Sent)
    }
    fn poll(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn max_plaintext(&self) -> usize {
        1200
    }
    fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            fingerprint: "test".into(),
            cipher: "test".into(),
            protocol: "test".into(),
        }
    }
    fn close(&mut self) {}
}
fn setup(max_bytes: usize) -> (Relay, Arc<Control>, UdpSocket, SocketAddr) {
    setup_access(max_bytes, Default::default())
}
fn setup_access(
    max_bytes: usize,
    access: syslog_agent_core::config::SourceAccess,
) -> (Relay, Arc<Control>, UdpSocket, SocketAddr) {
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let mut cfg = Config::default();
    cfg.listener.port = address.port();
    cfg.remote.host = "127.0.0.1".into();
    cfg.dtls.retry_initial_ms = 100;
    cfg.dtls.retry_max_ms = 100;
    cfg.dtls.shutdown_drain_ms = 0;
    cfg.queue.max_bytes = max_bytes;
    cfg.source_access = access;
    let control = Arc::new(Control::default());
    let relay = Relay::start(cfg, Arc::new(Backend(control.clone()))).unwrap();
    (
        relay,
        control,
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        address,
    )
}
fn wait(mut predicate: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(Instant::now() < until, "timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn recovery_preserves_fifo_and_inflight_across_failed_and_retryable_writes() {
    let (mut relay, control, socket, address) = setup(4096);
    let messages = [
        b"<34>1 - h a p m - first".as_slice(),
        b"<34>1 - h a p m - second",
    ];
    for message in messages {
        socket.send_to(message, address).unwrap();
    }
    wait(|| relay.status().queue_depth == 2);
    control.block.store(true, Ordering::SeqCst);
    control.fail_next.store(true, Ordering::SeqCst);
    control.available.store(true, Ordering::SeqCst);
    wait(|| relay.status().in_flight);
    assert_eq!(relay.status().queue_depth, 2);
    assert_eq!(relay.status().messages_forwarded, 0);
    control.block.store(false, Ordering::SeqCst);
    wait(|| relay.status().messages_forwarded == 2);
    assert_eq!(
        *control.frames.lock().unwrap(),
        messages
            .iter()
            .map(|m| syslog_agent_core::framing::frame(m))
            .collect::<Vec<_>>()
    );
    let s = relay.stop();
    assert_eq!(s.messages_dropped, 0);
    assert_eq!(s.queue_depth, 0);
    assert_eq!(s.sources.len(), 1);
    assert_eq!(s.sources[0].messages_received, 2);
    assert_eq!(s.sources[0].messages_forwarded, 2);
    assert_eq!(s.sources[0].messages_last_24h, 2);
}
#[test]
fn byte_limit_is_enforced_independently_of_message_limit() {
    let message = b"<34>1 - h a p m - test";
    let (mut relay, _, socket, address) = setup(message.len());
    for _ in 0..3 {
        socket.send_to(message, address).unwrap();
    }
    wait(|| relay.status().messages_received == 3);
    let s = relay.status();
    assert_eq!(s.queue_depth, 1);
    assert_eq!(s.queue_bytes, message.len());
    assert_eq!(s.drops.queue_full, 2);
    let s = relay.stop();
    assert_eq!(s.messages_dropped, 3);
    assert_eq!(s.drops.shutdown, 1);
    assert_eq!(s.sources[0].messages_dropped, 3);
}

#[test]
fn allowlist_rejects_before_parsing_or_queueing_including_empty_list() {
    use syslog_agent_core::config::{SourceAccess, SourceMode};
    for allowed_ips in [vec![], vec!["192.0.2.1".parse().unwrap()]] {
        let (mut relay, control, socket, address) = setup_access(
            4096,
            SourceAccess {
                mode: SourceMode::Allowlist,
                allowed_ips,
            },
        );
        control.available.store(true, Ordering::SeqCst);
        socket.send_to(b"not syslog", address).unwrap();
        socket
            .send_to(b"<34>1 - h a p m - denied", address)
            .unwrap();
        wait(|| relay.status().messages_received == 2);
        let s = relay.stop();
        assert_eq!(s.drops.source_denied, 2);
        assert_eq!(s.drops.invalid, 0);
        assert_eq!(s.queue_depth, 0);
        assert_eq!(s.messages_forwarded, 0);
        assert!(control.frames.lock().unwrap().is_empty());
        assert!(!s.sources[0].allowed);
        assert_eq!(s.sources[0].messages_dropped, 2);
    }
}

#[test]
fn allowlisted_ip_ignores_source_port_and_matches_mapped_ipv4() {
    use syslog_agent_core::config::{SourceAccess, SourceMode};
    let (mut relay, control, first, address) = setup_access(
        4096,
        SourceAccess {
            mode: SourceMode::Allowlist,
            allowed_ips: vec!["::ffff:127.0.0.1".parse().unwrap()],
        },
    );
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    control.available.store(true, Ordering::SeqCst);
    for socket in [first, second] {
        socket
            .send_to(b"<34>1 - h a p m - allowed", address)
            .unwrap();
    }
    wait(|| relay.status().messages_forwarded == 2);
    let s = relay.stop();
    assert_eq!(s.sources.len(), 1);
    assert!(s.sources[0].allowed);
    assert_eq!(s.sources[0].ip.to_string(), "127.0.0.1");
    assert_eq!(s.sources[0].messages_last_24h, 2);
    assert_eq!(s.messages_dropped, 0);
}
