use crate::{
    config::{canonical_ip, normalize_name, SourceMode},
    framing,
    sources::{Sources, SOURCE_LIMIT},
    status::now_ms,
    transport::{Connector, WriteOutcome},
    Config, Status,
};
use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

struct Message {
    payload: Arc<[u8]>,
    source: IpAddr,
}

struct State {
    status: Status,
    queue: VecDeque<Message>,
    sources: Sources,
    started: Instant,
    stop_at: Option<Instant>,
}
type Shared = Arc<Mutex<State>>;

/// Owns all relay workers. Dropping stops input and performs bounded draining.
pub struct Relay {
    shared: Shared,
    listener: Option<JoinHandle<()>>,
    sender: Option<JoinHandle<()>>,
    drain: Duration,
}
impl Relay {
    pub fn start(config: Config, connector: Arc<dyn Connector>) -> Result<Self, String> {
        config.validate()?;
        let socket = UdpSocket::bind(SocketAddr::new(
            config.listener.address,
            config.listener.port,
        ))
        .map_err(|e| format!("Cannot bind UDP listener: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|e| e.to_string())?;
        let shared = Arc::new(Mutex::new(State {
            status: Status {
                running: true,
                listener_status: "listening".into(),
                listener_address: socket.local_addr().map_err(|e| e.to_string())?.to_string(),
                dtls_status: "resolving".into(),
                remote_destination: format!("{}:{}", config.remote.host, config.remote.port),
                client_fingerprint: Some(connector.client_fingerprint()),
                ..Status::default()
            },
            queue: VecDeque::new(),
            sources: Sources::default(),
            started: Instant::now(),
            stop_at: None,
        }));
        let cfg = Arc::new(config);
        let (s, c) = (shared.clone(), cfg.clone());
        let listener = thread::Builder::new()
            .name("syslog-input".into())
            .spawn(move || listen(socket, &c, &s))
            .map_err(|e| e.to_string())?;
        let (s, c) = (shared.clone(), cfg.clone());
        let sender = match thread::Builder::new()
            .name("syslog-dtls".into())
            .spawn(move || send(&c, &s, connector))
        {
            Ok(t) => t,
            Err(e) => {
                shared.lock().unwrap().stop_at = Some(Instant::now());
                let _ = listener.join();
                return Err(e.to_string());
            }
        };
        Ok(Self {
            shared,
            listener: Some(listener),
            sender: Some(sender),
            drain: Duration::from_millis(cfg.dtls.shutdown_drain_ms),
        })
    }
    pub fn status(&self) -> Status {
        snapshot(&self.shared.lock().unwrap())
    }
    pub fn stop(&mut self) -> Status {
        {
            let mut s = self.shared.lock().unwrap();
            if s.stop_at.is_none() {
                s.stop_at = Some(Instant::now() + self.drain);
            }
        }
        if let Some(t) = self.listener.take() {
            let _ = t.join();
        }
        if let Some(t) = self.sender.take() {
            let _ = t.join();
        }
        let mut s = self.shared.lock().unwrap();
        s.status.running = false;
        s.status.listener_status = "stopped".into();
        s.status.dtls_status = "stopped".into();
        s.status.in_flight = false;
        snapshot(&s)
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn snapshot(s: &State) -> Status {
    let mut status = s.status.clone();
    status.sources = s.sources.snapshot(s.started.elapsed().as_secs());
    status.source_tracking_limit = SOURCE_LIMIT;
    status.untracked_source_messages = s.sources.untracked_messages;
    status
}

fn listen(socket: UdpSocket, cfg: &Config, shared: &Shared) {
    // Large enough for any conventional UDP payload; never forward truncated input.
    let mut buffer = vec![0u8; 65_536];
    let allowed_ips: HashSet<_> = cfg
        .source_access
        .allowed_ips
        .iter()
        .copied()
        .map(canonical_ip)
        .collect();
    loop {
        if shared.lock().unwrap().stop_at.is_some() {
            break;
        }
        match socket.recv_from(&mut buffer) {
            Ok((n, peer)) => {
                let ip = canonical_ip(peer.ip());
                let allowed =
                    cfg.source_access.mode == SourceMode::Any || allowed_ips.contains(&ip);
                let mut s = shared.lock().unwrap();
                // stop() may race with recv_from; account the datagram before dropping it.
                s.status.messages_received += 1;
                let now = now_ms();
                s.status.last_received_ms = Some(now);
                s.sources.received(ip, allowed, now);
                if !allowed {
                    s.status.drops.source_denied += 1;
                    s.status.messages_dropped += 1;
                    s.sources.dropped(ip);
                    continue;
                }
                if s.stop_at.is_some() {
                    s.status.drops.shutdown += 1;
                    s.status.messages_dropped += 1;
                    s.sources.dropped(ip);
                    continue;
                }
                if n > cfg.listener.max_message_bytes {
                    s.status.drops.oversized += 1;
                    s.status.messages_dropped += 1;
                    s.sources.dropped(ip);
                    continue;
                }
                if !framing::valid_message(&buffer[..n]) {
                    s.status.drops.invalid += 1;
                    s.status.messages_dropped += 1;
                    s.sources.dropped(ip);
                    continue;
                }
                if s.queue.len() >= cfg.queue.max_messages
                    || s.status.queue_bytes + n > cfg.queue.max_bytes
                {
                    s.status.drops.queue_full += 1;
                    s.status.messages_dropped += 1;
                    s.sources.dropped(ip);
                    continue;
                }
                s.queue.push_back(Message {
                    payload: Arc::from(&buffer[..n]),
                    source: ip,
                });
                s.status.queue_bytes += n;
                s.status.queue_depth = s.queue.len();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                let mut s = shared.lock().unwrap();
                s.status.listener_status = "failed".into();
                s.status.last_error = Some(format!("UDP listener failed: {e}"));
                s.stop_at = Some(Instant::now());
                break;
            }
        }
    }
}
fn expired(shared: &Shared) -> bool {
    shared
        .lock()
        .unwrap()
        .stop_at
        .is_some_and(|at| Instant::now() >= at)
}
fn pause(shared: &Shared, duration: Duration) {
    let until = Instant::now() + duration;
    while Instant::now() < until && !expired(shared) {
        thread::sleep(
            Duration::from_millis(10).min(until.saturating_duration_since(Instant::now())),
        );
    }
}
fn finish_front(s: &mut State, forwarded: bool) {
    if let Some(m) = s.queue.pop_front() {
        s.status.queue_bytes -= m.payload.len();
        if forwarded {
            s.sources.forwarded(m.source, s.started.elapsed().as_secs());
        } else {
            s.sources.dropped(m.source);
        }
    }
    s.status.queue_depth = s.queue.len();
    s.status.in_flight = false;
    if forwarded {
        s.status.messages_forwarded += 1;
        s.status.last_forwarded_ms = Some(now_ms());
    } else {
        s.status.messages_dropped += 1;
        s.status.drops.oversized += 1;
    }
}

/// At most one OS DNS call is outstanding per relay; stop never waits on OS DNS.
/// The detached lookup exits when the OS returns. Its channel carries no credentials.
type Lookup = mpsc::Receiver<Result<Vec<SocketAddr>, String>>;
fn resolve(
    cfg: &Config,
    shared: &Shared,
    pending: &mut Option<Lookup>,
) -> Result<Vec<SocketAddr>, String> {
    if pending.is_none() {
        let host = normalize_name(&cfg.remote.host)?;
        let port = cfg.remote.port;
        let (tx, rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("syslog-dns".into())
            .spawn(move || {
                let result = (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|a| a.collect::<Vec<_>>())
                    .map_err(|e| format!("DNS resolution failed: {e}"));
                let _ = tx.send(result);
            })
            .map_err(|e| e.to_string())?;
        *pending = Some(rx);
    }
    let until = Instant::now() + Duration::from_millis(cfg.dtls.handshake_timeout_ms);
    loop {
        if expired(shared) {
            return Err("Stopping".into());
        }
        match pending
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_millis(20))
        {
            Ok(result) => {
                *pending = None;
                return result.and_then(|a| {
                    if a.is_empty() {
                        Err("DNS returned no addresses".into())
                    } else {
                        Ok(a)
                    }
                });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= until {
                    return Err("DNS lookup timed out".into());
                }
            }
            Err(_) => {
                *pending = None;
                return Err("DNS worker stopped".into());
            }
        }
    }
}
fn send(cfg: &Config, shared: &Shared, connector: Arc<dyn Connector>) {
    let mut session = None;
    let mut pending_frame: Option<Vec<u8>> = None;
    let mut write_started = Instant::now();
    let mut dns = None;
    let mut attempts = 0usize;
    let mut delay = cfg.dtls.retry_initial_ms;
    let mut next_send = Instant::now();
    // Pseudorandom jitter is only scheduling, never cryptography.
    let mut jitter = now_ms() | 1;
    loop {
        {
            let s = shared.lock().unwrap();
            if s.stop_at
                .is_some_and(|at| Instant::now() >= at || s.queue.is_empty())
            {
                break;
            }
        }
        if session.is_none() {
            {
                let mut s = shared.lock().unwrap();
                s.status.dtls_status = "resolving".into();
                s.status.in_flight = false;
            }
            let result = resolve(cfg, shared, &mut dns).and_then(|addresses| {
                let remote = addresses[attempts % addresses.len()];
                attempts = attempts.wrapping_add(1);
                {
                    let mut s = shared.lock().unwrap();
                    s.status.dtls_status = "handshaking".into();
                    s.status.remote_address = Some(remote.to_string());
                }
                connector
                    .connect(cfg, remote, &|| expired(shared))
                    .map_err(|e| e.to_string())
            });
            match result {
                Ok(new) => {
                    let info = new.peer_info();
                    let mut s = shared.lock().unwrap();
                    s.status.dtls_status = "established".into();
                    s.status.last_handshake_ms = Some(now_ms());
                    s.status.last_error = None;
                    s.status.peer_fingerprint = Some(info.fingerprint);
                    s.status.cipher = Some(info.cipher);
                    s.status.protocol = Some(info.protocol);
                    session = Some(new);
                    pending_frame = None;
                }
                Err(error) => {
                    if expired(shared) {
                        break;
                    }
                    {
                        let mut s = shared.lock().unwrap();
                        s.status.dtls_status = "retrying".into();
                        s.status.last_error = Some(error);
                        s.status.retry_attempts += 1;
                    }
                    jitter ^= jitter << 13;
                    jitter ^= jitter >> 7;
                    jitter ^= jitter << 17;
                    pause(
                        shared,
                        Duration::from_millis(
                            (delay * 3 / 4 + jitter % (delay / 2 + 1)).min(cfg.dtls.retry_max_ms),
                        ),
                    );
                    delay = (delay * 2).min(cfg.dtls.retry_max_ms);
                    continue;
                }
            }
        }
        let transport = session.as_mut().unwrap();
        let mut failure = None;
        if pending_frame.is_none() {
            if let Err(e) = transport.poll() {
                failure = Some(e.to_string());
            }
            if failure.is_none() && Instant::now() >= next_send {
                let mut s = shared.lock().unwrap();
                if let Some(m) = s.queue.front() {
                    let frame = framing::frame(&m.payload);
                    if frame.len() > transport.max_plaintext() {
                        finish_front(&mut s, false);
                        continue;
                    }
                    pending_frame = Some(frame);
                    s.status.in_flight = true;
                    write_started = Instant::now();
                }
            }
        }
        if failure.is_none() {
            if let Some(frame) = &pending_frame {
                match transport.send(frame) {
                    Ok(WriteOutcome::Sent) => {
                        finish_front(&mut shared.lock().unwrap(), true);
                        pending_frame = None;
                        delay = cfg.dtls.retry_initial_ms;
                        next_send = Instant::now()
                            + Duration::from_secs_f64(1.0 / cfg.dtls.messages_per_second as f64);
                    }
                    Ok(WriteOutcome::WouldBlock) => {
                        if write_started.elapsed()
                            > Duration::from_millis(cfg.dtls.handshake_timeout_ms)
                        {
                            failure=Some("DTLS write timed out; queued message retained (delivery may be ambiguous)".into());
                        }
                    }
                    Err(e) => failure = Some(e.to_string()),
                }
            }
        }
        if let Some(error) = failure {
            transport.close();
            session = None;
            pending_frame = None;
            {
                let mut s = shared.lock().unwrap();
                s.status.dtls_status = "retrying".into();
                s.status.in_flight = false;
                s.status.last_error = Some(error);
                s.status.retry_attempts += 1;
            }
            pause(shared, Duration::from_millis(delay));
            delay = (delay * 2).min(cfg.dtls.retry_max_ms);
        } else if pending_frame.is_some() || shared.lock().unwrap().queue.is_empty() {
            pause(shared, Duration::from_millis(10));
        } else {
            pause(
                shared,
                next_send
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            );
        }
    }
    if let Some(mut s) = session {
        s.close();
    }
    let mut s = shared.lock().unwrap();
    let dropped = s.queue.len() as u64;
    s.status.messages_dropped += dropped;
    s.status.drops.shutdown += dropped;
    while let Some(m) = s.queue.pop_front() {
        s.sources.dropped(m.source);
    }
    s.status.queue_depth = 0;
    s.status.queue_bytes = 0;
    s.status.in_flight = false;
    s.status.dtls_status = "stopped".into();
    s.status.running = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Session, TransportError};
    struct Offline;
    impl Connector for Offline {
        fn connect(
            &self,
            _: &Config,
            _: SocketAddr,
            _: &dyn Fn() -> bool,
        ) -> Result<Box<dyn Session>, TransportError> {
            Err(TransportError("offline".into()))
        }
        fn client_fingerprint(&self) -> String {
            String::new()
        }
    }
    #[test]
    fn bounded_queue_and_shutdown_accounting() {
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut cfg = Config::default();
        cfg.listener.port = port;
        cfg.remote.host = "127.0.0.1".into();
        cfg.queue.max_messages = 2;
        cfg.dtls.shutdown_drain_ms = 0;
        let mut relay = Relay::start(cfg, Arc::new(Offline)).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..5 {
            socket
                .send_to(b"<34>1 - h a p m - test", ("127.0.0.1", port))
                .unwrap();
        }
        let until = Instant::now() + Duration::from_secs(2);
        while relay.status().messages_received < 5 && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        let s = relay.status();
        assert_eq!(s.queue_depth, 2);
        assert_eq!(s.drops.queue_full, 3);
        let s = relay.stop();
        assert_eq!(s.messages_received, 5);
        assert_eq!(s.messages_dropped, 5);
        assert_eq!(s.queue_bytes, 0);
    }
}
