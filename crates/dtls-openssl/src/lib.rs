//! OpenSSL DTLS adapter. Native datagram BIOs preserve UDP boundaries and timers.
use foreign_types::ForeignType;
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::PKey,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion},
    x509::{verify::X509CheckFlags, X509},
};
use openssl_sys as ffi;
use std::{
    ffi::{c_int, c_long, c_void},
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};
use syslog_agent_core::{
    config::{Identity, Trust},
    transport::{Connector, PeerInfo, Session, TransportError, WriteOutcome},
    Config,
};
use zeroize::Zeroizing;

// Stable public OpenSSL macros (openssl/bio.h and openssl/ssl.h).
const BIO_CTRL_DGRAM_SET_CONNECTED: c_int = 32;
const DTLS_CTRL_HANDLE_TIMEOUT: c_int = 74;
unsafe extern "C" {
    fn BIO_new_dgram(fd: c_int, close_flag: c_int) -> *mut ffi::BIO;
    fn DTLS_get_data_mtu(ssl: *const ffi::SSL) -> usize;
}

pub struct OpenSslConnector {
    context: SslContext,
    fingerprint: String,
}
impl OpenSslConnector {
    pub fn new(config: &Config) -> Result<Self, TransportError> {
        config.validate().map_err(TransportError)?;
        let mut context = SslContextBuilder::new(SslMethod::dtls_client()).map_err(crypto_error)?;
        context
            .set_min_proto_version(Some(SslVersion::DTLS1_2))
            .map_err(crypto_error)?;
        context
            .set_max_proto_version(Some(SslVersion::DTLS1_2))
            .map_err(crypto_error)?;
        context.set_verify(SslVerifyMode::PEER);
        context.set_verify_depth(8);
        context.set_options(
            SslOptions::NO_RENEGOTIATION | SslOptions::NO_COMPRESSION | SslOptions::NO_QUERY_MTU,
        );
        context.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384").map_err(crypto_error)?;
        let Identity::Pem {
            certificate_chain,
            private_key,
        } = &config.identity;
        let Trust::PemCa { ca_bundle } = &config.trust;
        let certificates = std::fs::read(certificate_chain)
            .map_err(|_| TransportError("Cannot read client certificate chain".into()))?;
        let mut chain = X509::stack_from_pem(&certificates)
            .map_err(|_| TransportError("Invalid client certificate chain PEM".into()))?
            .into_iter();
        let cert = chain
            .next()
            .ok_or_else(|| TransportError("Empty client certificate chain".into()))?;
        context.set_certificate(&cert).map_err(crypto_error)?;
        for cert in chain {
            context.add_extra_chain_cert(cert).map_err(crypto_error)?;
        }
        // No OpenSSL password callback / terminal prompt; encrypted keys are deferred.
        let key_bytes = Zeroizing::new(
            std::fs::read(private_key)
                .map_err(|_| TransportError("Cannot read client private key".into()))?,
        );
        let key=PKey::private_key_from_pem_callback(&key_bytes, |_|Err(ErrorStack::get())).map_err(|_|TransportError("Invalid or encrypted private key; MVP requires unencrypted PEM protected by file permissions".into()))?;
        if !cert.public_key().map_err(crypto_error)?.public_eq(&key) {
            return Err(TransportError(
                "Client certificate and private key do not match".into(),
            ));
        }
        context.set_private_key(&key).map_err(crypto_error)?;
        context.check_private_key().map_err(|_| {
            TransportError("Client certificate and private key do not match".into())
        })?;
        // Only explicitly configured trust anchors; never silently add system roots.
        context
            .set_ca_file(ca_bundle)
            .map_err(|_| TransportError("Cannot load CA bundle".into()))?;
        Ok(Self {
            context: context.build(),
            fingerprint: fingerprint(&cert)?,
        })
    }
}
fn crypto_error(_: ErrorStack) -> TransportError {
    TransportError("OpenSSL could not initialize security settings".into())
}
fn fingerprint(cert: &X509) -> Result<String, TransportError> {
    Ok(format!(
        "sha-256:{}",
        cert.digest(MessageDigest::sha256())
            .map_err(crypto_error)?
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    ))
}

impl Connector for OpenSslConnector {
    fn client_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
    fn connect(
        &self,
        cfg: &Config,
        remote: SocketAddr,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Box<dyn Session>, TransportError> {
        let socket = UdpSocket::bind(if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .map_err(io_error)?;
        socket.connect(remote).map_err(io_error)?;
        socket.set_nonblocking(true).map_err(io_error)?;
        let mut ssl = Ssl::new(&self.context).map_err(crypto_error)?;
        let name = cfg.server_name().map_err(TransportError)?;
        ssl.param_mut().set_hostflags(
            X509CheckFlags::NO_PARTIAL_WILDCARDS | X509CheckFlags::NEVER_CHECK_SUBJECT,
        );
        if let Ok(ip) = name.parse::<IpAddr>() {
            ssl.param_mut().set_ip(ip).map_err(crypto_error)?;
        } else {
            ssl.param_mut().set_host(&name).map_err(crypto_error)?;
            ssl.set_hostname(&name).map_err(crypto_error)?;
        }
        ssl.set_connect_state();
        ssl.set_mtu(cfg.dtls.datagram_bytes).map_err(crypto_error)?;
        let address = socket2::SockAddr::from(remote);
        // SAFETY: socket remains alive until after SSL/BIO destruction. BIO_NOCLOSE
        // means Rust alone closes it. OpenSSL owns the single BIO after SSL_set_bio.
        // SET_CONNECTED takes a valid sockaddr, copied by OpenSSL during this call.
        unsafe {
            let bio = BIO_new_dgram(socket_handle(&socket), 0);
            if bio.is_null() {
                return Err(TransportError("Cannot create DTLS datagram BIO".into()));
            }
            if ffi::BIO_ctrl(
                bio,
                BIO_CTRL_DGRAM_SET_CONNECTED,
                0,
                address.as_ptr() as *mut c_void,
            ) <= 0
            {
                ffi::BIO_free_all(bio);
                return Err(TransportError("Cannot connect datagram BIO".into()));
            }
            ffi::SSL_set_bio(ssl.as_ptr(), bio, bio);
        }
        let mut session = OpenSslSession {
            ssl,
            _socket: socket,
            mtu: 0,
            closed: false,
        };
        let until = Instant::now() + Duration::from_millis(cfg.dtls.handshake_timeout_ms);
        loop {
            if cancelled() {
                return Err(TransportError("DTLS handshake cancelled".into()));
            }
            // SAFETY: exclusively owned, initialized SSL and BIO; error queue cleared
            // immediately before operation, SSL_get_error called before other SSL APIs.
            let result = unsafe {
                ffi::ERR_clear_error();
                ffi::SSL_connect(session.ssl.as_ptr())
            };
            if result == 1 {
                break;
            }
            session.check_result(result)?;
            session.handle_timeout()?;
            if Instant::now() >= until {
                return Err(TransportError("DTLS handshake timed out".into()));
            }
            thread::sleep(Duration::from_millis(10));
        }
        if session.ssl.verify_result() != openssl::x509::X509VerifyResult::OK
            || session.ssl.peer_certificate().is_none()
        {
            return Err(TransportError(
                "Server certificate verification failed".into(),
            ));
        }
        // SAFETY: handshake complete; OpenSSL computes record overhead for the cipher.
        session.mtu = unsafe { DTLS_get_data_mtu(session.ssl.as_ptr()) }.min(16_384);
        if session.mtu == 0 {
            return Err(TransportError(
                "OpenSSL returned no DTLS payload budget".into(),
            ));
        }
        Ok(Box::new(session))
    }
}
fn io_error(e: std::io::Error) -> TransportError {
    TransportError(format!("DTLS socket error: {e}"))
}
#[cfg(unix)]
fn socket_handle(s: &UdpSocket) -> c_int {
    use std::os::fd::AsRawFd;
    s.as_raw_fd()
}
#[cfg(windows)]
fn socket_handle(s: &UdpSocket) -> c_int {
    use std::os::windows::io::AsRawSocket;
    s.as_raw_socket() as c_int
}

struct OpenSslSession {
    ssl: Ssl,
    _socket: UdpSocket,
    mtu: usize,
    closed: bool,
}
impl OpenSslSession {
    fn check_result(&self, result: c_int) -> Result<(), TransportError> {
        // SAFETY: called immediately after a failed SSL operation on this thread.
        let error = unsafe { ffi::SSL_get_error(self.ssl.as_ptr(), result) };
        match error {
            ffi::SSL_ERROR_WANT_READ | ffi::SSL_ERROR_WANT_WRITE => Ok(()),
            ffi::SSL_ERROR_ZERO_RETURN => Err(TransportError(
                "Collector closed the DTLS association".into(),
            )),
            _ => {
                let verification = self.ssl.verify_result();
                if verification != openssl::x509::X509VerifyResult::OK {
                    Err(TransportError(format!(
                        "Server certificate rejected: {}",
                        verification.error_string()
                    )))
                } else {
                    Err(TransportError(format!("DTLS operation failed (OpenSSL category {error}); check collector, client identity, and network")))
                }
            }
        }
    }
    fn handle_timeout(&mut self) -> Result<(), TransportError> {
        // SAFETY: stable OpenSSL macro DTLSv1_handle_timeout, no pointer argument.
        let result = unsafe {
            ffi::SSL_ctrl(
                self.ssl.as_ptr(),
                DTLS_CTRL_HANDLE_TIMEOUT,
                0 as c_long,
                std::ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(TransportError("DTLS timer processing failed".into()));
        }
        Ok(())
    }
}
impl Session for OpenSslSession {
    fn max_plaintext(&self) -> usize {
        self.mtu
    }
    fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            fingerprint: self
                .ssl
                .peer_certificate()
                .and_then(|c| fingerprint(&c).ok())
                .unwrap_or_default(),
            cipher: self
                .ssl
                .current_cipher()
                .map(|c| c.name().into())
                .unwrap_or_default(),
            protocol: self.ssl.version_str().into(),
        }
    }
    fn send(&mut self, frame: &[u8]) -> Result<WriteOutcome, TransportError> {
        if frame.len() > self.mtu || frame.is_empty() {
            return Err(TransportError(
                "Frame exceeds the DTLS record budget".into(),
            ));
        }
        // SAFETY: frame is valid for len, bounded well below c_int::MAX. The caller
        // retains identical bytes/address across WANT_READ/WANT_WRITE retries.
        let result = unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_write(
                self.ssl.as_ptr(),
                frame.as_ptr().cast(),
                frame.len() as c_int,
            )
        };
        if result == frame.len() as c_int {
            return Ok(WriteOutcome::Sent);
        }
        if result > 0 {
            return Err(TransportError("Unexpected partial DTLS write".into()));
        }
        self.check_result(result)?;
        self.handle_timeout()?;
        Ok(WriteOutcome::WouldBlock)
    }
    fn poll(&mut self) -> Result<(), TransportError> {
        let mut scratch = [0u8; 16_384];
        // SAFETY: writable buffer lives throughout call. No outstanding write retry.
        let result = unsafe {
            ffi::ERR_clear_error();
            ffi::SSL_read(
                self.ssl.as_ptr(),
                scratch.as_mut_ptr().cast(),
                scratch.len() as c_int,
            )
        };
        if result <= 0 {
            self.check_result(result)?;
        }
        self.handle_timeout()
    }
    fn close(&mut self) {
        if !self.closed {
            // SAFETY: live SSL; nonblocking best-effort close_notify, no wait required.
            unsafe {
                ffi::ERR_clear_error();
                ffi::SSL_shutdown(self.ssl.as_ptr());
            }
            self.closed = true;
        }
    }
}
impl Drop for OpenSslSession {
    fn drop(&mut self) {
        self.close();
    }
}
