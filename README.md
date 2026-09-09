# Syslog DTLS Agent

A small, open-source syslog relay with a Rust core, a headless CLI, and a Tauri 2 desktop interface. Receives RFC 5424 syslog datagrams and forwards them with RFC 6012 octet-count framing over mutually authenticated DTLS 1.2.

**Default input: `127.0.0.1:1514/udp`. Default output port: `6514/udp`.** Both endpoints are configurable. Windows, macOS, and Linux are the required platforms. BSD is optional; no BSD desktop support is promised.

## What the MVP includes

- One UDP listener and one collector, IPv4 or IPv6.
- Source-IP access mode: allow any source, or only explicitly allowlisted IPv4/IPv6 nodes.
- Per-source Overview statistics, including forwarding rates and a 24-hour count.
- PEM client certificate chain and private key; an explicit PEM CA bundle.
- Mandatory server chain and DNS/IP identity verification. No insecure bypass.
- A memory queue bounded by both message count and bytes; FIFO, drop newest on overflow.
- Retries with backoff, handshake retransmission, output pacing, and bounded shutdown draining.
- Desktop overview, connection settings, TOML import/export, credential validation, and diagnostics.
- Session counters, queue use, drop reasons, timestamps, peer/client fingerprints, and connection errors.

**Delivery is best effort.** A successful local DTLS write is counted as forwarded; it is not a collector acknowledgement. UDP packets can disappear without detection. A collector can lose session state while local writes continue succeeding. The queue covers detected failures, not all packet loss. Ambiguous write retries may duplicate messages.

## Build prerequisites

Install Rust (1.89 or later; current stable recommended), a C/C++ toolchain, Perl, and Node.js 22+ with npm for desktop builds. OpenSSL is built from vendored source by default, so users do not need to install a runtime OpenSSL library. Updating the locked OpenSSL dependency and rebuilding is required to ship native security fixes.

- **macOS:** Xcode Command Line Tools. A full Xcode install may be needed for packaging/signing.
- **Windows:** Visual Studio Build Tools with the Desktop development with C++ workload, Windows SDK, Strawberry Perl, and the WebView2 runtime. Use the MSVC Rust target. NASM is recommended for OpenSSL builds.
- **Linux (Debian/Ubuntu):** `build-essential`, `perl`, `pkg-config`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, and `patchelf` for desktop packaging. The CLI does not require GTK/WebKit.

See [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for other Linux distributions and platform setup.

## Run the CLI

```sh
cargo build --locked -p syslog-agent-cli
cargo run --locked -p syslog-agent-cli -- config > agent.toml
```

Edit the destination and credential paths in `agent.toml`, then:

```sh
cargo run --locked -p syslog-agent-cli -- check --config agent.toml
cargo run --locked -p syslog-agent-cli -- run --config agent.toml
```

`check` parses the configuration and loads the credentials without sending network traffic. It does not test collector connectivity. `run` emits JSON status snapshots every five seconds (`--status-interval` overrides this). Stop with Ctrl-C; on Unix SIGTERM also performs graceful shutdown.

The executable is `target/debug/syslog-dtls-agent` (`.exe` on Windows). Release builds use `cargo build --release --locked -p syslog-agent-cli`.

## Run the desktop app

```sh
npm ci
npm run desktop
```

Open **Connection**, select the certificate chain, private key, and CA bundle, enter the collector address, and start the relay. Credentials can be validated before starting. Settings are locked while running; stop before editing. Use **Save TOML** to persist configuration and **Open TOML** to reload it. There is no automatic startup or automatic configuration persistence.

```sh
npm run desktop:build
```

Desktop bundles are placed under `target/release/bundle`. Local bundles are unsigned unless signing is separately configured. Release signing, notarization, and public distribution are not automated by this MVP.

Closing the app stops the relay. This is not an installed daemon or Windows Service. The independent CLI can be supervised externally; native service installers and an independently running service/UI pair are deferred.

## Configuration

See [config.example.toml](config.example.toml). Unknown fields and invalid limits are rejected. Credential paths loaded from TOML are resolved relative to that TOML file. The desktop save action writes absolute credential paths so changing the configuration directory does not change credential identity. Configuration contains references, never inline keys or passwords.

The expected server name defaults to the remote host. To connect to an IP with a DNS certificate, set `remote.expected_server_name` to that DNS name. IP identities must match an IP SAN. DNS identities match DNS SANs (including a full leftmost-label wildcard); legacy common-name fallback is disabled. Internationalized names are converted to ASCII.

The CA file supplies the trust anchors exclusively; system trust roots are not implicitly added. Client chains should contain the leaf certificate first, then intermediate certificates. Unencrypted private-key PEM is the only MVP key format. Keep that file private with owner-only permissions/ACLs; do not commit it or include it in diagnostics. Rust owns the key and zeroizes the temporary PEM byte buffer; OpenSSL owns the parsed key. Neither payloads nor key material are logged. No TLS key-log export is enabled.

## Input, framing, and MTU

### Source access and statistics

In **Connection → Source access**, choose **Allow any source IP** (the default) or **Only allowlisted IPs**. Add/remove individual addresses with the allowlist editor. As with other connection settings, stop the relay before editing, then restart to apply. Save TOML to persist the changes. Existing TOML files without `[source_access]` continue allowing any source.

```toml
[source_access]
mode = "allowlist"
allowed_ips = ["192.0.2.10", "2001:db8::10"]
```

An empty allowlist in allowlist mode **blocks all sources**. Entries are exact IP addresses, not hostnames, source ports, or CIDR ranges. IPv4-mapped IPv6 addresses are normalized to IPv4 for matching and statistics. Filtering uses the UDP peer address before parsing or queueing any message. Denials increment `drops.source_denied` and the global dropped count. The source IP is retained with queued messages so later forwarding, overflow, and shutdown are attributed correctly. UDP source addresses can be spoofed; allowlisting is not cryptographic sender authentication.

**Overview → Source IPs** includes both allowed and blocked senders observed by the listener, including malformed input attempts. Different source ports on the same IP share one row. Received/forwarded/dropped counts are per session; rates count successful local DTLS writes, not arrivals or collector acknowledgements:

- **Msg/s:** count in the most recently completed one-second interval.
- **Msg/min:** count in the most recent 60 completed one-second intervals.
- **Last 24h:** rolling count using minute buckets, including the current minute; the oldest boundary has one-minute precision.

Windows advance using monotonic time and decay even when an IP stops sending. History is in memory, resets each time the relay starts, and shows only the available history if uptime is less than 24 hours. The stopped desktop view retains the final snapshot. To bound memory (about 6 MiB of bucket storage at capacity), the first 256 IPs are tracked for the session without evicting their history. Additional IPs still undergo filtering and contribute to global counters, but not individual rows; the card reports the number of untracked datagrams when this occurs. The allowlist itself supports up to 4096 entries independently of the statistics limit.

The listener accepts **RFC 5424 version 1**, one message per datagram. It preserves accepted bytes exactly, including trailing newlines and non-UTF-8 message bodies where RFC 5424 permits them. Legacy RFC 3164 datagrams are counted as invalid; they are not silently reinterpreted or converted.

Each outbound record contains one complete frame: decimal message byte length, ASCII space, exact original message bytes. The prefix is not included in the length. There is no added delimiter and no message batching or cross-record application fragmentation.

The default `dtls.datagram_bytes = 1200` is a conservative UDP payload budget including DTLS overhead. The actual message budget is smaller: OpenSSL reports available plaintext space after cipher overhead, and the length prefix consumes some of that space. A message that exceeds this budget is dropped whole and counted as oversized, even if it fits `listener.max_message_bytes`. The input maximum of 8192 is an acceptance ceiling, **not a promise to forward 8192-byte records with the default MTU**.

Increasing the datagram budget can accommodate larger messages but may require IP fragmentation and can increase loss. Test the collector and network path. Dynamic path-MTU discovery and application-level fragmentation are deferred. Never truncate syslog content to make it fit.

## Counter and lifecycle semantics

- **Received:** datagrams delivered to the application, including invalid/oversized inputs.
- **Forwarded:** full frames accepted by the local DTLS write API.
- **Dropped:** known invalid, oversized, queue-full, or shutdown discards.
- **Queue depth/bytes:** all pending payloads, including the in-flight message. Byte limits exclude small queue metadata and the single bounded framing buffer.
- **In flight:** one queue entry is being written; it remains queued across retryable writes.
- **Times:** wall-clock Unix milliseconds in JSON, localized in the desktop. Retry and shutdown deadlines use monotonic time.

While running, `received = forwarded + dropped + queue_depth`. After a completed stop the queue is empty. Counters reset on each start. Kernel receive-buffer loss and downstream loss may be unobservable and are not invented as application drops.

On stop, input closes, pending messages can drain up to `shutdown_drain_ms`, remaining messages are counted as shutdown drops, and OpenSSL attempts `close_notify`. DNS lookup runs separately so OS resolver delays do not block shutdown; at most one lookup is outstanding per relay. A cancelled OS lookup may finish after the relay stops. Queue contents do not survive a crash, forced termination, or restart.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `syslog-agent-core` | Configuration, strict input validation, framing, queue, worker lifecycle, status, transport/credential contracts |
| `syslog-agent-dtls-openssl` | Native datagram BIO, DTLS handshake/timers, PEM identity and CA loading, peer verification |
| `syslog-agent-cli` | Foreground runner and JSON status |
| `syslog-agent-desktop` | Tauri commands, file dialogs, desktop lifecycle |

The core has no Tauri dependency. Two worker threads own input and output; a short-lived worker resolves DNS. A locked queue/status snapshot keeps accounting coherent. Desktop commands invoke the core through a Rust adapter, and the frontend polls status twice per second. No message payloads traverse Tauri IPC. UI assets are local, with a restrictive CSP and no remote content, shell access, or frontend filesystem plugin.

`Identity` and `Trust` are provider-tagged references. Future identity backends may use opaque signing handles, allowing PKCS#12 and OS-store support without requiring private keys to cross the UI boundary. Supporting non-exportable OS keys will require additional native backend integration.

## Verification

```sh
cargo fmt --all --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
npm run test:ui
cargo build --locked -p syslog-agent-cli
python3 tests/interop.py
```

The interoperability script requires an OpenSSL 3 command-line executable. Set `OPENSSL_BIN` if it is not on PATH (for example Homebrew's `/opt/homebrew/opt/openssl@3/bin/openssl` on Apple Silicon). It creates disposable credentials in a temporary directory and binds temporary loopback UDP ports. It exercises an independent OpenSSL `s_server` process, exact decrypted framing, mTLS, DNS/IP verification, rejection of incorrect trust/name/key settings, and handshake retransmission after packet loss.

The GitHub Actions workflow builds/tests on Windows, macOS, and Linux. CI configuration is provided; a local macOS run does not establish that the other OS jobs have passed. Validation against a specific production syslog collector remains a deployment check.

For a manual desktop test, run `python3 tests/desktop_fixture.py` with the same `OPENSSL_BIN` setting. Open the printed temporary TOML path in the desktop app, start the relay, and check the forwarding counters. The fixture sends disposable test messages to its own randomly selected loopback port and stops after five minutes. Stop the desktop relay before the fixture ends. It does not change or use production credentials.

Locally verified on macOS: thirteen Rust tests, five frontend behavior tests, formatting, and Clippy with warnings denied. The original MVP also passed eight OpenSSL interoperability/security cases and was verified end-to-end by its user. Source access and statistics are covered by the additional automated tests. Windows and Linux CI runs remain to be executed.

## Standards profile and deferred features

This MVP implements the RFC 6012 framing/UDP transport profile with CA-authenticated DTLS 1.2. It does **not claim complete RFC 6012 conformance**: standalone certificate-fingerprint authorization (including inherited SHA-1 support), managed certificate generation, and DCCP are not implemented. SHA-256 fingerprints are displayed for diagnostics, not used as an alternative trust mode. DTLS 1.0 is prohibited by [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996.html).

Also deferred: PKCS#12, encrypted-key password handling, OS certificate stores, revocation retrieval/OCSP/CRLs, service installation, disk queues, multi-collector routing, message rewriting, DTLS 1.3, automatic updates, and BSD guarantees. Use short-lived/revocable-at-source identities and an appropriate trust-management process for your deployment; this MVP does not fetch revocation data.

Output pacing prevents an immediate queue-drain burst but is not responsive congestion control. High-volume UDP forwarding should be limited to provisioned/managed paths; do not treat the configurable rate cap as an Internet congestion-control implementation.

## License

MIT. Dependencies retain their own licenses; OpenSSL 3 is Apache-2.0. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No cryptographic primitives are implemented by this project.
