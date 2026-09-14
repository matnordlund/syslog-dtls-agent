#!/usr/bin/env python3
"""Real DTLS/mTLS interoperability tests. Uses disposable credentials, never production keys.

Run after cargo build: OPENSSL_BIN=/path/to/openssl python3 tests/interop.py
Works with Python's standard library and an OpenSSL 3 executable.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OPENSSL = os.environ.get("OPENSSL_BIN", "openssl")
AGENT = Path(os.environ.get("AGENT_BIN", ROOT / "target/debug" / ("syslog-dtls-agent.exe" if os.name == "nt" else "syslog-dtls-agent")))


def openssl(*args):
    subprocess.run([OPENSSL, *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, message, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError(message)


class Process:
    def __init__(self, args, lines=False):
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.process = subprocess.Popen(list(map(str, args)), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=flags)
        self.output = bytearray()
        self.errors = bytearray()
        self.status = {}
        self.lines = lines
        self.threads = [threading.Thread(target=self.read, args=(self.process.stdout, False), daemon=True), threading.Thread(target=self.read, args=(self.process.stderr, True), daemon=True)]
        for t in self.threads:
            t.start()

    def read(self, stream, error):
        while True:
            data = stream.readline() if self.lines and not error else os.read(stream.fileno(), 65536)
            if not data:
                return
            if error:
                self.errors.extend(data)
            else:
                self.output.extend(data)
                if self.lines:
                    try:
                        self.status = json.loads(data)
                    except json.JSONDecodeError:
                        pass

    def close(self, graceful=False):
        if self.process.poll() is None:
            if graceful:
                self.process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
            else:
                self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("Process did not stop within its drain deadline")
        for t in self.threads:
            t.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


class LossProxy:
    """Drop the first client handshake packet to exercise DTLS retransmission."""
    def __init__(self, collector_port):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(("127.0.0.1", 0))
        self.port = self.client.getsockname()[1]
        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upstream.connect(("127.0.0.1", collector_port))
        self.client.settimeout(0.05)
        self.upstream.settimeout(0.05)
        self.running = True
        self.dropped = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        peer = None
        while self.running:
            try:
                data, peer = self.client.recvfrom(65536)
                if not self.dropped:
                    self.dropped = True
                else:
                    self.upstream.send(data)
            except (TimeoutError, OSError):
                pass
            try:
                data = self.upstream.recv(65536)
                if peer:
                    self.client.sendto(data, peer)
            except (TimeoutError, OSError):
                pass

    def close(self):
        self.running = False
        self.thread.join(timeout=1)
        self.client.close()
        self.upstream.close()


def create_pki(directory):
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Test CA", "-keyout", directory / "ca.key", "-out", directory / "ca.pem")
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", directory / f"{name}.key", "-out", directory / f"{name}.csr")
        ext = directory / f"{name}.ext"
        ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:collector.test,IP:127.0.0.1\n")
        openssl("x509", "-req", "-in", directory / f"{name}.csr", "-CA", directory / "ca.pem", "-CAkey", directory / "ca.key", "-CAcreateserial", "-days", "1", "-extfile", ext, "-out", directory / f"{name}.pem")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Unrelated CA", "-keyout", directory / "other.key", "-out", directory / "other.pem")
    (directory / "index").write_text("")
    (directory / "serial").write_text("1000\n")
    conf = directory / "ca.cnf"
    conf.write_text(f'''[ca]
default_ca = test
[test]
database = {directory.as_posix()}/index
serial = {directory.as_posix()}/serial
new_certs_dir = {directory.as_posix()}
default_md = sha256
policy = policy
[policy]
commonName = supplied
''')
    openssl("ca", "-batch", "-notext", "-config", conf, "-in", directory / "server.csr", "-cert", directory / "ca.pem", "-keyfile", directory / "ca.key", "-startdate", "20000101000000Z", "-enddate", "20000102000000Z", "-extfile", directory / "server.ext", "-out", directory / "expired.pem")


def configuration(directory, listener_port, remote_port, hostname="collector.test", ca="ca.pem", key="client.key"):
    # JSON string quoting is valid for these TOML path strings, including Windows.
    q = lambda name: json.dumps(str(directory / name))
    return f'''schema_version = 1
[listener]
address = "127.0.0.1"
port = {listener_port}
max_message_bytes = 8192
[remote]
host = "127.0.0.1"
port = {remote_port}
expected_server_name = "{hostname}"
[identity]
provider = "pem"
certificate_chain = {q("client.pem")}
private_key = {q(key)}
[trust]
provider = "pem_ca"
ca_bundle = {q(ca)}
[queue]
max_messages = 10
max_bytes = 16384
[dtls]
handshake_timeout_ms = 4000
retry_initial_ms = 100
retry_max_ms = 300
shutdown_drain_ms = 100
'''


def case(directory, name, hostname="collector.test", ca="ca.pem", loss=False, reject=False, server_cert="server.pem", server_key="server.key"):
    listener_port, remote_port = port(), port()
    server = Process([OPENSSL, "s_server", "-dtls1_2", "-accept", f"127.0.0.1:{remote_port}", "-cert", directory / server_cert, "-key", directory / server_key, "-CAfile", directory / "ca.pem", "-Verify", "1", "-verify_return_error", "-quiet"])
    proxy = LossProxy(remote_port) if loss else None
    path = directory / f"{name}.toml"
    path.write_text(configuration(directory, listener_port, proxy.port if proxy else remote_port, hostname, ca))
    relay = Process([AGENT, "run", "--no-http", "--config", path, "--status-interval", "1"], lines=True)
    try:
        wait_for(lambda: relay.status.get("listener_status") == "listening", f"listener did not start: {bytes(relay.errors)!r}")
        message = "<34>1 2026-09-09T12:00:00Z host app 42 ID - hälsning\n".encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(message, ("127.0.0.1", listener_port))
            if reject:
                wait_for(lambda: relay.status.get("retry_attempts", 0) >= 2, f"expected verification failure: {relay.status}")
                assert not server.output, "plaintext delivered to an unauthorized collector"
                assert relay.status["messages_forwarded"] == 0
                assert relay.status["queue_depth"] == 1
                assert "certificate" in relay.status["last_error"].lower(), relay.status
            else:
                expected = str(len(message)).encode() + b" " + message
                wait_for(lambda: expected in server.output, f"collector never received expected frame; status={relay.status}", 12)
                assert bytes(server.output) == expected, bytes(server.output)
                wait_for(lambda: relay.status.get("messages_forwarded") == 1, "forwarded counter did not advance")
                assert relay.status["protocol"] == "DTLSv1.2"
                assert relay.status["peer_fingerprint"].startswith("sha-256:")
                sender.sendto(b"<34>1 - h a p m - " + b"x" * 2000, ("127.0.0.1", listener_port))
                sender.sendto(b"not syslog", ("127.0.0.1", listener_port))
                wait_for(lambda: relay.status.get("messages_dropped") == 2, "invalid/oversized messages were not accounted")
                assert relay.status["drops"]["oversized"] == 1
                assert relay.status["drops"]["invalid"] == 1
                assert bytes(server.output) == expected
        if proxy:
            assert proxy.dropped
    finally:
        relay.close(graceful=True)
        server.close()
        if proxy:
            proxy.close()
    status = relay.status
    assert status["messages_received"] == status["messages_forwarded"] + status["messages_dropped"], status
    assert status["queue_depth"] == 0
    print(f"PASS {name}", flush=True)


def main():
    assert AGENT.exists(), "Build the CLI first with cargo build"
    with tempfile.TemporaryDirectory(prefix="syslog-dtls-test-") as tmp:
        directory = Path(tmp)
        create_pki(directory)
        case(directory, "mutual_tls_and_framing")
        case(directory, "handshake_packet_loss", loss=True)
        case(directory, "ip_san_validation", hostname="127.0.0.1")
        case(directory, "wrong_hostname", hostname="wrong.test", reject=True)
        case(directory, "untrusted_ca", ca="other.pem", reject=True)
        case(directory, "expired_server_certificate", server_cert="expired.pem", reject=True)
        case(directory, "wrong_certificate_purpose", server_cert="client.pem", server_key="client.key", reject=True)
        bad = directory / "mismatch.toml"
        bad.write_text(configuration(directory, port(), port(), key="server.key"))
        result = subprocess.run([AGENT, "check", "--config", bad], capture_output=True)
        assert result.returncode != 0 and b"do not match" in result.stderr
        print("PASS mismatched_client_key", flush=True)


if __name__ == "__main__":
    main()
