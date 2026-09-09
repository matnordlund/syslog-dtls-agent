#!/usr/bin/env python3
"""Disposable local collector for manual desktop smoke tests; exits after five minutes.

Run with OPENSSL_BIN set as for interop.py, then open the printed TOML in the UI.
All certificate files are temporary. Ctrl-C stops the fixture early.
"""
from pathlib import Path
import socket
import tempfile
import time
from interop import OPENSSL, Process, configuration, create_pki, port


def main():
    with tempfile.TemporaryDirectory(prefix="syslog-desktop-smoke-") as tmp:
        directory = Path(tmp)
        create_pki(directory)
        listener, remote = port(), port()
        config = directory / "desktop-test.toml"
        config.write_text(configuration(directory, listener, remote))
        server = Process([OPENSSL, "s_server", "-dtls1_2", "-accept", f"127.0.0.1:{remote}", "-cert", directory / "server.pem", "-key", directory / "server.key", "-CAfile", directory / "ca.pem", "-Verify", "1", "-verify_return_error", "-quiet"])
        print(f"Open configuration: {config}", flush=True)
        until = time.monotonic() + 300
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                number = 0
                while time.monotonic() < until:
                    sender.sendto(f"<34>1 - desktop-test agent - SMOKE - Test message {number}\n".encode(), ("127.0.0.1", listener))
                    number += 1
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            server.close()
        print(f"Collector received {len(server.output)} decrypted bytes", flush=True)


if __name__ == "__main__":
    main()
