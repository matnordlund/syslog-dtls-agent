#!/usr/bin/env python3
"""Embedded HTTP integration checks using disposable credentials."""
import http.client
import json
import socket
import shutil
import tempfile
from pathlib import Path
from interop import AGENT, Process, configuration, create_pki, port, wait_for

with tempfile.TemporaryDirectory(prefix="syslog-http-test-") as tmp:
    directory = Path(tmp)
    create_pki(directory)
    config = directory / "agent.toml"
    config.write_text(configuration(directory, port(), port()))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        http_port = sock.getsockname()[1]
    config.write_text(config.read_text() + f'\n[http]\naddress = "127.0.0.1"\nport = {http_port}\n')
    binary = directory / AGENT.name
    shutil.copy2(AGENT, binary)
    agent = Process([binary],lines=True)
    def request(path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1",http_port,timeout=10)
        try:
            connection.request("GET" if body is None else "POST",path,body,headers or {})
            response = connection.getresponse()
            return response.status,response.read()
        finally:
            connection.close()
    def api(command, args=None):
        status,body = request('/api/'+command,json.dumps(args or {}),{'Content-Type':'application/json','X-Syslog-UI':'1'})
        assert status == 200,(status,body)
        return json.loads(body)
    try:
        wait_for(lambda: b"HTTP UI:" in agent.errors,"HTTP server did not start")
        assert b'Your relay, at a glance.' in request('/')[1]
        assert b'__SYSLOG_HTTP__ = true' in request('/agent-mode.js')[1]
        assert request('/../Cargo.toml')[0] == 404
        assert request('/',headers={'Host':'evil.example'})[0] == 403
        assert request('/api/stop','{}',{'Content-Type':'application/json'})[0] == 403
        assert request('/api/stop','{}',{'Content-Type':'application/json','X-Syslog-UI':'1','Origin':'http://evil.example'})[0] == 403
        assert api('status')['running']
        assert not api('stop')['running']
        cfg = api('default_config')
        assert cfg['http']['address'] == '127.0.0.1' and cfg['http']['port'] == http_port
        assert not cfg['http']['oidc']['enabled']
        cfg['source_access']['mode'] = 'allowlist'
        cfg['source_access']['allowed_ips'] = ['127.0.0.1']
        cfg['http'].update(address='::1',port=2080)
        assert api('save_config',{'config':cfg})
        assert api('load_config')['http'] == cfg['http']
        assert api('load_config')['source_access']['mode'] == 'allowlist'
        assert api('start',{'config':cfg})['running']
        assert not api('stop')['running']
        assert not api('status')['running']
        print('HTTP UI assets, request protections, start/stop, and configuration persistence passed.')
    finally:
        agent.close(graceful=True)
