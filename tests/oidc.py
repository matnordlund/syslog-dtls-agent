#!/usr/bin/env python3
"""OIDC integration with a disposable signed-token provider; no external accounts."""
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit
from interop import AGENT, OPENSSL, Process, configuration, create_pki, port, wait_for


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def tcp_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix="syslog-oidc-test-") as tmp:
    directory = Path(tmp)
    create_pki(directory)
    key = directory / "client.key"
    modulus = subprocess.check_output([OPENSSL, "rsa", "-in", str(key), "-modulus", "-noout"])
    modulus = bytes.fromhex(modulus.decode().strip().split("=")[1])
    jwks = {"keys": [{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": b64(modulus), "e": "AQAB"}]}
    codes = {}
    issued_tokens = set()
    provider_logouts = []
    sensitive_values = {"test-secret", "access-secret", "provider-description-secret"}
    behavior = {"mode": "valid", "confidential": True, "unavailable": False, "logout_endpoint": None}

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path)
            if path.path == "/custom/discovery.json":
                if behavior["unavailable"]:
                    self.send_error(503)
                    return
                self.respond({"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                              "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
                              "response_types_supported": ["code"], "subject_types_supported": ["public"],
                              "id_token_signing_alg_values_supported": ["RS256"],
                              **({"end_session_endpoint":behavior["logout_endpoint"]} if behavior["logout_endpoint"] else {})})
            elif path.path == "/jwks":
                self.respond(jwks)
            elif path.path == "/authorize":
                assert [key for key, _ in parse_qsl(path.query)] == ["response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "nonce", "scope"]
                params = parse_qs(path.query)
                assert params["client_id"] == ["agent"]
                assert params["response_type"] == ["code"]
                assert params["code_challenge_method"] == ["S256"]
                assert "openid" in params["scope"][0].split()
                code = secrets.token_urlsafe(24)
                sensitive_values.update([code, params["state"][0], params["nonce"][0], params["code_challenge"][0]])
                codes[code] = (params, behavior["mode"])
                location = params["redirect_uri"][0] + "?" + urlencode({"code": code, "state": params["state"][0]})
                self.send_response(303)
                self.send_header("Location", location)
                self.end_headers()
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path == "/end-session":
                params = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                assert params["id_token_hint"][0] in issued_tokens
                assert params["client_id"] == ["agent"]
                assert "client_secret" not in params
                provider_logouts.append(params)
                self.send_response(303)
                self.send_header("Location",params["post_logout_redirect_uri"][0])
                self.end_headers()
                return
            assert self.path == "/token"
            if behavior["confidential"]:
                assert self.headers.get("Authorization") == "Basic " + base64.b64encode(b"agent:test-secret").decode()
            else:
                assert self.headers.get("Authorization") is None
            params = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if not behavior["confidential"]:
                assert params["client_id"] == ["agent"]
            auth, mode = codes.pop(params["code"][0])
            sensitive_values.add(params["code_verifier"][0])
            if mode == "token_error":
                body = json.dumps({"error":"invalid_client","error_description":"provider-description-secret"}).encode()
                self.send_response(400)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            assert b64(hashlib.sha256(params["code_verifier"][0].encode()).digest()) == auth["code_challenge"][0]
            assert params["redirect_uri"] == auth["redirect_uri"]
            now = int(time.time())
            claims = {"iss": issuer, "sub": "user-123", "aud": "agent", "iat": now,
                      "exp": now + (2 if mode == "short" else 300), "nonce": auth["nonce"][0],
                      "roles": ["other", "operators"], "preferred_username":"test-user", "email":"test@example.invalid"}
            changes = {"wrong_group": {"roles": ["Operators"]}, "other_group": {"roles": ["unrelated"]}, "wrong_issuer": {"iss": issuer + "/wrong"},
                       "wrong_audience": {"aud": "other"}, "expired": {"exp": now - 5},
                       "wrong_nonce": {"nonce": "wrong"}, "future_iat": {"iat": now + 3600},
                       "wrong_azp": {"azp": "other"}, "future_nbf": {"nbf": now + 3600},
                       "malformed_group": {"roles": ["operators", 1]},
                       "scalar_group": {"roles": "operators"},
                       "comma_groups": {"roles": "Administrator,Remote_VPN,operators"},
                       "comma_wrong_case": {"roles": "Administrator,Operators"},
                       "comma_substring": {"roles": "Administrator,operators-extra"}, "wrong_hash": {"at_hash": "wrong"}}
            claims.update(changes.get(mode, {}))
            if mode == "missing_group":
                del claims["roles"]
            if mode in ["username_email", "username_subject"]:
                claims.pop("preferred_username")
            if mode == "username_subject":
                claims.pop("email")
            signing_input = (b64(json.dumps({"alg": "RS256", "kid": "test"}).encode()) + "." +
                             b64(json.dumps(claims).encode())).encode()
            signature = subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", str(key)],
                                       input=signing_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
            if mode == "bad_signature":
                signature = bytes([signature[0] ^ 1]) + signature[1:]
            id_token = signing_input.decode() + "." + b64(signature)
            issued_tokens.add(id_token)
            sensitive_values.add(id_token)
            self.respond({"access_token": "access-secret", "token_type": "Bearer",
                          "id_token": id_token})

    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    issuer = f"http://127.0.0.1:{provider.server_port}"
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    http_port = tcp_port()
    origin = f"http://127.0.0.1:{http_port}"
    config = directory / "agent.toml"
    config.write_text(configuration(directory, port(), port()) + f'''
[http]
address = "127.0.0.1"
port = {http_port}
[http.oidc]
enabled = true
discovery_uri = "{issuer}/custom/discovery.json"
client_id = "agent"
client_secret = "test-secret"
public_url = "{origin}"
groups_claim = "roles"
required_group = "operators"
scopes = ["profile", "groups"]
''')
    agent = Process([AGENT, "--config", config], lines=True)

    def request(url, method="GET", body=None, headers=None):
        parsed = urlsplit(url if "://" in url else origin + url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=15)
        try:
            connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""), body, headers or {})
            response = connection.getresponse()
            return response.status, response.read(), response.getheaders()
        finally:
            connection.close()

    def header(response, name):
        return next((value for key, value in response[2] if key.lower() == name.lower()), None)

    def cookie(response, name):
        return next((value.split(";")[0] for key, value in response[2]
                     if key.lower() == "set-cookie" and value.startswith(name + "=")), None)

    def begin(mode="valid", extra_headers=None):
        behavior["mode"] = mode
        login = request("/auth/login", headers=extra_headers)
        assert login[0] == 303, login
        flow = cookie(login, "syslog_flow") or cookie(login, "__Host-syslog_flow")
        sensitive_values.add(flow.split("=",1)[1])
        assert "HttpOnly" in header(login, "Set-Cookie") and "SameSite=Lax" in header(login, "Set-Cookie")
        authorize = request(header(login, "Location"))
        assert authorize[0] == 303
        return header(authorize, "Location"), flow

    def complete(mode="valid"):
        callback, flow = begin(mode)
        response = request(callback, headers={"Cookie": flow})
        return response, callback, flow

    def api(session=None, name="status", config_value=None):
        headers = {"Content-Type": "application/json", "X-Syslog-UI": "1"}
        if session:
            headers["Cookie"] = session
        return request("/api/" + name, "POST", json.dumps({"config": config_value} if config_value else {}), headers)

    try:
        wait_for(lambda: b"HTTP UI:" in agent.errors, "OIDC agent did not start")
        assert request("/")[0] == 303
        for name in ["status", "default_config", "start", "stop", "save_config", "load_config", "validate"]:
            assert api(name=name)[0] == 401
        assert request("/app.js")[0] == 303
        assert request("/auth/session")[0] == 401
        assert request("/", headers={"Host": "evil.example"})[0] == 403
        behavior["unavailable"] = True
        assert request("/auth/login")[0] == 503
        assert api()[0] == 401
        behavior["unavailable"] = False
        callback, flow = begin()
        assert request(callback)[0] == 403  # State alone cannot log in a different browser.
        assert request(callback, headers={"Cookie": flow})[0] == 303
        callback, flow = begin()
        assert request(callback + "&state=duplicate", headers={"Cookie": flow})[0] == 403
        callback, flow = begin()
        parsed = urlsplit(callback)
        params = parse_qs(parsed.query)
        params["state"] = ["incorrect"]
        wrong = parsed._replace(query=urlencode({k: v[0] for k, v in params.items()})).geturl()
        assert request(wrong, headers={"Cookie": flow})[0] == 403
        assert request(callback, headers={"Cookie": flow})[0] == 403  # Consumed even after failure.
        for mode in ["wrong_group", "other_group", "comma_wrong_case", "comma_substring", "missing_group", "malformed_group", "wrong_issuer",
                     "wrong_audience", "expired", "wrong_nonce", "bad_signature", "future_iat",
                     "wrong_azp", "future_nbf", "wrong_hash", "token_error"]:
            response, _, _ = complete(mode)
            assert response[0] == 403, (mode, response)
            assert cookie(response, "syslog_session") is None
        response, callback, flow = complete("valid")
        assert response[0] == 303, response
        session = cookie(response, "syslog_session")
        assert session and api(session)[0] == 200
        assert json.loads(request("/auth/session",headers={"Cookie":session})[1]) == {"username":"test-user"}
        sensitive_values.add(session.split("=",1)[1])
        assert request("/agent-mode.js", headers={"Cookie": session})[1].endswith(b"window.__SYSLOG_OIDC__ = true;")
        assert request(callback, headers={"Cookie": flow})[0] == 403  # No replay.
        assert request("/api/stop", "POST", "{}", {"Cookie": session, "Content-Type": "application/json"})[0] == 403
        assert request("/api/stop", "POST", "{}", {"Cookie": session, "X-Syslog-UI": "1",
            "Content-Type": "application/json", "Origin": "https://evil.example"})[0] == 403
        cfg = json.loads(api(session, "default_config")[1])
        assert cfg["http"]["oidc"]["client_secret"] == "test-secret"
        assert request("/auth/logout", "POST", "{}", {"Cookie": session})[0] == 403
        local_logout = request("/auth/logout", "POST", "{}", {"Cookie": session, "X-Syslog-UI": "1"})
        assert local_logout[0] == 200
        assert json.loads(local_logout[1]) == {"redirect":"/auth/signed-out"}
        assert api(session)[0] == 401

        # Provider logout is browser-mediated, one-use and clears local access first.
        behavior["logout_endpoint"] = issuer + "/end-session"
        response, _, _ = complete()
        provider_session = cookie(response,"syslog_session")
        signed_out = request("/auth/logout","POST","{}",{"Cookie":provider_session,"X-Syslog-UI":"1"})
        assert json.loads(signed_out[1]) == {"redirect":"/auth/end-session"}
        assert api(provider_session)[0] == 401
        assert request("/auth/session",headers={"Cookie":provider_session})[0] == 401
        logout_cookie = cookie(signed_out,"syslog_logout")
        assert logout_cookie
        sensitive_values.add(logout_cookie.split("=",1)[1])
        assert b"id_token_hint" not in request("/auth/end-session")[1]
        handoff = request("/auth/end-session",headers={"Cookie":logout_cookie})
        assert handoff[0] == 200
        class LogoutForm(HTMLParser):
            def __init__(self):
                super().__init__()
                self.action = None
                self.values = {}
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "form":
                    assert attrs["method"] == "post"
                    self.action = attrs["action"]
                if tag == "input":
                    self.values[attrs["name"]] = attrs["value"]
        form = LogoutForm()
        form.feed(handoff[1].decode())
        assert form.action == issuer + "/end-session"
        assert form.values["post_logout_redirect_uri"] == origin + "/auth/signed-out"
        assert b"id_token_hint" not in request("/auth/end-session",headers={"Cookie":logout_cookie})[1]
        assert request("/auth/logout.js")[0] == 200
        provider_response = request(form.action,"POST",urlencode(form.values),
            {"Content-Type":"application/x-www-form-urlencoded"})
        assert provider_response[0] == 303
        assert request(header(provider_response,"Location"))[0] == 200
        assert len(provider_logouts) == 1
        behavior["logout_endpoint"] = "javascript:alert(1)"
        response, _, _ = complete()
        invalid_endpoint_session = cookie(response,"syslog_session")
        assert json.loads(request("/auth/logout","POST","{}",{"Cookie":invalid_endpoint_session,"X-Syslog-UI":"1"})[1]) == {"redirect":"/auth/signed-out"}
        behavior["logout_endpoint"] = None
        for mode, username in [("username_email","test@example.invalid"),("username_subject","user-123")]:
            response, _, _ = complete(mode)
            assert json.loads(request("/auth/session",headers={"Cookie":cookie(response,"syslog_session")})[1]) == {"username":username}
        response, _, _ = complete("scalar_group")
        assert response[0] == 303
        response, _, _ = complete("comma_groups")
        assert response[0] == 303
        assert api(cookie(response, "syslog_session"))[0] == 200
        response, _, _ = complete("short")
        short_session = cookie(response, "syslog_session")
        assert short_session
        time.sleep(2.2)
        assert api(short_session)[0] == 401
        # Saving auth-disabled settings must not weaken the running listener.
        response, _, _ = complete()
        session = cookie(response, "syslog_session")
        assert api(session, "stop")[0] == 200
        cfg["http"]["oidc"]["enabled"] = False
        assert api(session, "save_config", cfg)[0] == 200
        assert 'client_secret = "test-secret"' in config.read_text()
        if __import__("os").name != "nt":
            assert config.stat().st_mode & 0o777 == 0o600
        assert api()[0] == 401
        agent.close(graceful=True)
        logs = bytes(agent.errors)
        for value in sensitive_values:
            assert value.encode() not in logs, "Sensitive OIDC value appeared in logs"
        if "release" in AGENT.parts:
            assert b"[oidc]" not in logs
        else:
            for expected in [b"Authentication enabled", b"discovery: HTTP 200",
                             b"Discovery parsed successfully", b"JWKS parsed successfully",
                             b"redirect_uri=", b"PKCE=S256", b"token exchange: HTTP 400",
                             b"provider error=invalid_client", b"ID token nonce mismatch",
                             b"Required group missing", b"Verified ID-token claims (sensitive fields redacted)",
                             b'"roles":["other","operators"]', b'"nonce":"[REDACTED]"', b"configured claim absent from ID token",
                             b"required group not found in string array", b"matched string-array member", b"matched comma-separated group", b"Login successful"]:
                assert expected in logs, expected

        text = config.read_text().replace("enabled = false", "enabled = true")
        for public_url, authority, prefix in [
            ("https://agent.example", "agent.example", "__Host-"),
            ("http://agent.internal:1080", "agent.internal:1080", ""),
        ]:
            # Test proxy origin pinning and Secure host-only cookies (simulate TLS termination).
            config.write_text(text.replace(origin, public_url).replace('client_secret = "test-secret"', 'client_secret = ""'))
            behavior["confidential"] = False
            agent = Process([AGENT, "--config", config], lines=True)
            wait_for(lambda: b"HTTP UI:" in agent.errors, "Proxied agent did not start")
            assert request("/")[0] == 403  # No Host/forwarded-header bypass on the backend URL.
            assert request("/", headers={"X-Forwarded-Host": authority})[0] == 403
            assert request("/", headers={"Host": authority})[0] == 303
            callback, flow = begin(extra_headers={"Host": authority})
            assert flow.startswith(prefix + "syslog_flow=")
            callback_path = urlsplit(callback).path + "?" + urlsplit(callback).query
            response = request(callback_path, headers={"Host": authority, "Cookie": flow})
            assert response[0] == 303, response
            secure_session = cookie(response, prefix + "syslog_session")
            assert secure_session
            assert ("Secure" in header(response, "Set-Cookie")) == bool(prefix)
            assert "Domain=" not in header(response, "Set-Cookie")
            assert request("/api/status", "POST", "{}", {"Host": authority, "Cookie": secure_session,
                "Origin": public_url, "Content-Type": "application/json", "X-Syslog-UI": "1"})[0] == 200
            assert b"test-secret" not in agent.output + agent.errors
            assert b"access-secret" not in agent.output + agent.errors
            agent.close(graceful=True)
        print("OIDC signed-token login, PKCE, group authorization, token rejection, replay, sessions, logout and proxy protections passed.")
    finally:
        agent.close(graceful=True)
        provider.shutdown()
        provider.server_close()
