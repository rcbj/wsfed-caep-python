# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The demo handler over HTTP, against the stub identity provider."""

from __future__ import annotations

import threading
from http.client import HTTPConnection
from urllib.parse import parse_qsl, urlsplit

import pytest

from demo.app import App
from stub_idp import IDP_ENTITY, PASSIVE, RP_CERT, RP_KEY, idp_metadata, signed_assertion, wresult
from wsfed_caep import RelyingParty


@pytest.fixture()
def base():
    rp = RelyingParty.create({
        "realm": "https://rp.test/",
        "replyUrl": "https://rp.test/wsfed",
        "privateKey": RP_KEY,
        "certificate": RP_CERT,
        "idpMetadata": idp_metadata(),
    })
    app = App(rp)

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _go(self):
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {name.lower(): value for name, value in self.headers.items()}
            status, fields, payload = app(self.command, self.path, headers, body)
            self.send_response(status)
            for name, value in fields:
                self.send_header(name, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._go()

        def do_POST(self):
            self._go()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _cookies(response) -> dict[str, str]:
    out = {}
    for raw in response.headers.get_all("set-cookie") or []:
        pair = raw.split(";", 1)[0]
        if "=" in pair:
            name, value = pair.split("=", 1)
            out[name] = value
    return out


def test_sign_in_cleanup_and_logout(base):
    host, port = base.split(":")
    conn = HTTPConnection(host, int(port), timeout=5)
    conn.request("GET", "/healthz")
    health = conn.getresponse()
    assert health.status == 200
    assert health.read() == b"ok"
    conn.request("GET", "/login")
    login = conn.getresponse()
    assert login.status == 302
    location = login.getheader("location")
    login.read()
    parsed = urlsplit(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == PASSIVE
    params = dict(parse_qsl(parsed.query))
    assert params["wa"] == "wsignin1.0"
    pending = _cookies(login)["wsfed_pending"]
    body = __import__("urllib.parse").parse.urlencode({
        "wa": "wsignin1.0",
        "wresult": wresult(token=signed_assertion()["xml"]),
        "wctx": params["wctx"],
    }).encode()
    conn.request("POST", "/wsfed", body=body, headers={"content-type": "application/x-www-form-urlencoded", "cookie": f"wsfed_pending={pending}"})
    reply = conn.getresponse()
    assert reply.status == 303, reply.read()
    sid = _cookies(reply)["sid"]
    reply.read()
    conn.request("GET", "/", headers={"cookie": f"sid={sid}"})
    home = conn.getresponse().read().decode()
    assert "Signed in as <strong>alice-1234</strong>" in home
    assert IDP_ENTITY in home
    conn.request("GET", "/wsfed?wa=wsignoutcleanup1.0", headers={"cookie": f"sid={sid}"})
    cleanup = conn.getresponse()
    assert cleanup.getheader("content-type") == "image/gif"
    cleanup.read()
    conn.request("GET", "/", headers={"cookie": f"sid={sid}"})
    assert "Sign in with WS-Federation" in conn.getresponse().read().decode()
    conn.request("POST", "/logout")
    out = conn.getresponse()
    out.read()
    assert dict(parse_qsl(urlsplit(out.getheader("location")).query))["wa"] == "wsignout1.0"
    conn.request("POST", "/wsfed", body=b"wa=wsignin1.0&wresult=x&wctx=id%3Dabc", headers={"content-type": "application/x-www-form-urlencoded"})
    refused = conn.getresponse()
    refused.read()
    assert refused.status == 400
