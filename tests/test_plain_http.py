# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Plain http is refused for every fetch (federation metadata, and the Shared Signals transmitter's
configuration, JWKS, stream and poll) unless the host is loopback, before any connection.
``http://0.0.0.0:<port>`` reaches a 127.0.0.1 listener on Linux, so a listener that sees no
connection proves the refusal comes first."""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from stub_idp import IDP_ENTITY, REALM, REPLY, RP_CERT, RP_KEY, idp_metadata
from wsfed_caep import RelyingParty, SignalsReceiver, WsFedError
from wsfed_caep.http_client import is_loopback_host, send

REFUSED = "is refused: plain http is allowed only to a loopback host"


def config(source: str) -> dict:
    return {"realm": REALM, "replyUrl": REPLY, "privateKey": RP_KEY, "certificate": RP_CERT, "idpMetadata": source}


def refused(fn, code: str, shown: str, secret: str | None = None) -> None:
    with pytest.raises(WsFedError) as caught:
        fn()
    message = str(caught.value)
    assert caught.value.code == code, message
    assert message.startswith(f"http://{shown} {REFUSED}"), message
    if secret:
        assert secret not in message
    assert "/md" not in message and "?" not in message and "/jwks" not in message


def metadata_of(url: str):
    return lambda: RelyingParty.create(config(url))


class _Quiet:
    def info(self, message): pass
    def warn(self, message): pass
    def error(self, message): pass


def transmitter_at(url: str):
    return lambda: SignalsReceiver(url, lambda ids, event=None: None, log=_Quiet()).start()


class _Tripwire:
    """A 127.0.0.1 listener that counts the connections it is offered."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self._stop = True
        self._thread.join()
        self.sock.close()


@pytest.fixture()
def tripwire():
    wire = _Tripwire()
    yield wire
    wire.close()


def _serve(handler_body):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            status, ctype, body = handler_body(self)
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture()
def naming_jwks():
    """A loopback transmitter whose configuration names the JWKS it is given."""
    servers = []

    def start(jwks_uri: str) -> str:
        def body(req):
            base = f"http://127.0.0.1:{req.server.server_address[1]}"
            if req.path == "/.well-known/ssf-configuration":
                return 200, "application/json", json.dumps({
                    "issuer": base, "jwks_uri": jwks_uri, "configuration_endpoint": f"{base}/ssf/stream",
                    "delivery_methods_supported": ["urn:ietf:rfc:8936"]})
            return 200, "application/json", "{}"
        httpd = _serve(body)
        servers.append(httpd)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    yield start
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def test_knows_a_loopback_host():
    for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "127.255.255.255", "::1"]:
        assert is_loopback_host(host), host
    for host in ["example.com", "0.0.0.0", "128.0.0.1", "10.0.0.1", "localhost.example.com", "::ffff:127.0.0.1", "::", ""]:
        assert not is_loopback_host(host), host


def test_refuses_metadata_and_the_transmitter_on_example_com():
    refused(metadata_of("http://example.com/md?x=1"), "metadata", "example.com")
    refused(transmitter_at("http://example.com:8080"), "ssf", "example.com:8080")


def test_refuses_a_jwks_on_example_com_that_a_loopback_transmitter_names(naming_jwks):
    refused(transmitter_at(naming_jwks("http://example.com/jwks")), "ssf", "example.com")


def test_refuses_0000_before_connecting(tripwire, naming_jwks):
    port = tripwire.port
    refused(metadata_of(f"http://0.0.0.0:{port}/md"), "metadata", f"0.0.0.0:{port}")
    refused(transmitter_at(f"http://0.0.0.0:{port}"), "ssf", f"0.0.0.0:{port}")
    refused(transmitter_at(naming_jwks(f"http://0.0.0.0:{port}/jwks")), "ssf", f"0.0.0.0:{port}")
    time.sleep(0.3)
    assert tripwire.connections == 0


def test_userinfo_is_never_loopback_and_the_password_stays_out(tripwire):
    port = tripwire.port
    refused(metadata_of(f"http://localhost:{port}@example.com/md"), "metadata", "example.com")
    refused(metadata_of(f"http://user:s3cret-pw@localhost:{port}/md"), "metadata", f"localhost:{port}", "s3cret-pw")
    refused(transmitter_at(f"http://user:s3cret-pw@127.0.0.1:{port}"), "ssf", f"127.0.0.1:{port}", "s3cret-pw")
    time.sleep(0.3)
    assert tripwire.connections == 0


def test_refuses_whitespace_and_control_characters_without_connecting(tripwire):
    port = tripwire.port

    def unsafe(fn, code):
        with pytest.raises(WsFedError) as caught:
            fn()
        assert caught.value.code == code
        assert "whitespace or a control character" in str(caught.value)

    for url in [f"http://127.0.0.1:{port}/m\td", f"http://127.0.0.1:{port}/m\nd", "http://exa\x00mple.com/md", f"https://127.0.0.1:{port}/m d"]:
        unsafe(metadata_of(url), "metadata")
        unsafe(transmitter_at(url), "ssf")
    # The configuration strips idpMetadata, so the outer cases go to send() directly.
    for url in [f"http://127.0.0.1:{port}/md\t", f" http://127.0.0.1:{port}/md", f"http://127.0.0.1:{port}/md\r\n"]:
        unsafe(lambda: send(url, {}, {}, "metadata"), "metadata")
    time.sleep(0.3)
    assert tripwire.connections == 0


@pytest.fixture()
def metadata_server():
    httpd = _serve(lambda req: (200, "application/samlmetadata+xml", idp_metadata()))
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_reads_metadata_from_loopback_http(metadata_server):
    assert RelyingParty.create(config(f"http://127.0.0.1:{metadata_server}/md")).idp.entity_id == IDP_ENTITY
    assert RelyingParty.create(config(f"http://localhost:{metadata_server}/md")).idp.entity_id == IDP_ENTITY


def test_https_to_an_unreachable_host_is_a_connection_error():
    with pytest.raises(WsFedError) as caught:
        RelyingParty.create(config("https://127.0.0.1:1/md"))
    assert caught.value.code == "metadata"
    assert REFUSED not in str(caught.value)
    assert "refused" in str(caught.value).lower()
