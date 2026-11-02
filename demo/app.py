#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""WS-Federation demo. stdlib HTTP only.

GET /healthz is 200 ok before the identity provider is reachable. GET /login redirects with
wa=wsignin1.0. POST at the reply URL accepts the sign-in. GET there with wsignoutcleanup1.0
is a GIF. POST /logout signs out here and at the identity provider. GET /live-status is JSON:
whether this process is signed in, and the Shared Signals events it has accepted.

A loopback realm and reply URL follow PORT. PUBLIC_URL or --public-url replaces the origin and
keeps the path. The default http://localhost:3000 is not an explicit public URL.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from configure_iya_sts import endpoints_for  # noqa: E402
from wsfed_caep import RelyingParty, SignalsReceiver  # noqa: E402

_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
_HERE = Path(__file__).resolve().parent


def _sign(secret: bytes, value: str) -> str:
    mac = base64.urlsafe_b64encode(hmac.new(secret, value.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{value}.{mac}"


def _unsign(secret: bytes, signed: str | None) -> str | None:
    if not signed or "." not in signed:
        return None
    if hmac.compare_digest(_sign(secret, signed.rsplit(".", 1)[0]), signed):
        return signed.rsplit(".", 1)[0]
    return None


def _cookies(header: str | None) -> dict[str, str]:
    out = {}
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.strip().split("=", 1)
        if name and value:
            out[name] = value
    return out


def _esc(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class App:
    """The request handler the example application and the demo share."""

    def __init__(self, rp: RelyingParty, receiver: SignalsReceiver | None = None):
        self.rp = rp
        self.receiver = receiver
        self.sessions: dict[str, object] = {}
        self.events: list[dict] = []
        self.receiver_state = "not configured"
        self.secret = secrets.token_bytes(32)
        reply = urlsplit(rp.config.reply_url)
        self.reply_path = reply.path or "/wsfed"
        self.secure = "; Secure" if reply.scheme == "https" else ""

    def _pending(self, value: str, age: int) -> str:
        return f"wsfed_pending={value}; Path={self.reply_path}; HttpOnly; SameSite=None{self.secure or '; Secure'}; Max-Age={age}"

    def __call__(self, method: str, target: str, headers: dict, body: bytes):
        url = urlsplit(target)
        path = url.path or "/"
        cookies = _cookies(headers.get("cookie"))
        sid = _unsign(self.secret, cookies.get("sid"))
        method = method.upper()

        if path == "/healthz" and method == "GET":
            return 200, [("content-type", "text/plain")], b"ok"

        if path == "/live-status" and method == "GET":
            return self._live_status(sid)

        if path == "/login" and method == "GET":
            request = self.rp.login(relay_state="/")
            return 302, [("location", request.url), ("set-cookie", self._pending(_sign(self.secret, request.id), 600))], b""

        if path == self.reply_path and self.rp.is_sign_out_cleanup({"method": method, "url": target}):
            if sid:
                self.sessions.pop(sid, None)
                if self.receiver:
                    self.receiver.untrack(sid)
            return 200, [("content-type", "image/gif"), ("set-cookie", f"sid=; Path=/; HttpOnly; Max-Age=0{self.secure}")], _GIF

        if path == self.reply_path and method == "POST":
            try:
                who = self.rp.handle_reply(
                    {"method": "POST", "url": target, "body": body.decode("utf-8")},
                    _unsign(self.secret, cookies.get("wsfed_pending")),
                )
            except Exception:
                return 400, [("content-type", "text/plain")], b"Sign-in failed."
            session_id = secrets.token_urlsafe(24)
            self.sessions[session_id] = who
            if self.receiver:
                self.receiver.track(session_id, who)
            relay = getattr(who, "relay_state", None)
            nxt = relay if isinstance(relay, str) and relay.startswith("/") and not relay.startswith("//") else "/"
            headers_out = [
                ("location", nxt),
                ("set-cookie", self._pending("", 0)),
                ("set-cookie", f"sid={_sign(self.secret, session_id)}; Path=/; HttpOnly; SameSite=Lax{self.secure}"),
            ]
            return 303, headers_out, b""

        if path == "/logout" and method == "POST":
            if sid:
                self.sessions.pop(sid, None)
                if self.receiver:
                    self.receiver.untrack(sid)
            origin = f"{urlsplit(self.rp.config.reply_url).scheme}://{urlsplit(self.rp.config.reply_url).netloc}/"
            return 303, [("location", self.rp.logout(reply=origin)), ("set-cookie", f"sid=; Path=/; HttpOnly; Max-Age=0{self.secure}")], b""

        if path == "/FederationMetadata/2007-06/FederationMetadata.xml" and method == "GET":
            xml = self.rp.metadata().encode()
            return 200, [("content-type", "application/samlmetadata+xml")], xml

        if path == "/" and method == "GET":
            who = self.sessions.get(sid) if sid else None
            if who is not None:
                page = (
                    f"<p>Signed in as <strong>{_esc(who.name_id)}</strong> by {_esc(who.issuer)}.</p>"
                    '<form method="post" action="/logout"><button>Sign out</button></form>'
                )
            else:
                page = '<p><a href="/login">Sign in with WS-Federation</a></p>'
            html = (
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WS-Federation</title>"
                "<link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main>"
                f"{page}</main></body></html>"
            ).encode()
            return 200, [("content-type", "text/html; charset=utf-8")], html

        if path == "/styles.css" and method == "GET":
            css = (_HERE / "public" / "styles.css").read_bytes() if (_HERE / "public" / "styles.css").exists() else b"body{font-family:sans-serif}\n"
            return 200, [("content-type", "text/css")], css

        return 404, [("content-type", "text/plain")], b"Not found"

    def _remember(self, event) -> None:
        self.events.append({"type": getattr(event, "type", None), "jti": getattr(event, "jti", None)})

    def _live_status(self, sid: str | None):
        who = self.sessions.get(sid) if sid else None
        subject = getattr(who, "name_id", None) if who is not None else None
        body = {
            "signedIn": who is not None,
            "subject": None if subject is None else str(subject),
            "receiver": self.receiver_state,
            "events": [{"type": item.get("type"), "jti": item.get("jti")} for item in self.events],
        }
        raw = json.dumps(body).encode()
        return 200, [("content-type", "application/json"), ("cache-control", "no-store")], raw


def _public_url(argv: list[str]) -> tuple[str, bool]:
    given = bool(os.environ.get("PUBLIC_URL"))
    public = (os.environ.get("PUBLIC_URL") or "").rstrip("/")
    i = 0
    while i < len(argv):
        if argv[i] == "--public-url":
            if i + 1 >= len(argv) or not argv[i + 1]:
                raise SystemExit("--public-url is empty")
            public = argv[i + 1].rstrip("/")
            given = True
            i += 2
            continue
        i += 1
    return public, given


def _config_path(argv: list[str]) -> Path:
    configured = os.environ.get("WSFED_CONFIG")
    i = 0
    while i < len(argv):
        if argv[i] == "--config" and i + 1 < len(argv):
            configured = argv[i + 1]
        i += 1
    return Path(configured) if configured else _HERE / "wsfed.json"


def load_party(config_path: Path, port: int, public_url: str, public_url_given: bool) -> tuple[RelyingParty, dict]:
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    endpoints = endpoints_for(
        raw.get("realm") or "",
        raw.get("replyUrl") or "",
        {"public_url": public_url, "public_url_given": public_url_given, "port": port},
    )
    overrides = {}
    if endpoints.get("realm"):
        overrides["realm"] = endpoints["realm"]
    if endpoints.get("reply_url"):
        overrides["replyUrl"] = endpoints["reply_url"]
    return RelyingParty.from_file(str(config_path), overrides), raw


def serve(port: int, get_app) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _read(self) -> bytes:
            length = int(self.headers.get("content-length") or 0)
            return self.rfile.read(length) if length else b""

        def _send(self, status: int, headers: list[tuple[str, str]], payload: bytes) -> None:
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _go(self) -> None:
            path = urlsplit(self.path).path
            if path == "/healthz":
                self._send(200, [("content-type", "text/plain")], b"ok")
                return
            try:
                app = get_app()
            except Exception as err:
                self._send(503, [("content-type", "text/plain")], f"not ready: {err}\n".encode())
                return
            header_map = {name.lower(): value for name, value in self.headers.items()}
            status, headers, payload = app(self.command, self.path, header_map, self._read())
            self._send(status, headers, payload)

        def do_GET(self):
            self._go()

        def do_POST(self):
            self._go()

    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"wsfed-caep demo on port {port}", flush=True)
    httpd.serve_forever()


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    port = int(os.environ.get("PORT") or "3000")
    for i, arg in enumerate(argv):
        if arg == "--port" and i + 1 < len(argv):
            port = int(argv[i + 1])
    public, given = _public_url(argv)
    config_path = _config_path(argv)
    holder: dict = {}

    def get_app():
        if "app" in holder:
            return holder["app"]
        rp, raw = load_party(config_path, port, public, given)
        app = App(rp, None)
        ssf = raw.get("ssf") if isinstance(raw.get("ssf"), dict) else None
        if raw.get("signals") is False:
            app.receiver_state = "not configured (signals are off)"
        elif not (ssf and ssf.get("transmitter")):
            app.receiver_state = "not configured (no ssf block in the configuration file)"
        elif not getattr(rp.config, "private_key", None):
            app.receiver_state = "not running: the relying party has no private key"
        else:
            from cryptography.hazmat.primitives import serialization

            def end(ids, _event):
                for local_id in ids:
                    app.sessions.pop(local_id, None)

            tls = {}
            if getattr(rp.config, "idp_ca", None):
                tls["ca"] = rp.config.idp_ca
            tls["cert"] = rp.config.certificate.public_bytes(serialization.Encoding.PEM).decode()
            tls["key"] = rp.config.private_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode()
            receiver = SignalsReceiver(ssf["transmitter"], end, tls=tls, poll_interval_ms=int(ssf.get("pollIntervalMs") or 5000))
            receiver.on("*", app._remember)
            try:
                receiver.start()
                app.receiver = receiver
                stream_id = (receiver.stream or {}).get("stream_id")
                app.receiver_state = f"polling stream {stream_id} at {ssf['transmitter']}"
            except Exception as err:
                app.receiver_state = f"not running: {err}"
                print(f"ssf: not started: {err}", flush=True)
        holder["app"] = app
        return app

    serve(port, get_app)


if __name__ == "__main__":
    main()
