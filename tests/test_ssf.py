# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The Shared Signals receiver against a stub transmitter. No live iya-sts."""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from wsfed_caep import CAEP_EVENTS, EVENT, MemorySessionIndex, RISC_EVENTS, SignalsReceiver, WsFedError, subject_of
from wsfed_caep.ssf.jws import verify_compact_jws
from wsfed_caep.token import WsFedLogin

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _jwk(key: rsa.RSAPrivateKey, kid: str = "k1") -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


_JWK = _jwk(_PRIVATE)


def jws(payload: dict, key: rsa.RSAPrivateKey = _PRIVATE, header: dict | None = None) -> str:
    head = header or {"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
    h = _b64url(json.dumps(head, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}"


class _Stub:
    def __init__(self):
        self.queue: dict[str, str] = {}
        self.acked: list[str] = []
        self.errs: dict = {}
        self.created = 0
        self.url = ""
        self._streams: list[dict] = []
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _read(self) -> str:
                length = int(self.headers.get("content-length") or 0)
                return self.rfile.read(length).decode() if length else ""

            def _out(self, status: int, body=None) -> None:
                raw = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def _route(self, method: str) -> None:
                text = self._read()
                path = self.path.split("?", 1)[0]
                with stub._lock:
                    if path == "/.well-known/ssf-configuration":
                        return self._out(200, {
                            "issuer": stub.url,
                            "jwks_uri": f"{stub.url}/jwks",
                            "configuration_endpoint": f"{stub.url}/ssf/stream",
                            "verification_endpoint": f"{stub.url}/ssf/verify",
                            "delivery_methods_supported": ["urn:ietf:rfc:8936"],
                        })
                    if path == "/jwks":
                        return self._out(200, {"keys": [_JWK]})
                    if path == "/ssf/stream" and method == "GET":
                        return self._out(200, stub._streams)
                    if path == "/ssf/stream" and method == "POST":
                        body = json.loads(text)
                        stub.created += 1
                        stream = {
                            "stream_id": f"s{stub.created}",
                            "iss": stub.url,
                            "aud": "my-app",
                            "delivery": {"method": body["delivery"]["method"], "endpoint_url": f"{stub.url}/ssf/poll/s{stub.created}"},
                            "events_requested": body["events_requested"],
                            "events_delivered": body["events_requested"],
                        }
                        stub._streams.append(stream)
                        return self._out(201, stream)
                    if path.startswith("/ssf/poll/"):
                        body = json.loads(text or "{}")
                        for jti in body.get("ack") or []:
                            stub.acked.append(jti)
                            stub.queue.pop(jti, None)
                        for jti, err in (body.get("setErrs") or {}).items():
                            stub.errs[jti] = err
                            stub.queue.pop(jti, None)
                        return self._out(200, {"sets": dict(stub.queue), "moreAvailable": False})
                self._out(404, {"err": "not found"})

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


@pytest.fixture()
def stub():
    made = _Stub()
    made.start()
    yield made
    made.close()


def _set(stub: _Stub, event_type: str, sub_id: dict, extra: dict | None = None, key=None, aud: str | None = None, iss: str | None = None) -> str:
    jti = str(uuid.uuid4())
    payload = {
        "iss": iss or stub.url,
        "aud": aud or "my-app",
        "jti": jti,
        "iat": 1,
        "sub_id": sub_id,
        "events": {event_type: {"event_timestamp": 1, **(extra or {})}},
    }
    with stub._lock:
        stub.queue[jti] = jws(payload, key or _PRIVATE)
    return jti


def _login(person: str, session_index: str) -> WsFedLogin:
    return WsFedLogin(
        name_id=person,
        issuer="x",
        realm="https://rp.test/",
        trust_version="2005/02",
        encrypted=False,
        assertion_id=str(uuid.uuid4()),
        attributes={
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": [f"urn:uuid:{person}"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [f"{person}@example.com"],
        },
        attribute_friendly_names={},
        session_index=session_index,
    )


class _Log:
    def __init__(self):
        self.errors: list[str] = []

    def info(self, _message: str) -> None:
        return None

    def warn(self, _message: str) -> None:
        return None

    def error(self, message: str) -> None:
        self.errors.append(message)


def test_verifies_a_set_and_refuses_the_wrong_key():
    token = jws({"a": 1})
    assert verify_compact_jws(token, [_JWK])["payload"] == {"a": 1}
    with pytest.raises(WsFedError, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, _OTHER), [_JWK])
    with pytest.raises(WsFedError, match="no RSA signing key with kid nope"):
        verify_compact_jws(jws({"a": 1}, _PRIVATE, {"alg": "RS256", "kid": "nope"}), [_JWK])
    with pytest.raises(WsFedError, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, _PRIVATE, {"alg": "none"}), [_JWK])
    with pytest.raises(WsFedError, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, _PRIVATE, {"alg": "HS256", "kid": "k1"}), [_JWK])


def test_subjects():
    assert subject_of({"format": "complex", "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"}, "session": {"format": "opaque", "id": "S1"}}, "https://i") == {"person": "urn:uuid:a", "idp_session": "S1"}
    assert subject_of({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i") == {}
    assert subject_of({"format": "email", "email": "A@x.com"}, "https://i") == {"email": "A@x.com"}


def test_poll_stream_ends_the_named_sessions(stub: _Stub):
    ended: list[list[str]] = []
    seen = []
    receiver = SignalsReceiver(stub.url, lambda ids, _event: ended.append(list(ids)), poll_interval_ms=60_000, log=_Log())
    receiver.on("*", seen.append)
    receiver.start()
    receiver.stop()
    assert stub.created == 1
    assert receiver.stream["stream_id"] == "s1"
    receiver.track("L-a1", _login("alice", "IDP-A1"))
    receiver.track("L-a2", _login("alice", "IDP-A2"))
    receiver.track("L-b1", _login("bob", "IDP-B1"))
    j1 = _set(stub, EVENT["session_revoked"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}})
    j2 = _set(stub, EVENT["credential_change"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}}, {"credential_type": "password", "change_type": "update"})
    receiver.poll_once()
    assert ended == [["L-a1"]]
    change = next(event for event in seen if event.jti == j2)
    assert change.ended is False
    assert change.sessions == ["L-b1"]
    j3 = _set(stub, EVENT["account_disabled"], {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"})
    receiver.poll_once()
    assert ended == [["L-a1"], ["L-a2"]]
    assert j1 in stub.acked and j2 in stub.acked
    _set(stub, EVENT["credential_compromise"], {"format": "email", "email": "BOB@example.com"}, {"credential_type": "password"})
    receiver.poll_once()
    assert ended[2] == ["L-b1"]
    receiver.poll_once()
    assert j3 in stub.acked
    again = SignalsReceiver(stub.url, lambda ids, _event: None, log=_Log())
    again.start()
    again.stop()
    assert stub.created == 1
    assert again.stream["stream_id"] == "s1"


def test_forged_sets_are_reported(stub: _Stub):
    ended: list = []
    index = MemorySessionIndex()
    receiver = SignalsReceiver(stub.url, lambda ids, _event: ended.append(ids), session_index=index, log=_Log())
    receiver.start()
    receiver.stop()
    receiver.track("L-c1", _login("carol", "IDP-C1"))
    subject = {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:carol"}, "session": {"format": "opaque", "id": "IDP-C1"}}
    forged = _set(stub, EVENT["session_revoked"], subject, key=_OTHER)
    misaddressed = _set(stub, EVENT["session_revoked"], subject, aud="someone-else")
    foreign = _set(stub, EVENT["session_revoked"], subject, iss="https://evil.example")
    receiver.poll_once()
    assert ended == []
    assert index.by_person("urn:uuid:carol") == ["L-c1"]
    receiver.poll_once()
    for jti in (forged, misaddressed, foreign):
        assert jti in stub.errs


def test_event_catalog():
    assert len(CAEP_EVENTS) == 8
    assert len(RISC_EVENTS) == 14
    assert EVENT["risk_level_change"] in CAEP_EVENTS
    assert EVENT["opt_out_effective"] in RISC_EVENTS


def test_handler_and_on_end_errors_are_still_acknowledged(stub: _Stub):
    log = _Log()
    seen: list[str] = []

    def boom(_ids, _event):
        raise RuntimeError("store down")

    def handler_bug(_event):
        raise RuntimeError("handler bug")

    receiver = SignalsReceiver(stub.url, boom, log=log)
    receiver.on(EVENT["credential_change"], handler_bug)
    receiver.on("*", lambda event: seen.append(event.jti))
    receiver.start()
    receiver.stop()
    receiver.track("L-d1", _login("dave", "IDP-D1"))
    j1 = _set(stub, EVENT["credential_change"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}}, {"credential_type": "password", "change_type": "update"})
    j2 = _set(stub, EVENT["session_revoked"], {"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}, "session": {"format": "opaque", "id": "IDP-D1"}})
    receiver.poll_once()
    receiver.poll_once()
    receiver.poll_once()
    assert j1 in stub.acked and j2 in stub.acked
    assert j1 not in stub.errs and j2 not in stub.errs
    assert sorted(seen) == sorted([j1, j2])
    assert any("handler for" in message and "credential-change" in message and "threw" in message for message in log.errors)
    assert any("onEndSessions threw" in message for message in log.errors)


def test_overlapping_polls_handle_a_set_once(stub: _Stub):
    seen: list[str] = []
    receiver = SignalsReceiver(stub.url, lambda _ids, _event: None, log=_Log())
    receiver.on("*", lambda event: seen.append(event.jti))
    receiver.start()
    receiver.stop()
    jti = _set(stub, EVENT["account_enabled"], {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:erin"})
    threads = [threading.Thread(target=receiver.poll_once) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    receiver.poll_once()
    assert [item for item in seen if item == jti] == [jti]


def test_refuses_a_transmitter_without_poll_delivery():
    receiver = SignalsReceiver("http://127.0.0.1:1", lambda _ids, _event: None, log=_Log())
    with pytest.raises(WsFedError) as caught:
        receiver.start()
    assert caught.value.code == "ssf"
