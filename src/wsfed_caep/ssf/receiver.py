# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Shared Signals poll receiver (OpenID SSF 1.0, RFC 8936). The relying party does not start one."""

from __future__ import annotations

import json
import sys
import threading

from wsfed_caep.errors import WsFedError
from wsfed_caep.http_client import send
from wsfed_caep.ssf.events import DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, subject_of
from wsfed_caep.ssf.jws import verify_compact_jws
from wsfed_caep.ssf.session_index import MemorySessionIndex, tracked_from

POLL_METHOD = "urn:ietf:rfc:8936"


class _Log:
    def info(self, message: str) -> None:
        print(message)

    def warn(self, message: str) -> None:
        print(message, file=sys.stderr)

    def error(self, message: str) -> None:
        print(message, file=sys.stderr)


class SignalEvent:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class SignalsReceiver:
    def __init__(self, transmitter: str, on_end_sessions, tls: dict | None = None, headers=None,
                 events_requested=None, end_on=None, session_index=None, subject_attribute: str | None = None,
                 description: str | None = None, poll_interval_ms: int = 5000, max_events: int = 50, log=None):
        if not callable(on_end_sessions):
            raise WsFedError("config", "onEndSessions is required")
        if not isinstance(transmitter, str) or not (transmitter.startswith("http://") or transmitter.startswith("https://")):
            raise WsFedError("config", "transmitter must be an http(s) URL")
        self.transmitter = transmitter.rstrip("/")
        self._on_end = on_end_sessions
        self._tls = tls or {}
        self._headers = headers
        self._events_requested = list(events_requested or DEFAULT_EVENTS_REQUESTED)
        self._end_on = list(end_on or DEFAULT_ENDING_EVENTS)
        self._index = session_index or MemorySessionIndex()
        self._subject_attribute = subject_attribute
        self._description = description
        self._poll_interval_ms = poll_interval_ms
        self._max_events = max_events
        self._log = log or _Log()
        self._config = None
        self._stream = None
        self._keys: list[dict] = []
        self._keys_at = 0.0
        self._timer: threading.Timer | None = None
        self._running = False
        self._ack: list[str] = []
        self._errs: dict = {}
        self._handlers: dict[str, list] = {}
        self._poll_lock = threading.Lock()
        self._inflight = None
        self._thread: threading.Thread | None = None

    @property
    def stream(self):
        return self._stream

    def track(self, local_id: str, login, expires_at=None) -> None:
        self._index.add(tracked_from(local_id, login, self._subject_attribute, expires_at))

    def untrack(self, local_id: str) -> None:
        self._index.remove(local_id)

    def on(self, event_type: str, handler):
        self._handlers.setdefault(event_type, []).append(handler)
        return self

    def _call(self, method: str, url: str, body=None) -> dict:
        headers = {"accept": "application/json"}
        if self._headers:
            headers.update(self._headers() or {})
        if body is not None:
            headers["content-type"] = "application/json"
        answer = send(url, {"method": method, "headers": headers, **({"body": json.dumps(body)} if body is not None else {})}, self._tls, "ssf")
        parsed = None
        if answer["body"]:
            try:
                parsed = json.loads(answer["body"])
            except json.JSONDecodeError:
                parsed = answer["body"]
        return {"status": answer["status"], "json": parsed}

    def _discover(self) -> dict:
        url = f"{self.transmitter}/.well-known/ssf-configuration"
        response = self._call("GET", url)
        config = response["json"]
        if response["status"] != 200 or not isinstance(config, dict) or not config.get("configuration_endpoint") or not config.get("jwks_uri"):
            raise WsFedError("ssf", f"{url} answered {response['status']} without a usable transmitter configuration")
        supported = config.get("delivery_methods_supported")
        if supported and POLL_METHOD not in supported:
            raise WsFedError("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
        return config

    def _jwks(self, force: bool = False) -> list[dict]:
        import time

        if not force and self._keys and time.time() - self._keys_at < 3600:
            return self._keys
        response = self._call("GET", self._config["jwks_uri"])
        keys = response["json"].get("keys") if isinstance(response["json"], dict) else None
        if response["status"] != 200 or not isinstance(keys, list):
            raise WsFedError("ssf", f"the transmitter's JWKS answered {response['status']}")
        self._keys = keys
        self._keys_at = time.time()
        return keys

    def _ensure_stream(self) -> dict:
        endpoint = self._config["configuration_endpoint"]
        listed = self._call("GET", endpoint)
        if listed["status"] == 200:
            raw = listed["json"]
            all_streams = raw if isinstance(raw, list) else ([raw] if raw else [])
            mine = next((item for item in all_streams if isinstance(item, dict) and item.get("delivery", {}).get("method") == POLL_METHOD and item.get("stream_id")), None)
            if mine:
                return mine
        elif listed["status"] != 404:
            raise WsFedError("ssf", f"listing the streams at {endpoint} answered {listed['status']}: {json.dumps(listed['json'])[:300]}")
        body = {"delivery": {"method": POLL_METHOD}, "events_requested": self._events_requested}
        if self._description:
            body["description"] = self._description
        created = self._call("POST", endpoint, body)
        stream = created["json"] if isinstance(created["json"], dict) else {}
        if created["status"] not in (200, 201) or not stream.get("stream_id"):
            raise WsFedError("ssf", f"creating a stream at {endpoint} answered {created['status']}: {json.dumps(created['json'])[:300]}")
        return stream

    def start(self) -> None:
        if self._running:
            return
        self._config = self._discover()
        self._jwks(True)
        self._stream = self._ensure_stream()
        if not (self._stream.get("delivery") or {}).get("endpoint_url"):
            raise WsFedError("ssf", "the stream has no poll endpoint_url")
        self._running = True
        delivered = self._stream.get("events_delivered") or []
        self._log.info(f"ssf: polling stream {self._stream.get('stream_id')} at {self._stream['delivery']['endpoint_url']}, delivering {len(delivered)} event type(s)")
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=20)
            self._thread = None

    def _loop(self) -> None:
        if not self._running:
            return
        delay = self._poll_interval_ms
        try:
            more = self.poll_once()
            if more:
                delay = 0
        except Exception as err:
            self._log.warn(f"ssf: poll failed: {err}")
            delay = min(self._poll_interval_ms * 4, 60_000)
        if self._running:
            self._timer = threading.Timer(delay / 1000, self._loop)
            self._timer.daemon = True
            self._timer.start()

    def poll_once(self) -> bool:
        with self._poll_lock:
            if self._inflight is None:
                flight = {"event": threading.Event(), "result": None, "error": None}
                self._inflight = flight
                owner = True
            else:
                flight = self._inflight
                owner = False
        if not owner:
            flight["event"].wait()
            if flight["error"] is not None:
                raise flight["error"]
            return flight["result"]
        try:
            flight["result"] = self._poll_now()
            return flight["result"]
        except Exception as err:
            flight["error"] = err
            raise
        finally:
            with self._poll_lock:
                if self._inflight is flight:
                    self._inflight = None
            flight["event"].set()

    def _poll_now(self) -> bool:
        url = self._stream["delivery"]["endpoint_url"]
        ack = self._ack
        self._ack = []
        set_errs = self._errs
        self._errs = {}
        body = {"maxEvents": self._max_events, "returnImmediately": True}
        if ack:
            body["ack"] = ack
        if set_errs:
            body["setErrs"] = set_errs
        response = self._call("POST", url, body)
        if response["status"] != 200:
            self._ack = ack + self._ack
            self._errs = {**set_errs, **self._errs}
            raise WsFedError("ssf", f"the poll answered {response['status']}: {json.dumps(response['json'])[:300]}")
        payload = response["json"] if isinstance(response["json"], dict) else {}
        for jti, token in (payload.get("sets") or {}).items():
            try:
                self._handle(jti, token)
                self._ack.append(jti)
            except Exception as err:
                description = str(err)
                self._log.warn(f"ssf: SET {jti} refused: {description}")
                code = "invalid_key" if isinstance(err, WsFedError) and err.code == "signature" else "invalid_request"
                self._errs[jti] = {"err": code, "description": description}
        return bool(payload.get("moreAvailable"))

    def _handle(self, jti: str, token: str) -> None:
        try:
            verified = verify_compact_jws(token, self._jwks())
        except WsFedError as err:
            if not ("publishes no" in str(err) or "does not verify" in str(err)):
                raise
            verified = verify_compact_jws(token, self._jwks(True))
        header, payload = verified["header"], verified["payload"]
        if header.get("typ") is not None and str(header["typ"]).lower() != "secevent+jwt":
            raise WsFedError("validation", f"the SET's typ is {header.get('typ')}")
        if payload.get("iss") != self._config["issuer"]:
            raise WsFedError("validation", f"the SET was issued by {payload.get('iss')}, not {self._config['issuer']}")
        want = self._stream.get("aud")
        want_list = want if isinstance(want, list) else ([want] if want else [])
        aud = payload.get("aud")
        aud_list = [str(item) for item in (aud if isinstance(aud, list) else ([aud] if aud is not None else []))]
        if want_list and not any(item in want_list for item in aud_list):
            raise WsFedError("validation", f"the SET is for {', '.join(aud_list)}, not this stream")
        if payload.get("jti") is not None and payload.get("jti") != jti:
            raise WsFedError("validation", "the SET's jti is not the one it was delivered under")
        events = payload.get("events")
        if not isinstance(events, dict) or not events:
            raise WsFedError("validation", "the SET carries no events")
        for event_type, body in events.items():
            subject = subject_of(payload.get("sub_id") if payload.get("sub_id") is not None else (body or {}).get("subject") if isinstance(body, dict) else None, self._config["issuer"])
            sessions = self._sessions_for(event_type, subject)
            ends = event_type in self._end_on and len(sessions) > 0
            event = SignalEvent(
                type=event_type,
                payload=body or {},
                subject=subject,
                jti=jti,
                sessions=sessions,
                ended=ends,
                iat=payload.get("iat") if isinstance(payload.get("iat"), (int, float)) and not isinstance(payload.get("iat"), bool) else None,
                txn=payload.get("txn") if isinstance(payload.get("txn"), str) else None,
            )
            if ends:
                try:
                    self._on_end(sessions, event)
                except Exception as err:
                    self._log.error(f"ssf: onEndSessions threw for {event_type} (SET {jti} is still acknowledged): {err}")
                    event.ended = False
                if event.ended:
                    for local_id in sessions:
                        self._index.remove(local_id)
            for handler in [*(self._handlers.get(event_type) or []), *(self._handlers.get("*") or [])]:
                try:
                    handler(event)
                except Exception as err:
                    self._log.error(f"ssf: a handler for {event_type} threw (SET {jti} is still acknowledged): {err}")

    def _sessions_for(self, event_type: str, subject: dict) -> list[str]:
        if event_type in (EVENT["verification"], EVENT["stream_updated"]):
            return []
        if subject.get("idp_session"):
            found = self._index.by_idp_session(subject["idp_session"])
            if found or event_type == EVENT["session_revoked"]:
                return found
        if subject.get("person"):
            return self._index.by_person(subject["person"])
        if subject.get("email"):
            return self._index.by_email(subject["email"])
        return []

    def verify(self, state: str | None = None) -> None:
        endpoint = (self._config or {}).get("verification_endpoint") if self._config else None
        if not isinstance(endpoint, str):
            raise WsFedError("ssf", "the transmitter publishes no verification_endpoint")
        body = {"stream_id": self._stream["stream_id"]}
        if state:
            body["state"] = state
        response = self._call("POST", endpoint, body)
        if response["status"] not in (200, 204):
            raise WsFedError("ssf", f"verification answered {response['status']}")
