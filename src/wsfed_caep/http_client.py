# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Back channel: identity-provider metadata and the Shared Signals transmitter. TLS is verified.
Plain http is refused unless the host is loopback. http.client follows no redirect."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import tempfile
import urllib.parse
from pathlib import Path

from wsfed_caep.errors import WsFedError

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15


def is_loopback_host(host: str) -> bool:
    """A loopback host: 127.0.0.0/8, ::1 or the name localhost. ``host`` is a urlsplit hostname."""
    host = host.lower()
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version == 4:
        return address in ipaddress.ip_network("127.0.0.0/8")
    return address == ipaddress.IPv6Address("::1")


def _unsafe(url: str) -> bool:
    """Whitespace or a control character anywhere: urlsplit drops some of them silently, and another
    parser may read a different host from the same string, so such a URL is refused outright."""
    return any(ord(c) <= 0x20 or ord(c) == 0x7F or c.isspace() for c in url)


def plain_http_refusal(parsed: urllib.parse.SplitResult, code: str) -> WsFedError | None:
    """The refusal of a plain http URL, unless it names a loopback host, where the bytes never leave
    the machine. Userinfo is never loopback, so ``http://localhost:80@host/`` cannot pass as
    localhost. The message names the scheme and host[:port] only: never userinfo, path or query."""
    userinfo, at, shown = parsed.netloc.rpartition("@")
    if not at and is_loopback_host(parsed.hostname or ""):
        return None
    return WsFedError(code, f"http://{shown} is refused: plain http is allowed only to a loopback host "
                      "(127.0.0.0/8, ::1, localhost); use https")


def send(url: str, init: dict | None, tls: dict | None, code: str) -> dict:
    init = init or {}
    tls = tls or {}
    if _unsafe(url):
        raise WsFedError(code, "the URL is refused: it contains whitespace or a control character")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("https", "http"):
        raise WsFedError(code, f"{parsed.scheme or 'a schemeless'} URL is not http(s)")
    # Every fetch this library makes goes through here: the identity provider's federation metadata
    # (its signing keys) and the Shared Signals transmitter (configuration, JWKS, stream and poll:
    # SETs and the bearer token). None of them may travel in the clear off this machine, so plain
    # http is refused before any lookup or connection unless the host is loopback.
    if parsed.scheme == "http":
        refusal = plain_http_refusal(parsed, code)
        if refusal is not None:
            raise refusal
    payload = None if init.get("body") is None else str(init["body"]).encode("utf-8")
    headers = {str(k): str(v) for k, v in (init.get("headers") or {}).items()}
    if payload is not None:
        headers.setdefault("Content-Length", str(len(payload)))
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    context = None
    cert_path = key_path = None
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            if tls.get("ca"):
                context.load_verify_locations(cadata=tls["ca"])
            if tls.get("cert") and tls.get("key"):
                cert_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
                key_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
                cert_file.write(tls["cert"])
                key_file.write(tls["key"])
                cert_file.close()
                key_file.close()
                cert_path, key_path = cert_file.name, key_file.name
                context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(parsed.hostname, port, timeout=TIMEOUT_S, context=context)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=TIMEOUT_S)
        try:
            conn.request(init.get("method") or "GET", path, body=payload, headers=headers)
            response = conn.getresponse()
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    raise WsFedError(code, f"{url} answered more than {MAX_BYTES} bytes")
                chunks.append(chunk)
            ctype = response.getheader("content-type") or ""
            return {"status": response.status, "content_type": ctype, "body": b"".join(chunks).decode("utf-8", "replace")}
        finally:
            conn.close()
    except WsFedError:
        raise
    except (socket.timeout, TimeoutError) as err:
        raise WsFedError(code, f"{url} did not answer within {TIMEOUT_S} s", err) from err
    except Exception as err:
        reason = getattr(err, "reason", None)
        if isinstance(reason, (socket.timeout, TimeoutError)):
            raise WsFedError(code, f"{url} did not answer within {TIMEOUT_S} s", err) from err
        raise WsFedError(code, f"{url}: {err}", err) from err
    finally:
        for name in (cert_path, key_path):
            if name:
                Path(name).unlink(missing_ok=True)
