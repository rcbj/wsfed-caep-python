# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Fetch iya-sts's listener CA trust chain and write the file idpCa names.

The chain is every certificate iya-sts publishes at GET /tls/server-certificate: the listener's
leaf, the TLS Issuing CA, the Intermediate and the Root. The whole chain is written, and the library
(wsfed_caep.http_client) loads every PEM block in it as a trust anchor (ssl load_verify_locations)
and still checks the host name against the leaf, so OpenSSL ends the path at the self-signed Root.
GET /tls/server-certificate is tried first, with verification off: nothing is trusted from that
connection, the file is trust on first use and the install script prints the anchor to compare. If
that document is missing, the handshake's own chain is used. scripts/configure_iya_sts.py calls
save_trust_chain() on every run; run as a program, a failure leaves the file as it is and exits 0.

    python scripts/trust_chain.py --config demo/wsfed.json --idp https://localhost:8081
"""

import http.client
import json
import os
import re
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

TIMEOUT_S = 10
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


def trust_path(raw, base_dir):
    """A path or file: path. PEM and env: are the configuration's own value, and are not a file to write."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value or "-----BEGIN" in value or value.startswith("env:"):
        return None
    path = value[5:] if value.startswith("file:") else value
    if not path:
        return None
    return path if os.path.isabs(path) else str(Path(base_dir) / path)


def _certs(text):
    return CERT_RE.findall(str(text or ""))


def _unverified_context():
    """Verification off, for fetching the chain to save. TLS 1.2 at the least."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _load(pem):
    from cryptography import x509
    return x509.load_pem_x509_certificate(pem.encode())


def _fingerprint(cert):
    from cryptography.hazmat.primitives import hashes
    return ":".join(f"{byte:02X}" for byte in cert.fingerprint(hashes.SHA256()))


def bundle_of(blocks):
    """The PEM to write, and the trust anchor: the self-signed certificate, else the last one."""
    if not blocks:
        raise RuntimeError("the trust chain has no certificates")
    certs = [_load(block) for block in blocks]
    anchor = next((cert for cert in reversed(certs) if cert.subject == cert.issuer), certs[-1])
    return {
        "pem": "\n".join(block.strip() for block in blocks) + "\n",
        "anchor_subject": anchor.subject.rfc4514_string(),
        "anchor_fingerprint": _fingerprint(anchor),
        "count": len(blocks),
    }


def _servername(hostname):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, hostname.strip("[]"))
            return None
        except OSError:
            continue
    return hostname


def _host_port(origin):
    parts = urlsplit(origin if "://" in origin else f"https://{origin}")
    return parts.hostname or "", parts.port or 443


def fetch_published(origin):
    host, port = _host_port(origin)
    conn = http.client.HTTPSConnection(host, port, context=_unverified_context(), timeout=TIMEOUT_S)
    try:
        conn.request("GET", "/tls/server-certificate", headers={"accept": "text/plain"})
        response = conn.getresponse()
        raw = response.read()
    finally:
        conn.close()
    if response.status != 200:
        raise RuntimeError(f"GET /tls/server-certificate answered {response.status}")
    return bundle_of(_certs(raw.decode("utf-8", "replace")))


def _pem_of(value):
    """PEM for one handshake certificate: DER bytes, or an ssl.Certificate on newer interpreters."""
    if hasattr(value, "public_bytes"):
        value = value.public_bytes()
    if isinstance(value, str):
        return value.strip()
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    return x509.load_der_x509_certificate(bytes(value)).public_bytes(Encoding.PEM).decode().strip()


def fetch_handshake(origin):
    host, port = _host_port(origin)
    with socket.create_connection((host, port), timeout=TIMEOUT_S) as sock:
        with _unverified_context().wrap_socket(sock, server_hostname=_servername(host)) as tls:
            chain = getattr(tls._sslobj, "get_unverified_chain", lambda: None)()
            presented = list(chain) if chain else [tls.getpeercert(binary_form=True)]
    presented = [item for item in presented if item]
    if not presented:
        raise RuntimeError(f"{origin} presented no certificate")
    return bundle_of([_pem_of(item) for item in presented])


def fetch_trust_chain(origin):
    try:
        return fetch_published(origin)
    except Exception:
        return fetch_handshake(origin)


def save_trust_chain(origin, dest):
    chain = fetch_trust_chain(origin)
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(chain["pem"], encoding="utf-8")
    chain["path"] = str(path)
    chain["origin"] = origin
    return chain


def _args(argv):
    config = os.environ.get("WSFED_CONFIG") or str(Path(__file__).resolve().parents[1] / "demo" / "wsfed.json")
    idp = os.environ.get("IYA_STS_URL") or "https://localhost:8081"
    index = 0
    while index < len(argv):
        if argv[index] in ("--config", "--idp"):
            flag = argv[index]
            index += 1
            if index >= len(argv) or not argv[index]:
                raise RuntimeError(f"{flag} needs a value")
            if flag == "--config":
                config = argv[index]
            else:
                idp = argv[index]
        index += 1
    return str(Path(config).resolve()), idp


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        config_path, idp = _args(argv)
        raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
        dest = trust_path(raw.get("idpCa"), str(Path(config_path).parent))
        if not dest:
            raise RuntimeError(f"{config_path} idpCa is not a file this process can update")
        target = urlsplit(idp)
        saved = save_trust_chain(f"{target.scheme}://{target.netloc}", dest)
        print(f"Saved {saved['origin']}'s listener CA trust chain ({saved['count']} certificate(s)) to {saved['path']}")
        print(f"  trust anchor {saved['anchor_subject']}")
        print(f"  sha256 {saved['anchor_fingerprint']}")
    except Exception as err:
        print(f"idp ca: not updated: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
