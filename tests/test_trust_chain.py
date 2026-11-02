# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""idpCa (demo/wsfed.json): the install script writes the whole listener CA trust chain to the file
the parameter names, every run, and the library takes that file as its trust store.

The stub identity provider is HTTPS on a four-certificate chain shaped like iya-sts's (leaf, TLS
Issuing CA, Intermediate, Root; the leaf's only name is the IP address 127.0.0.1) and publishes it,
leaf first, at GET /tls/server-certificate. A second server presents a forged leaf for the same
address followed by the real Issuing CA and Intermediate: the library must refuse it, because only
a path that verifies to an anchor is accepted, never a match of any presented certificate.
"""

import contextlib
import datetime
import ipaddress
import json
import os
import ssl
import stat
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import configure_iya_sts  # noqa: E402
import trust_chain  # noqa: E402
from stub_idp import IDP_ENTITY, RP_CERT, RP_KEY, idp_metadata  # noqa: E402
from wsfed_caep import RelyingParty  # noqa: E402
from wsfed_caep.config import resolve_config  # noqa: E402
from wsfed_caep.errors import WsFedError  # noqa: E402
from wsfed_caep.http_client import send  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_CONFIG = ROOT / "demo" / "wsfed.json"
DEFAULT_IDP_CA = "generated/idp-ca.pem"
CERT_RE = trust_chain.CERT_RE


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _cert(subject, key, issuer, issuer_key, ca, leaf_ip=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    if leaf_ip:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(leaf_ip))]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(Encoding.PEM).decode()


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # A refused handshake (the forged and wrong-name tests) is the expected outcome.
        pass


@contextlib.contextmanager
def _https(presented, key, handler):
    """An HTTPS server on 127.0.0.1 presenting the given chain (leaf first)."""
    with tempfile.TemporaryDirectory(prefix="trust-chain-server-") as directory:
        chain_file = Path(directory, "server.pem")
        key_file = Path(directory, "server.key")
        chain_file.write_text("".join(_pem(cert) for cert in presented), encoding="utf-8")
        key_file.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(chain_file), str(key_file))
        server = _QuietServer(("127.0.0.1", 0), handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            server.server_close()


@pytest.fixture(scope="module")
def provider():
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(5)]
    root = _cert("sts Root CA", keys[0], "sts Root CA", keys[0], True)
    intermediate = _cert("sts Intermediate CA", keys[1], "sts Root CA", keys[0], True)
    issuing = _cert("sts TLS Issuing CA", keys[2], "sts Intermediate CA", keys[1], True)
    leaf = _cert("127.0.0.1", keys[3], "sts TLS Issuing CA", keys[2], False, leaf_ip="127.0.0.1")
    # Same names as the real leaf, signed by a key that is not the Issuing CA's.
    forged = _cert("127.0.0.1", keys[4], "sts TLS Issuing CA", keys[4], False, leaf_ip="127.0.0.1")
    published = "".join(_pem(cert) for cert in (leaf, issuing, intermediate, root))
    metadata = idp_metadata()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/tls/server-certificate":
                body, kind = published.encode(), "text/plain"
            elif self.path == "/FederationMetadata/2007-06/FederationMetadata.xml":
                body, kind = metadata.encode(), "application/samlmetadata+xml"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("content-type", kind)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            # The token endpoint refuses, so the install script stops right after the chain.
            self.rfile.read(int(self.headers.get("content-length") or 0))
            body = b'{"error":"invalid_client"}'
            self.send_response(401)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with _https((leaf, issuing, intermediate), keys[3], Handler) as port, \
            _https((forged, issuing, intermediate), keys[4], Handler) as forged_port:
        yield {
            "origin": f"https://127.0.0.1:{port}",
            "port": port,
            "forged_origin": f"https://127.0.0.1:{forged_port}",
            "published": published,
            "root": root,
        }


def _demo_dir(directory, origin):
    """A demo directory whose wsfed.json is the shipped one, its transmitter pointed at the stub."""
    demo = Path(directory, "demo")
    demo.mkdir()
    raw = json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    raw["ssf"]["transmitter"] = origin
    (demo / "wsfed.json").write_text(json.dumps(raw), encoding="utf-8")
    generated = demo / "generated"
    generated.mkdir()
    (generated / "rp.key").write_text(RP_KEY, encoding="utf-8")
    (generated / "rp.crt").write_text(RP_CERT, encoding="utf-8")
    return demo


def _blocks(text):
    return [block.strip() for block in CERT_RE.findall(text)]


def _fingerprint(cert):
    return ":".join(f"{byte:02X}" for byte in cert.fingerprint(hashes.SHA256()))


def _metadata_url(origin):
    return origin + "/FederationMetadata/2007-06/FederationMetadata.xml"


def test_the_shipped_demo_names_generated_idp_ca_pem():
    assert json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))["idpCa"] == "file:" + DEFAULT_IDP_CA


def test_save_trust_chain_writes_the_whole_chain_to_idp_ca(provider):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        target = demo / DEFAULT_IDP_CA
        files = configure_iya_sts.files_of(str(demo / "wsfed.json"))
        assert Path(files["idp_ca"]).resolve() == target.resolve()
        saved = trust_chain.save_trust_chain(provider["origin"], files["idp_ca"])
        written = target.read_text(encoding="utf-8")
        assert _blocks(written) == _blocks(provider["published"])
        assert len(_blocks(written)) == 4
        assert saved["count"] == 4
        assert saved["anchor_subject"] == "CN=sts Root CA"
        assert saved["anchor_fingerprint"] == _fingerprint(provider["root"])


def test_the_handshake_chain_is_the_fallback(provider):
    # Without the published document, the chain the listener presents (leaf, Issuing, Intermediate).
    chain = trust_chain.fetch_handshake(provider["origin"])
    assert chain["count"] == 3
    assert _blocks(chain["pem"]) == _blocks(provider["published"])[:3]


def test_the_install_script_rewrites_idp_ca_with_the_chain_every_run(provider, monkeypatch, capsys):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        target = demo / DEFAULT_IDP_CA
        # A file from an earlier iya-sts: the script replaces it rather than keeping it.
        target.write_text(RP_CERT, encoding="utf-8")
        monkeypatch.setenv("ADMIN_API_CLIENT_SECRET", "unit-test-secret")
        monkeypatch.setenv("PORT", "3000")
        with pytest.raises(RuntimeError, match="401"):
            configure_iya_sts.main([
                "--config", str(demo / "wsfed.json"), "--idp", provider["origin"], "--no-test-user",
            ])
        assert _blocks(target.read_text(encoding="utf-8")) == _blocks(provider["published"])
        printed = capsys.readouterr().out
        assert f"(4 certificate(s)) to {target.resolve()}" in printed
        assert "trust anchor CN=sts Root CA" in printed
        assert f"sha256 {_fingerprint(provider['root'])}" in printed


def test_the_refresh_entry_point_writes_idp_ca_and_names_the_anchor(provider, capsys):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        assert trust_chain.main(["--config", str(demo / "wsfed.json"), "--idp", provider["origin"]]) == 0
        assert _blocks((demo / DEFAULT_IDP_CA).read_text(encoding="utf-8")) == _blocks(provider["published"])
        printed = capsys.readouterr().out
        assert "(4 certificate(s))" in printed
        assert "CN=sts Root CA" in printed
        assert "sha256 " in printed


def test_the_library_trusts_the_identity_provider_through_the_saved_file(provider):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        url = _metadata_url(provider["origin"])
        with pytest.raises(WsFedError):
            send(url, None, None, "metadata")
        trust_chain.save_trust_chain(provider["origin"], str(demo / DEFAULT_IDP_CA))
        raw = json.loads((demo / "wsfed.json").read_text(encoding="utf-8"))
        raw["idpMetadata"] = url
        config = resolve_config(raw, str(demo))
        assert _blocks(config.idp_ca) == _blocks(provider["published"])
        party = RelyingParty(config)
        party.refresh_metadata()
        assert party.idp.entity_id == IDP_ENTITY


def test_the_root_alone_is_enough_to_trust_the_listener(provider):
    # Every block is an anchor, and the path ends at the self-signed Root: the Root alone verifies too.
    answer = send(_metadata_url(provider["origin"]), None, {"ca": _pem(provider["root"])}, "metadata")
    assert answer["status"] == 200


def test_a_forged_leaf_followed_by_the_real_cas_is_refused(provider):
    # The forged server presents the real Issuing CA and Intermediate after its own leaf. A file
    # certificate matching some presented certificate is not trust: the leaf must verify.
    with pytest.raises(WsFedError, match="CERTIFICATE_VERIFY_FAILED"):
        send(_metadata_url(provider["forged_origin"]), None, {"ca": provider["published"]}, "metadata")


def test_the_host_name_is_verified_against_the_leaf(provider):
    # The leaf names only IP 127.0.0.1. The right chain under another name is refused.
    with pytest.raises(WsFedError, match="CERTIFICATE_VERIFY_FAILED"):
        send(f"https://localhost:{provider['port']}/FederationMetadata/2007-06/FederationMetadata.xml",
             None, {"ca": provider["published"]}, "metadata")
    assert send(_metadata_url(provider["origin"]), None, {"ca": provider["published"]}, "metadata")["status"] == 200


def test_a_generated_password_goes_to_an_owner_only_file_and_is_never_printed(monkeypatch, capsys):
    secret = "generated-password-value"
    monkeypatch.delenv("WSFED_DEMO_USER_PASSWORD", raising=False)
    monkeypatch.setattr(configure_iya_sts, "_json", lambda *_a, **_k: {"status": 200, "body": {"known": False}})

    def api(path, body):
        assert path == "/users/create" and body["credential"] == "generate"
        return {"status": 200, "body": {"ok": True, "password": secret}}

    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        generated = Path(directory, "generated")
        configure_iya_sts._ensure_user("https://127.0.0.1:1", None, "token", "demo-user", api, generated)
        saved = generated / "demo-user.password"
        assert saved.read_text(encoding="utf-8") == secret + "\n"
        assert stat.S_IMODE(os.stat(saved).st_mode) == 0o600
    assert secret not in capsys.readouterr().out
