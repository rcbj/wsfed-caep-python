# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The self-signed certificate generate-keys makes, and its command-line subject."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from wsfed_caep import create_self_signed_key_pair
from wsfed_caep.cli import main

_SKI = bytes([0x06, 0x03, 0x55, 0x1D, 0x0E])
_AKI = bytes([0x06, 0x03, 0x55, 0x1D, 0x23])


def _key_id_after(cert: bytes, oid: bytes) -> bytes:
    at = cert.index(oid)
    assert at > 0
    rest = cert[at + len(oid) :]
    marker = rest.index(bytes([0x14]))
    start = at + len(oid) + marker + 1
    return cert[start : start + 20]


def test_signs_itself_and_names_its_key():
    pair = create_self_signed_key_pair("rp", bits=2048)
    pair.certificate.public_key().verify(
        pair.certificate.signature,
        pair.certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        pair.certificate.signature_hash_algorithm,
    )
    spki = pair.certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    want = hashlib.sha1(spki).digest()
    der = pair.certificate.public_bytes(serialization.Encoding.DER)
    assert _key_id_after(der, _SKI) == want
    assert _key_id_after(der, _AKI) == want


def test_two_certificates_of_one_name_have_different_key_identifiers():
    one = create_self_signed_key_pair("localhost:3000", bits=2048)
    two = create_self_signed_key_pair("localhost:3000", bits=2048)
    assert one.certificate.subject.rfc4514_string() == two.certificate.subject.rfc4514_string()
    der_a = one.certificate.public_bytes(serialization.Encoding.DER)
    der_b = two.certificate.public_bytes(serialization.Encoding.DER)
    assert _key_id_after(der_a, _SKI) != _key_id_after(der_b, _SKI)


def test_generate_keys_names_the_certificate_after_the_realm(tmp_path: Path):
    config = tmp_path / "wsfed.json"
    config.write_text(json.dumps({
        "realm": "http://localhost:3000/",
        "replyUrl": "http://localhost:3000/wsfed",
        "idpMetadata": "x",
        "privateKey": "k.pem",
        "certificate": "c.pem",
    }), encoding="utf-8")
    main(["generate-keys", "--config", str(config), "--bits", "2048"], out=lambda _text: None)
    from cryptography import x509

    cert = x509.load_pem_x509_certificate((tmp_path / "c.pem").read_bytes())
    assert cert.subject.rfc4514_string() == "CN=wsfed-caep-nodejs relying party http://localhost:3000/"
