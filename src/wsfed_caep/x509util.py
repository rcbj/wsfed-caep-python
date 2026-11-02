# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A self-signed certificate for the relying party's key. WS-Federation uses it as a public-key container."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = []
    value = n
    while value > 0:
        raw.append(value & 0xFF)
        value >>= 8
    raw.reverse()
    return bytes([0x80 | len(raw), *raw])


def _tlv(tag: int, *content: bytes) -> bytes:
    body = b"".join(content)
    return bytes([tag]) + _length(len(body)) + body


def _seq(*content: bytes) -> bytes:
    return _tlv(0x30, *content)


def _set(*content: bytes) -> bytes:
    return _tlv(0x31, *content)


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = [parts[0] * 40 + parts[1]]
    for number in parts[2:]:
        chunk = [number & 0x7F]
        value = number >> 7
        while value > 0:
            chunk.append((value & 0x7F) | 0x80)
            value >>= 7
        chunk.reverse()
        out.extend(chunk)
    return _tlv(0x06, bytes(out))


def _time(moment: datetime) -> bytes:
    moment = moment.astimezone(timezone.utc)
    iso = moment.strftime("%Y%m%d%H%M%S") + "Z"
    if moment.year < 2050:
        return _tlv(0x17, iso[2:].encode("ascii"))
    return _tlv(0x18, iso.encode("ascii"))


def _header(spki: bytes, at: int) -> tuple[int, int]:
    first = spki[at + 1]
    if first < 0x80:
        return at + 2, at + 2 + first
    count = first & 0x7F
    length = 0
    for i in range(count):
        length = length * 256 + spki[at + 2 + i]
    return at + 2 + count, at + 2 + count + length


def _subject_public_key_bits(spki: bytes) -> bytes:
    body, end = _header(spki, 0)
    _alg_body, alg_end = _header(spki, body)
    bits_body, bits_end = _header(spki, alg_end)
    return spki[bits_body + 1 : bits_end]


def _name(common_name: str) -> bytes:
    return _seq(_set(_seq(_oid("2.5.4.3"), _tlv(0x0C, common_name.encode("utf-8")))))


_SHA256_RSA = _seq(_oid("1.2.840.113549.1.1.11"), bytes([0x05, 0x00]))


@dataclass
class KeyPair:
    private_key_pem: str
    certificate_pem: str
    certificate: x509.Certificate


def create_self_signed_key_pair(common_name: str, days: int = 1095, bits: int = 3072) -> KeyPair:
    """RSA key and a self-signed certificate: digitalSignature and keyEncipherment, not a CA."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    serial = bytearray(os.urandom(16))
    serial[0] &= 0x7F
    if serial[0] == 0:
        serial[0] = 1
    not_before = datetime.now(timezone.utc) - timedelta(seconds=60)
    not_after = not_before + timedelta(days=days)
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha1(_subject_public_key_bits(spki)).digest()
    extensions = _tlv(
        0xA3,
        _seq(
            _seq(_oid("2.5.29.14"), _tlv(0x04, _tlv(0x04, key_id))),
            _seq(_oid("2.5.29.35"), _tlv(0x04, _seq(_tlv(0x80, key_id)))),
            _seq(_oid("2.5.29.19"), _tlv(0x01, bytes([0xFF])), _tlv(0x04, _seq())),
            _seq(_oid("2.5.29.15"), _tlv(0x01, bytes([0xFF])), _tlv(0x04, _tlv(0x03, bytes([0x05, 0xA0])))),
        ),
    )
    tbs = _seq(
        _tlv(0xA0, _tlv(0x02, bytes([0x02]))),
        _tlv(0x02, bytes(serial)),
        _SHA256_RSA,
        _name(common_name),
        _seq(_time(not_before), _time(not_after)),
        _name(common_name),
        spki,
        extensions,
    )
    signature = private_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    der = _seq(tbs, _SHA256_RSA, _tlv(0x03, bytes([0]) + signature))
    b64 = _b64_lines(der)
    certificate_pem = f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n"
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return KeyPair(private_pem, certificate_pem, certificate)


def _b64_lines(data: bytes) -> str:
    import base64

    raw = base64.b64encode(data).decode("ascii")
    return "\n".join(raw[i : i + 64] for i in range(0, len(raw), 64))
