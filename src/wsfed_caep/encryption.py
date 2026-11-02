# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Decrypt an EncryptedAssertion or EncryptedID. RSA-OAEP wraps the content key; AES-GCM or AES-CBC holds the XML.
RSA PKCS#1 v1.5 is refused. An OAEP digest that differs from its MGF1 hash is refused."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from lxml import etree

from wsfed_caep.errors import WsFedError
from wsfed_caep.xmlutil import NS, attr, child, descendants, is_el, text

CIPHERS = {
    "http://www.w3.org/2009/xmlenc11#aes128-gcm": {"name": "aes-128-gcm", "gcm": True, "key_length": 16},
    "http://www.w3.org/2009/xmlenc11#aes192-gcm": {"name": "aes-192-gcm", "gcm": True, "key_length": 24},
    "http://www.w3.org/2009/xmlenc11#aes256-gcm": {"name": "aes-256-gcm", "gcm": True, "key_length": 32},
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc": {"name": "aes-128-cbc", "gcm": False, "key_length": 16},
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc": {"name": "aes-192-cbc", "gcm": False, "key_length": 24},
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc": {"name": "aes-256-cbc", "gcm": False, "key_length": 32},
}
OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
DIGESTS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": hashes.SHA1,
    "http://www.w3.org/2001/04/xmlenc#sha256": hashes.SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": hashes.SHA384,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashes.SHA512,
}
DIGEST_NAMES = {
    "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}
MGFS = {
    "http://www.w3.org/2009/xmlenc11#mgf1sha1": "sha1",
    "http://www.w3.org/2009/xmlenc11#mgf1sha256": "sha256",
    "http://www.w3.org/2009/xmlenc11#mgf1sha384": "sha384",
    "http://www.w3.org/2009/xmlenc11#mgf1sha512": "sha512",
}


def _fail(message: str, cause: BaseException | None = None) -> None:
    raise WsFedError("decryption", message, cause)


def _b64(value: str) -> bytes:
    return base64.b64decode("".join(value.split()))


def _unwrap_key(encrypted_key: etree._Element, key: RSAPrivateKey) -> bytes:
    method = child(encrypted_key, NS["xenc"], "EncryptionMethod")
    alg = attr(method, "Algorithm") if method is not None else ""
    alg = alg or ""
    if alg not in (OAEP_MGF1P, OAEP):
        _fail(f"the content key is wrapped with {alg or '(none)'}; only RSA-OAEP is accepted")
    digest_method = child(method, NS["ds"], "DigestMethod") if method is not None else None
    digest_alg = attr(digest_method, "Algorithm") if digest_method is not None else None
    digest_name = DIGEST_NAMES.get(digest_alg, "sha1") if digest_alg else "sha1"
    if digest_alg and digest_alg not in DIGESTS:
        _fail(f"the OAEP digest {digest_alg} is not supported")
    mgf = "sha1"
    if alg == OAEP and method is not None:
        mgf_el = child(method, NS["xenc11"], "MGF")
        mgf_alg = attr(mgf_el, "Algorithm") if mgf_el is not None else None
        if mgf_alg:
            if mgf_alg not in MGFS:
                _fail(f"the OAEP mask generation function {mgf_alg} is not supported")
            mgf = MGFS[mgf_alg]
    if mgf != digest_name:
        _fail(f"OAEP with digest {digest_name} and MGF1 {mgf} is not supported; node:crypto uses one hash for both")
    cipher_value = descendants(encrypted_key, NS["xenc"], "CipherValue")
    hash_new = DIGESTS[digest_alg] if digest_alg else hashes.SHA1
    try:
        return key.decrypt(
            _b64(text(cipher_value[0]) if cipher_value else ""),
            padding.OAEP(mgf=padding.MGF1(algorithm=hash_new()), algorithm=hash_new(), label=None),
        )
    except WsFedError:
        raise
    except Exception as err:
        _fail("the content key could not be unwrapped with this relying party's key", err)
    raise AssertionError("unreachable")


def decrypt_element(encrypted: etree._Element, key: RSAPrivateKey) -> str:
    data = encrypted if is_el(encrypted, NS["xenc"], "EncryptedData") else child(encrypted, NS["xenc"], "EncryptedData")
    if data is None:
        _fail(f"<{etree.QName(encrypted).localname}> has no EncryptedData")
    method = child(data, NS["xenc"], "EncryptionMethod")
    alg = attr(method, "Algorithm") if method is not None else None
    cipher = CIPHERS.get(alg or "")
    if not cipher:
        _fail(f"the content is encrypted with {alg or '(none)'}, which is not supported")
    keys = descendants(encrypted, NS["xenc"], "EncryptedKey")
    if not keys:
        _fail(f"<{etree.QName(encrypted).localname}> carries no EncryptedKey")
    content_key = _unwrap_key(keys[0], key)
    if len(content_key) != cipher["key_length"]:
        _fail(f"the content key is {len(content_key)} bytes; {cipher['name']} needs {cipher['key_length']}")
    cipher_data = child(data, NS["xenc"], "CipherData")
    value_el = child(cipher_data, NS["xenc"], "CipherValue") if cipher_data is not None else None
    raw = _b64(text(value_el))
    try:
        if cipher["gcm"]:
            if len(raw) < 12 + 16:
                _fail("the ciphertext is too short")
            return AESGCM(content_key).decrypt(raw[:12], raw[12:], None).decode("utf-8")
        if len(raw) < 32 or len(raw) % 16:
            _fail("the ciphertext is not a whole number of blocks")
        decryptor = Cipher(algorithms.AES(content_key), modes.CBC(raw[:16])).decryptor()
        plain = decryptor.update(raw[16:]) + decryptor.finalize()
        pad = plain[-1]
        if pad < 1 or pad > 16:
            _fail("the decrypted content is not padded as XML Encryption pads it")
        return plain[:-pad].decode("utf-8")
    except WsFedError:
        raise
    except Exception as err:
        _fail("the content could not be decrypted", err)
    raise AssertionError("unreachable")
