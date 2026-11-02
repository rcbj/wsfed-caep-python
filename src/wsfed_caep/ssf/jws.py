# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Verify a Security Event Token (compact JWS) against the transmitter's JWKS. none and HMAC are refused."""

from __future__ import annotations

import base64
import json
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from wsfed_caep.errors import WsFedError

_HASH = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
# hash name or None, kty, pss, p1363
ALGS = {
    "RS256": ("sha256", "RSA", False, False),
    "RS384": ("sha384", "RSA", False, False),
    "RS512": ("sha512", "RSA", False, False),
    "PS256": ("sha256", "RSA", True, False),
    "PS384": ("sha384", "RSA", True, False),
    "PS512": ("sha512", "RSA", True, False),
    "ES256": ("sha256", "EC", False, True),
    "ES384": ("sha384", "EC", False, True),
    "ES512": ("sha512", "EC", False, True),
    "EdDSA": (None, "OKP", False, False),
    "Ed25519": (None, "OKP", False, False),
}
SUPPORTED_JWS_ALGS = list(ALGS)
_CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}


def _b64url(value: str, what: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value or ""):
        raise WsFedError("signature", f"the SET's {what} is not base64url")
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _b64int(value: str) -> int:
    raw = _b64url(value, "key")
    return int.from_bytes(raw, "big")


def _key_for(jwk: dict):
    try:
        if jwk.get("kty") == "RSA":
            return rsa.RSAPublicNumbers(_b64int(jwk["e"]), _b64int(jwk["n"])).public_key()
        if jwk.get("kty") == "EC":
            curve = _CURVES[jwk["crv"]]
            return ec.EllipticCurvePublicNumbers(_b64int(jwk["x"]), _b64int(jwk["y"]), curve).public_key()
        if jwk.get("kty") == "OKP":
            return ed25519.Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"], "key"))
        raise ValueError(f"unsupported kty {jwk.get('kty')}")
    except WsFedError:
        raise
    except Exception as err:
        raise WsFedError("signature", f"the transmitter's key {jwk.get('kid') or ''} cannot be read: {err}", err) from err


def verify_compact_jws(token: str, keys: list[dict]) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise WsFedError("signature", "the SET is not a compact JWS")
    header_b, payload_b, sig_b = parts
    try:
        header = json.loads(_b64url(header_b, "header").decode("utf-8"))
        payload = json.loads(_b64url(payload_b, "payload").decode("utf-8"))
    except WsFedError:
        raise
    except Exception as err:
        raise WsFedError("signature", "the SET's header or payload is not JSON", err) from err
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise WsFedError("signature", "the SET's header or payload is not a JSON object")
    alg = str(header.get("alg") or "")
    spec = ALGS.get(alg)
    if not spec:
        raise WsFedError("signature", f"the SET is signed with {alg or '(no alg)'}, which this receiver does not verify ({', '.join(SUPPORTED_JWS_ALGS)})")
    if "crit" in header:
        raise WsFedError("signature", "the SET's header has a crit member this receiver does not understand")
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    hash_name, kty, pss, p1363 = spec
    candidates = [
        key for key in keys
        if (kid is None or key.get("kid") == kid) and key.get("kty") == kty and (not key.get("use") or key.get("use") == "sig") and (not key.get("alg") or key.get("alg") == alg)
    ]
    if not candidates:
        raise WsFedError("signature", f"the transmitter publishes no {kty} signing key{f' with kid {kid}' if kid else ''}")
    data = f"{header_b}.{payload_b}".encode("ascii")
    signature = _b64url(sig_b, "signature")
    for jwk in candidates:
        key = _key_for(jwk)
        try:
            if hash_name is None:
                key.verify(signature, data)
            elif pss:
                algo = _HASH[hash_name]()
                key.verify(
                    signature,
                    data,
                    padding.PSS(mgf=padding.MGF1(_HASH[hash_name]()), salt_length=algo.digest_size),
                    _HASH[hash_name](),
                )
            elif p1363:
                half = len(signature) // 2
                der = encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
                key.verify(der, data, ec.ECDSA(_HASH[hash_name]()))
            else:
                key.verify(signature, data, padding.PKCS1v15(), _HASH[hash_name]())
            return {"header": header, "payload": payload}
        except Exception:
            continue
    raise WsFedError("signature", "the SET's signature does not verify against the transmitter's keys")
