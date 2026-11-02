# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Configuration. signals defaults to on. false is recorded; true and omitted are left off the result."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from wsfed_caep.errors import WsFedError


class ResolvedConfig:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _pem(value: str) -> bool:
    return "-----BEGIN " in value


def _material(value: str, base_dir: str, what: str) -> str:
    if value.startswith("env:"):
        name = value[4:]
        if not os.environ.get(name):
            raise WsFedError("config", f"{what} environment variable {name} is not set")
        value = os.environ[name]
    if value.startswith("file:"):
        value = value[5:]
    if _pem(value):
        return value
    path = value if os.path.isabs(value) else str(Path(base_dir) / value)
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as err:
        raise WsFedError("config", f"{what} is neither a PEM nor a readable file ({path})", err) from err


def _absolute_url(value, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WsFedError("config", f"{what} is required")
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValueError("not http(s)")
    except Exception:
        raise WsFedError("config", f"{what} must be an absolute http(s) URL, not {value}") from None
    return value


def _flag(value, default: bool, what: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise WsFedError("config", f"{what} must be true or false")
    return value


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _idp_metadata(value: str, base_dir: str) -> str:
    value = value.strip()
    if value.startswith("env:"):
        name = value[4:]
        if not os.environ.get(name):
            raise WsFedError("config", f"idpMetadata environment variable {name} is not set")
        value = os.environ[name].strip()
    if value.startswith("file:"):
        value = value[5:]
    if value.startswith("http://") or value.startswith("https://") or value.startswith("<"):
        return value
    return value if os.path.isabs(value) else str(Path(base_dir) / value)


def resolve_config(config: dict, base_dir: str | None = None) -> ResolvedConfig:
    if not isinstance(config, dict):
        raise WsFedError("config", "the configuration must be an object")
    base = base_dir or os.getcwd()
    realm = config.get("realm")
    if not isinstance(realm, str) or not realm.strip():
        raise WsFedError("config", "realm is required")
    reply_url = _absolute_url(config.get("replyUrl"), "replyUrl")
    raw_metadata = config.get("idpMetadata")
    if not isinstance(raw_metadata, str) or not raw_metadata.strip():
        raise WsFedError("config", "idpMetadata is required")
    skew = 60 if config.get("clockSkewSeconds") is None else config.get("clockSkewSeconds")
    if not _number(skew) or skew < 0 or skew > 600 or skew != skew:
        raise WsFedError("config", "clockSkewSeconds must be a number from 0 to 600")
    signals = _flag(config.get("signals") if "signals" in config else None, True, "signals")
    # A missing key and an explicit JSON null are both the default. A non-boolean is an error.
    if "signals" in config:
        signals = _flag(config.get("signals"), True, "signals")
    out = ResolvedConfig(
        realm=realm,
        reply_url=reply_url,
        idp_metadata=_idp_metadata(raw_metadata, base),
        clock_skew_ms=int(skew * 1000) if isinstance(skew, float) and not isinstance(skew, int) else int(skew) * 1000,
        want_assertions_encrypted=_flag(config.get("wantAssertionsEncrypted") if "wantAssertionsEncrypted" in config else None, False, "wantAssertionsEncrypted"),
        allow_unsolicited=_flag(config.get("allowUnsolicited") if "allowUnsolicited" in config else None, False, "allowUnsolicited"),
        request_token_type=_flag(config.get("requestTokenType") if "requestTokenType" in config else None, True, "requestTokenType"),
    )
    if "wantAssertionsEncrypted" in config:
        out.want_assertions_encrypted = _flag(config.get("wantAssertionsEncrypted"), False, "wantAssertionsEncrypted")
    if "allowUnsolicited" in config:
        out.allow_unsolicited = _flag(config.get("allowUnsolicited"), False, "allowUnsolicited")
    if "requestTokenType" in config:
        out.request_token_type = _flag(config.get("requestTokenType"), True, "requestTokenType")
    if not signals:
        out.signals = False
    has_key = config.get("privateKey") is not None
    has_cert = config.get("certificate") is not None
    if has_key != has_cert:
        raise WsFedError("config", "privateKey and certificate go together: give both or neither")
    if has_key and has_cert:
        try:
            private_key = serialization.load_pem_private_key(_material(config["privateKey"], base, "privateKey").encode(), password=None)
            certificate = x509.load_pem_x509_certificate(_material(config["certificate"], base, "certificate").encode())
        except WsFedError:
            raise
        except Exception as err:
            raise WsFedError("config", f"the private key or certificate cannot be read: {err}", err) from err
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise WsFedError("config", f"the private key is {type(private_key).__name__}; an RSA key is required")
        if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
            raise WsFedError("config", "the certificate is not for the private key")
        out.private_key = private_key
        out.certificate = certificate
    elif out.want_assertions_encrypted:
        raise WsFedError("config", "wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them")
    if config.get("idpCa"):
        out.idp_ca = _material(config["idpCa"], base, "idpCa")
    if config.get("idpEntityId"):
        out.idp_entity_id = config["idpEntityId"]
    return out


def read_config_file(path: str, overrides: dict | None = None) -> ResolvedConfig:
    overrides = overrides or {}
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise WsFedError("config", f"{path} cannot be read as JSON: {err}", err) from err
    defined = {key: value for key, value in overrides.items() if value is not None}
    merged = {**parsed, **defined}
    return resolve_config(merged, str(Path(path).resolve().parent))
