# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""WS-Federation 1.2 passive requestor: login, the reply URL, logout, and this party's metadata."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

from wsfed_caep.config import ResolvedConfig, read_config_file, resolve_config
from wsfed_caep.errors import WsFedError
from wsfed_caep.http_client import send
from wsfed_caep.metadata import IdpMetadata, read_idp_metadata, write_rp_metadata
from wsfed_caep.replay import MemoryReplayCache
from wsfed_caep.token import validate_token
from wsfed_caep.xmlutil import NS, SAML2_TOKEN_TYPE

MAX_RELAY_STATE = 1024
PROTOCOL_PARAMS = {"wa", "wtrealm", "wreply", "wctx", "wct", "wreq", "wreqptr", "wfresh", "wauth", "whr"}


class LoginRequest:
    def __init__(self, request_id: str, url: str, wctx: str):
        self.id = request_id
        self.url = url
        self.wctx = wctx


class RelyingParty:
    def __init__(self, config: ResolvedConfig, idp: IdpMetadata | None = None, replay_cache=None):
        self.config = config
        self._idp = idp
        self._replay_cache = replay_cache or MemoryReplayCache()

    @classmethod
    def create(cls, config: dict, replay_cache=None, base_dir: str | None = None) -> "RelyingParty":
        party = cls(resolve_config(config, base_dir), None, replay_cache)
        party.refresh_metadata()
        return party

    @classmethod
    def from_file(cls, path: str, overrides: dict | None = None, replay_cache=None) -> "RelyingParty":
        party = cls(read_config_file(path, overrides), None, replay_cache)
        party.refresh_metadata()
        return party

    @property
    def idp(self) -> IdpMetadata:
        if self._idp is None:
            raise WsFedError("metadata", "the identity provider's metadata has not been loaded")
        return self._idp

    def refresh_metadata(self) -> IdpMetadata:
        source = self.config.idp_metadata
        if source.startswith("<"):
            xml = source
        elif source.startswith("http://") or source.startswith("https://"):
            tls = {"ca": self.config.idp_ca} if getattr(self.config, "idp_ca", None) else {}
            answer = send(source, {"headers": {"accept": "application/samlmetadata+xml, application/xml, text/xml"}}, tls, "metadata")
            if answer["status"] != 200:
                raise WsFedError("metadata", f"{source} answered HTTP {answer['status']}")
            xml = answer["body"]
        else:
            try:
                xml = Path(source).read_text(encoding="utf-8")
            except OSError as err:
                raise WsFedError("metadata", f"the identity provider metadata file {source} cannot be read", err) from err
        self._idp = read_idp_metadata(xml, getattr(self.config, "idp_entity_id", None))
        return self._idp

    def metadata(self) -> str:
        return write_rp_metadata(self.config.realm, self.config.reply_url, getattr(self.config, "certificate", None))

    def login(self, relay_state: str | None = None, force_authn: bool = False, freshness: int | None = None,
              authentication_method: str | None = None, home_realm: str | None = None, params: dict | None = None) -> LoginRequest:
        if relay_state is not None and len(relay_state.encode("utf-8")) > MAX_RELAY_STATE:
            raise WsFedError("config", f"relayState is longer than {MAX_RELAY_STATE} bytes")
        request_id = secrets.token_hex(20)
        wctx_pairs = [("id", request_id)]
        if relay_state is not None:
            wctx_pairs.append(("ru", relay_state))
        wctx = urlencode(wctx_pairs)
        pairs = [
            ("wa", "wsignin1.0"),
            ("wtrealm", self.config.realm),
            ("wreply", self.config.reply_url),
            ("wctx", wctx),
            ("wct", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        if self.config.request_token_type:
            pairs.append(("wreq", f'<wst:RequestSecurityToken xmlns:wst="{NS["trust13"]}"><wst:TokenType>{SAML2_TOKEN_TYPE}</wst:TokenType></wst:RequestSecurityToken>'))
        if force_authn:
            pairs.append(("wfresh", "0"))
        elif freshness is not None:
            if isinstance(freshness, bool) or not isinstance(freshness, int) or freshness < 0:
                raise WsFedError("config", "freshness is a whole number of minutes")
            pairs.append(("wfresh", str(freshness)))
        if authentication_method:
            pairs.append(("wauth", authentication_method))
        if home_realm:
            pairs.append(("whr", home_realm))
        for key, value in (params or {}).items():
            if key in PROTOCOL_PARAMS:
                raise WsFedError("config", f"params cannot set {key}; it is the protocol's own")
            pairs.append((key, value))
        endpoint = self.idp.passive_requestor_endpoint
        joiner = "&" if "?" in endpoint else "?"
        return LoginRequest(request_id, f"{endpoint}{joiner}{urlencode(pairs)}", wctx)

    def handle_reply(self, request: dict, request_id: str | list[str] | tuple[str, ...] | None = None):
        idp = self.idp
        form, query = _params_of(request)
        wa = form.get("wa") if "wa" in form else query.get("wa")
        if wa in ("wsignoutcleanup1.0", "wsignout1.0"):
            raise WsFedError("message", f"the request is {wa}, a sign-out, not a sign-in response; see isSignOutCleanup()")
        if str(request.get("method", "")).upper() != "POST":
            raise WsFedError("message", "a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET")
        if wa != "wsignin1.0":
            raise WsFedError("message", f"the request's wa is {wa or '(none)'}, not wsignin1.0")
        if "wresultptr" in form:
            raise WsFedError("message", "the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted")
        wresult = form.get("wresult")
        if not wresult:
            raise WsFedError("message", "the request carries no wresult")
        wctx = _first_map(parse_qsl(form.get("wctx") or "", keep_blank_values=True))
        got_id = wctx.get("id")
        if request_id is None:
            expected: list[str] = []
        elif isinstance(request_id, str):
            expected = [request_id]
        else:
            expected = list(request_id)
        if got_id is not None:
            if got_id not in expected:
                raise WsFedError("validation", f"the response answers {got_id}, which is not a sign-in this browser has outstanding")
        elif not self.config.allow_unsolicited:
            raise WsFedError("validation", "the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted")
        token = validate_token(wresult, {
            "realm": self.config.realm,
            "reply_url": self.config.reply_url,
            "idp_entity_id": idp.entity_id,
            "idp_certificates": idp.signing_certificates,
            "decryption_key": getattr(self.config, "private_key", None),
            "clock_skew_ms": self.config.clock_skew_ms,
            "want_assertions_encrypted": self.config.want_assertions_encrypted,
            "replay_cache": self._replay_cache,
        })
        if got_id is not None:
            token.request_id = got_id
        if "ru" in wctx:
            token.relay_state = wctx["ru"]
        return token

    def is_sign_out_cleanup(self, request: dict) -> bool:
        form, query = _params_of(request)
        wa = form.get("wa") if "wa" in form else query.get("wa")
        return wa in ("wsignoutcleanup1.0", "wsignout1.0")

    def logout(self, reply: str | None = None) -> str:
        pairs = [("wa", "wsignout1.0"), ("wtrealm", self.config.realm)]
        if reply:
            pairs.append(("wreply", reply))
        endpoint = self.idp.passive_requestor_endpoint
        joiner = "&" if "?" in endpoint else "?"
        return f"{endpoint}{joiner}{urlencode(pairs)}"


def _first_map(pairs) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in pairs:
        if key not in out:
            out[key] = value
    return out


def _form_of(body) -> dict[str, str]:
    if body is None:
        return {}
    if isinstance(body, str):
        return _first_map(parse_qsl(body, keep_blank_values=True))
    if isinstance(body, dict):
        return {str(key): value for key, value in body.items() if isinstance(value, str)}
    return {}


def _params_of(request: dict) -> tuple[dict[str, str], dict[str, str]]:
    url = request.get("url") or ""
    query = ""
    if "?" in url:
        query = url.split("?", 1)[1].split("#", 1)[0]
    parsed = _first_map(parse_qsl(query, keep_blank_values=True))
    form = _form_of(request.get("body")) if str(request.get("method", "")).upper() == "POST" else {}
    return form, parsed
