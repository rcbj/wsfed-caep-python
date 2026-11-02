# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Read a wresult and validate the SAML 2.0 assertion it carries. The assertion signature is the only one."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from wsfed_caep.encryption import decrypt_element
from wsfed_caep.errors import WsFedError
from wsfed_caep.signature import verify_signed
from wsfed_caep.xmlutil import (
    CM_BEARER,
    NS,
    SAML2_TOKEN_TYPES,
    assert_unique_ids,
    attr,
    child,
    children,
    element_children,
    is_el,
    parse_xml,
    text,
    text_content,
    wsa_addresses,
)

_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$")


class WsFedLogin:
    """Who signed in. Optional fields are absent when the assertion did not carry them."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _invalid(message: str):
    raise WsFedError("validation", message)


def _malformed(message: str):
    raise WsFedError("message", message)


def _instant(value: str | None, what: str) -> datetime | None:
    if value is None:
        return None
    if not _UTC.match(value):
        _invalid(f"{what} is not a UTC dateTime: {value}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _invalid(f"{what} is not a dateTime: {value}")
    return None


def _ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def _response_of(root):
    if is_el(root, NS["trust13"], "RequestSecurityTokenResponseCollection"):
        all_responses = children(root, NS["trust13"], "RequestSecurityTokenResponse")
        if len(all_responses) != 1:
            _malformed(f"the RequestSecurityTokenResponseCollection holds {len(all_responses)} responses; exactly one is accepted")
        return all_responses[0], NS["trust13"], "1.3"
    if is_el(root, NS["trust2005"], "RequestSecurityTokenResponse"):
        return root, NS["trust2005"], "2005/02"
    if is_el(root, NS["trust13"], "RequestSecurityTokenResponse"):
        return root, NS["trust13"], "1.3"
    ns = etree_ns(root)
    _malformed(f"wresult is a <{local_name(root)}> in {ns}, not a WS-Trust RequestSecurityTokenResponse")
    raise AssertionError("unreachable")


def local_name(el) -> str:
    from lxml import etree

    return etree.QName(el).localname if isinstance(el.tag, str) else ""


def etree_ns(el) -> str:
    from lxml import etree

    if not isinstance(el.tag, str):
        return "no namespace"
    return etree.QName(el).namespace or "no namespace"


def validate_token(wresult: str, ctx: dict) -> WsFedLogin:
    now = _ms(ctx.get("now") or datetime.now(timezone.utc))
    skew = ctx["clock_skew_ms"]
    root = parse_xml(wresult, "wresult")
    assert_unique_ids(root)
    rstr, trust, trust_version = _response_of(root)
    token_type = text(child(rstr, trust, "TokenType"))
    if token_type and token_type not in SAML2_TOKEN_TYPES:
        _malformed(f"the response carries a token of type {token_type}; this relying party accepts SAML 2.0 assertions only")
    applies = [*children(rstr, NS["wsp"], "AppliesTo"), *children(rstr, NS["wsp15"], "AppliesTo")]
    if len(applies) > 1:
        _malformed("the response has more than one AppliesTo")
    if applies:
        scopes = wsa_addresses(applies[0])
        if scopes and ctx["realm"] not in scopes:
            _invalid(f"the response applies to {', '.join(scopes)}, not to {ctx['realm']}")
    lifetime = child(rstr, trust, "Lifetime")
    expires = None
    if lifetime is not None:
        raw_expires = text(child(lifetime, NS["wsu"], "Expires")) or None
        expires = _instant(raw_expires, "the response's Lifetime Expires")
    if expires and _ms(expires) <= now - skew:
        _invalid(f"the response expired at {expires.strftime('%Y-%m-%dT%H:%M:%S.') + f'{expires.microsecond // 1000:03d}Z'}")
    requested = children(rstr, trust, "RequestedSecurityToken")
    if len(requested) != 1:
        _malformed(f"the response holds {len(requested)} RequestedSecurityToken elements; exactly one is accepted")
    tokens = element_children(requested[0])
    if len(tokens) != 1:
        _malformed(f"the RequestedSecurityToken holds {len(tokens)} tokens; exactly one is accepted")
    token = tokens[0]
    encrypted = False
    if is_el(token, NS["saml"], "Assertion"):
        if ctx["want_assertions_encrypted"]:
            _invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on")
        assertion = token
        assertion_root = root
    elif is_el(token, NS["saml"], "EncryptedAssertion") or is_el(token, NS["xenc"], "EncryptedData"):
        if not ctx.get("decryption_key"):
            raise WsFedError("decryption", "the assertion is encrypted, and this relying party has no privateKey to decrypt it with")
        encrypted = True
        assertion_xml = decrypt_element(token, ctx["decryption_key"])
        assertion_root = parse_xml(assertion_xml, "the decrypted assertion")
        assert_unique_ids(assertion_root)
        assertion = assertion_root
        if is_el(assertion, NS["saml1"], "Assertion"):
            _malformed("the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only")
        if not is_el(assertion, NS["saml"], "Assertion"):
            _invalid("the encrypted token does not hold a SAML 2.0 Assertion")
    elif is_el(token, NS["saml1"], "Assertion"):
        _malformed(
            "the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. "
            "Ask for SAML 2.0 (requestTokenType, the default), or configure the identity provider to issue it to this realm"
        )
    else:
        _malformed(f"the RequestedSecurityToken holds a <{local_name(token)}>, not a SAML 2.0 assertion")
        raise AssertionError("unreachable")

    signed = verify_signed("", assertion, ctx["idp_certificates"], "the assertion")
    if signed is None:
        _invalid("the assertion is not signed; in WS-Federation its signature is the only one, so it is required")
    assertion = parse_xml(signed, "the signed assertion")
    if attr(assertion, "Version") != "2.0":
        _invalid("the assertion is not version 2.0")
    assertion_id = attr(assertion, "ID")
    if not assertion_id:
        _invalid("the assertion has no ID")
    issuer = child(assertion, NS["saml"], "Issuer")
    if issuer is None:
        _invalid("the assertion has no Issuer")
    issuer_format = attr(issuer, "Format")
    if issuer_format and issuer_format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity":
        _invalid(f"the assertion's Issuer has the Format {issuer_format}")
    if text(issuer) != ctx["idp_entity_id"]:
        _invalid(f"the assertion was issued by {text(issuer)}, not by {ctx['idp_entity_id']}")
    subject = child(assertion, NS["saml"], "Subject")
    if subject is None:
        _invalid("the assertion has no Subject")
    name_id_el = child(subject, NS["saml"], "NameID")
    encrypted_id = child(subject, NS["saml"], "EncryptedID")
    if name_id_el is None and encrypted_id is not None:
        if not ctx.get("decryption_key"):
            raise WsFedError("decryption", "the NameID is encrypted, and this relying party has no privateKey to decrypt it with")
        name_id_el = parse_xml(decrypt_element(encrypted_id, ctx["decryption_key"]), "the decrypted NameID")
        if not is_el(name_id_el, NS["saml"], "NameID"):
            _invalid("the EncryptedID does not hold a NameID")
    if name_id_el is None or not text(name_id_el):
        _invalid("the assertion's Subject has no NameID")
    conditions = child(assertion, NS["saml"], "Conditions")
    if conditions is None:
        _invalid("the assertion has no Conditions, so it names no audience")
    not_before = _instant(attr(conditions, "NotBefore"), "Conditions NotBefore")
    not_on_or_after = _instant(attr(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter")
    reasons: list[str] = []
    confirmed_until = None
    for confirmation in children(subject, NS["saml"], "SubjectConfirmation"):
        if attr(confirmation, "Method") != CM_BEARER:
            reasons.append(f"method {attr(confirmation, 'Method')}")
            continue
        data = child(confirmation, NS["saml"], "SubjectConfirmationData")
        if data is None:
            if not_on_or_after is None:
                reasons.append("no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it")
                continue
            confirmed_until = not_on_or_after
            break
        recipient = attr(data, "Recipient")
        until = _instant(attr(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter") or not_on_or_after
        if recipient is not None and recipient != ctx["reply_url"]:
            reasons.append(f"Recipient {recipient}")
        elif until is None:
            reasons.append("no NotOnOrAfter, on the confirmation or the Conditions")
        elif _ms(until) <= now - skew:
            reasons.append(f"expired at {_iso(until)}")
        elif attr(data, "NotBefore") is not None:
            reasons.append("a NotBefore, which a bearer confirmation must not have")
        elif attr(data, "InResponseTo") is not None:
            reasons.append(f"InResponseTo {attr(data, 'InResponseTo')}, which answers a SAML request, not a WS-Federation sign-in")
        else:
            confirmed_until = until
            break
    if confirmed_until is None:
        _invalid(f"no bearer SubjectConfirmation of the assertion fits: {'; '.join(reasons) or 'there is none'}")
    if not_before and _ms(not_before) > now + skew:
        _invalid(f"the assertion is not valid before {_iso(not_before)}")
    if not_on_or_after and _ms(not_on_or_after) <= now - skew:
        _invalid(f"the assertion expired at {_iso(not_on_or_after)}")
    restrictions = children(conditions, NS["saml"], "AudienceRestriction")
    if not restrictions:
        _invalid("the assertion has no AudienceRestriction")
    for restriction in restrictions:
        if not any(text(audience) == ctx["realm"] for audience in children(restriction, NS["saml"], "Audience")):
            _invalid(f"the assertion is not for {ctx['realm']}")
    authn_all = children(assertion, NS["saml"], "AuthnStatement")
    if not authn_all:
        _invalid("the assertion has no AuthnStatement")
    authn = authn_all[0]
    authn_instant = _instant(attr(authn, "AuthnInstant"), "AuthnInstant")
    if authn_instant is None:
        _invalid("the AuthnStatement has no AuthnInstant")
    session_not = _instant(attr(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter")
    if session_not and _ms(session_not) <= now - skew:
        _invalid("the identity provider's session has already ended")
    context_el = child(authn, NS["saml"], "AuthnContext")
    class_ref = text(child(context_el, NS["saml"], "AuthnContextClassRef")) if context_el is not None else ""
    attributes: dict[str, list[str]] = {}
    friendly: dict[str, str] = {}
    for statement in children(assertion, NS["saml"], "AttributeStatement"):
        decrypted = []
        for encrypted_attr in children(statement, NS["saml"], "EncryptedAttribute"):
            if not ctx.get("decryption_key"):
                raise WsFedError("decryption", "an attribute is encrypted, and this relying party has no privateKey to decrypt it with")
            element = parse_xml(decrypt_element(encrypted_attr, ctx["decryption_key"]), "the decrypted attribute")
            if not is_el(element, NS["saml"], "Attribute"):
                _invalid("an EncryptedAttribute does not hold an Attribute")
            decrypted.append(element)
        for attribute in [*children(statement, NS["saml"], "Attribute"), *decrypted]:
            name = attr(attribute, "Name")
            if not name:
                continue
            values = [text_content(value) for value in children(attribute, NS["saml"], "AttributeValue")]
            attributes.setdefault(name, []).extend(values)
            friendly_name = attr(attribute, "FriendlyName")
            if friendly_name:
                friendly[name] = friendly_name
    keep_ms = max(_ms(confirmed_until), _ms(not_on_or_after) if not_on_or_after else 0) + skew
    keep_until = datetime.fromtimestamp(keep_ms / 1000, tz=timezone.utc)
    replay_id = f"{ctx['idp_entity_id']} {assertion_id}"
    recorded = ctx["replay_cache"].check_and_record(replay_id, keep_until)
    if recorded:
        raise WsFedError("replay", f"the assertion {assertion_id} has been accepted before")
    login = WsFedLogin(
        name_id=text(name_id_el),
        authn_instant=authn_instant,
        attributes=attributes,
        attribute_friendly_names=friendly,
        issuer=ctx["idp_entity_id"],
        realm=ctx["realm"],
        trust_version=trust_version,
        encrypted=encrypted,
        assertion_id=assertion_id,
        not_on_or_after=confirmed_until,
    )
    optional = {
        "name_id_format": attr(name_id_el, "Format"),
        "name_qualifier": attr(name_id_el, "NameQualifier"),
        "sp_name_qualifier": attr(name_id_el, "SPNameQualifier"),
        "session_index": attr(authn, "SessionIndex"),
        "session_not_on_or_after": session_not,
        "authn_context_class_ref": class_ref or None,
    }
    for key, value in optional.items():
        if value is not None:
            setattr(login, key, value)
    return login


def _iso(moment: datetime) -> str:
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
