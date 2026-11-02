# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The relying party against the stub identity provider."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

from stub_idp import (
    IDP_CERT,
    IDP_ENTITY,
    PASSIVE,
    REALM,
    REPLY,
    RP_CERT,
    RP_KEY,
    assertion_xml,
    encrypt,
    idp_metadata,
    saml11_assertion,
    sign_xml,
    signed_assertion,
    wresult,
)
from wsfed_caep import RelyingParty, WsFedError, resolve_config


def config(extra: dict | None = None, **metadata) -> dict:
    body = {
        "realm": REALM,
        "replyUrl": REPLY,
        "privateKey": RP_KEY,
        "certificate": RP_CERT,
        "idpMetadata": idp_metadata(**metadata) if metadata else idp_metadata(),
    }
    body.update(extra or {})
    return body


def post(rp: RelyingParty, result: str, request_id=None, wctx=None):
    if wctx is None and request_id:
        wctx = f"id={request_id}"
    body = {"wa": "wsignin1.0", "wresult": result}
    if wctx is not None:
        body["wctx"] = wctx
    return rp.handle_reply({"method": "POST", "url": "/wsfed", "body": body}, request_id)


def rejects(call, code: str, pattern: str | None = None):
    with pytest.raises(WsFedError) as caught:
        call()
    assert caught.value.code == code, str(caught.value)
    if pattern:
        assert re.search(pattern, str(caught.value)), str(caught.value)


def qparams(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def test_configuration_requires_realm_reply_and_a_matching_key():
    rejects(lambda: RelyingParty.create({**config(), "realm": ""}), "config", "realm")
    rejects(lambda: RelyingParty.create({**config(), "replyUrl": "/wsfed"}), "config", "absolute")
    rejects(lambda: RelyingParty.create(config({"certificate": IDP_CERT})), "config", "not for the private key")
    rejects(lambda: RelyingParty.create({"realm": REALM, "replyUrl": REPLY, "idpMetadata": idp_metadata(), "privateKey": RP_KEY}), "config", "together")
    rejects(lambda: RelyingParty.create({"realm": REALM, "replyUrl": REPLY, "idpMetadata": idp_metadata(), "wantAssertionsEncrypted": True}), "config", "needs privateKey")
    keyless = RelyingParty.create({"realm": REALM, "replyUrl": REPLY, "idpMetadata": idp_metadata()})
    assert "KeyDescriptor" not in keyless.metadata()


def test_signals_omitted_or_true_is_left_off_the_resolved_config():
    base = {"realm": REALM, "replyUrl": REPLY, "idpMetadata": "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml"}
    omitted = resolve_config(base)
    assert not hasattr(omitted, "signals")
    assert omitted.realm == REALM
    assert omitted.reply_url == REPLY
    assert omitted.request_token_type is True
    on = resolve_config({**base, "signals": True})
    assert not hasattr(on, "signals")
    assert on.__dict__ == omitted.__dict__


def test_signals_false_is_recorded_and_the_rest_still_resolves():
    base = {"realm": REALM, "replyUrl": REPLY, "idpMetadata": "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml"}
    off = resolve_config({**base, "signals": False})
    assert off.signals is False
    rest = dict(off.__dict__)
    assert rest.pop("signals") is False
    assert rest == resolve_config(base).__dict__
    assert off.realm == REALM
    assert off.reply_url == REPLY
    assert off.idp_metadata == base["idpMetadata"]


def test_signals_must_be_true_or_false():
    base = {"realm": REALM, "replyUrl": REPLY, "idpMetadata": "https://idp.example/metadata"}
    with pytest.raises(WsFedError) as caught:
        resolve_config({**base, "signals": "no"})
    assert caught.value.code == "config"
    assert str(caught.value) == "signals must be true or false"


def test_reads_the_security_token_service_role():
    rp = RelyingParty.create(config())
    assert rp.idp.entity_id == IDP_ENTITY
    assert rp.idp.passive_requestor_endpoint == PASSIVE
    assert "urn:oasis:names:tc:SAML:2.0:assertion" in rp.idp.token_types_offered
    assert len(rp.idp.signing_certificates) == 1


def test_xsi_type_is_resolved_by_namespace_and_the_idp_role_key_is_a_fallback():
    assert RelyingParty.create(config(fed_prefix="wsfed")).idp.passive_requestor_endpoint == PASSIVE
    assert len(RelyingParty.create(config(key_in="idpsso")).idp.signing_certificates) == 1


def test_refuses_metadata_without_an_sts_or_saml2():
    rejects(lambda: RelyingParty.create(config(no_sts=True)), "metadata", "SecurityTokenServiceType")
    rejects(lambda: RelyingParty.create(config(token_types=["urn:oasis:names:tc:SAML:1.0:assertion"])), "metadata", "no SAML 2.0")


def test_writes_application_service_metadata():
    xml = RelyingParty.create(config()).metadata()
    root = __import__("lxml").etree.fromstring(xml.encode())
    assert root.get("entityID") == REALM
    role = root.find("{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor")
    assert role.get("{http://www.w3.org/2001/XMLSchema-instance}type") == "fed:ApplicationServiceType"
    assert f"<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>{REPLY}</wsa:Address>" in xml
    assert f"<fed:TargetScopes><wsa:EndpointReference><wsa:Address>{REALM}</wsa:Address>" in xml
    assert re.search(r'<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*</md:KeyDescriptor>', xml)


def test_signin_names_realm_reply_wctx_and_saml2():
    rp = RelyingParty.create(config())
    req = rp.login(relay_state="/home é")
    params = qparams(req.url)
    assert urlsplit(req.url).scheme + "://" + urlsplit(req.url).netloc + urlsplit(req.url).path == PASSIVE
    assert params["wa"] == "wsignin1.0"
    assert params["wtrealm"] == REALM
    assert params["wreply"] == REPLY
    wctx = dict(parse_qsl(params["wctx"]))
    assert wctx["id"] == req.id
    assert wctx["ru"] == "/home é"
    assert "<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>" in params["wreq"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", params["wct"])
    assert "wfresh" not in params


def test_force_authn_and_protocol_params():
    rp = RelyingParty.create(config({"requestTokenType": False}))
    params = qparams(rp.login(force_authn=True, authentication_method="http://schemas.microsoft.com/claims/multipleauthn", home_realm="urn:partner", params={"login_hint": "alice"}).url)
    assert params["wfresh"] == "0"
    assert params["wauth"] == "http://schemas.microsoft.com/claims/multipleauthn"
    assert params["whr"] == "urn:partner"
    assert params["login_hint"] == "alice"
    assert "wreq" not in params
    with pytest.raises(WsFedError, match="protocol's own"):
        rp.login(params={"wtrealm": "urn:evil"})
    with pytest.raises(WsFedError, match="1024 bytes"):
        rp.login(relay_state="x" * 1025)


def test_signout_request():
    rp = RelyingParty.create(config())
    params = qparams(rp.logout(reply="https://rp.test/"))
    assert params["wa"] == "wsignout1.0"
    assert params["wtrealm"] == REALM
    assert params["wreply"] == "https://rp.test/"


def test_signed_assertion_in_a_2005_response():
    rp = RelyingParty.create(config())
    req = rp.login(relay_state="/home")
    who = post(rp, wresult(), req.id, req.wctx)
    assert who.name_id == "alice-1234"
    assert who.name_id_format == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    assert who.session_index == "_session1"
    assert who.relay_state == "/home"
    assert who.request_id == req.id
    assert who.trust_version == "2005/02"
    assert who.realm == REALM
    assert who.encrypted is False
    assert who.attributes["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"] == ["staff", "admins"]
    assert who.attribute_friendly_names["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] == "mail"
    assert who.authn_context_class_ref == "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"


def test_trust_13_and_a_raw_form_body():
    rp = RelyingParty.create(config())
    assert post(rp, wresult(trust="1.3"), "_r").trust_version == "1.3"
    raw = urlencode({"wa": "wsignin1.0", "wresult": wresult(), "wctx": "id=_s"})
    who = rp.handle_reply({"method": "POST", "url": "/wsfed", "body": raw}, ["_x", "_s"])
    assert who.name_id == "alice-1234"


def test_recipient_optional_and_checked():
    rp = RelyingParty.create(config())
    assert post(rp, wresult(token=signed_assertion(recipient=None)["xml"]), "_r").name_id == "alice-1234"
    rejects(lambda: post(rp, wresult(token=signed_assertion(recipient="https://other.test/wsfed")["xml"]), "_r"), "validation", "Recipient")


def test_bare_bearer_confirmation():
    rp = RelyingParty.create(config())
    who = post(rp, wresult(token=signed_assertion(bare_confirmation=True)["xml"]), "_r")
    assert who.name_id == "alice-1234"
    assert who.not_on_or_after.timestamp() > __import__("time").time()
    rejects(lambda: post(rp, wresult(token=signed_assertion(bare_confirmation=True, not_on_or_after_ms=-120_000)["xml"]), "_r"), "validation", "expired")
    rejects(lambda: post(rp, wresult(token=signed_assertion(bare_confirmation=True, no_conditions_expiry=True)["xml"]), "_r"), "validation", "nothing|no Conditions NotOnOrAfter")


def test_unsigned_assertion_is_refused():
    rp = RelyingParty.create(config())
    rejects(lambda: post(rp, wresult(token=assertion_xml()["xml"]), "_r"), "validation", "not signed")


def test_altered_or_wrong_key_is_refused():
    rp = RelyingParty.create(config())
    rejects(lambda: post(rp, wresult(token=signed_assertion()["xml"].replace("alice-1234", "mallory")), "_r"), "signature", None)
    made = assertion_xml()
    rejects(lambda: post(rp, wresult(token=sign_xml(made["xml"], made["id"], RP_KEY, RP_CERT)), "_r"), "signature", "does not verify")


def test_signature_wrapping():
    rp = RelyingParty.create(config())
    signed = signed_assertion()
    forged = assertion_xml(name_id="mallory")["xml"]
    rejects(lambda: post(rp, wresult(token=forged + signed["xml"]), "_r"), "message", "exactly one")
    hidden = re.sub(r'ID="[^"]+"', f'ID="{signed["id"]}"', forged, count=1).replace(
        "</saml:Assertion>", f"<saml:Advice>{signed['xml']}</saml:Advice></saml:Assertion>"
    )
    rejects(lambda: post(rp, wresult(token=hidden), "_r"), "signature", "two elements")
    decoy = wresult(token=signed["xml"]).replace(
        "<t:Lifetime>",
        f'<t:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="{signed["id"]}">',
    )
    rejects(lambda: post(rp, decoy, "_r"), "signature", "two elements")
    sig_xml = re.search(r"<ds:Signature[\s\S]*</ds:Signature>", signed["xml"]).group(0)
    moved = re.sub(r"(</saml:Issuer>)", r"\1" + sig_xml, forged, count=1)
    rejects(lambda: post(rp, wresult(token=moved), "_r"), "signature", "refers to")


def test_wrong_realm_issuer_or_expiry():
    rp = RelyingParty.create(config())
    rejects(lambda: post(rp, wresult(token=signed_assertion(audience="https://other.test/")["xml"]), "_r"), "validation", "not for")
    rejects(lambda: post(rp, wresult(token=signed_assertion(issuer="https://evil.test")["xml"]), "_r"), "validation", "issued by")
    rejects(lambda: post(rp, wresult(token=signed_assertion(not_on_or_after_ms=-120_000)["xml"]), "_r"), "validation", "expired")
    rejects(lambda: post(rp, wresult(applies_to="https://other.test/"), "_r"), "validation", "applies to")
    rejects(lambda: post(rp, wresult(expires_ms=-120_000), "_r"), "validation", "response expired")


def test_in_response_to_is_refused():
    rp = RelyingParty.create(config())
    rejects(lambda: post(rp, wresult(token=signed_assertion(in_response_to="_samlreq")["xml"]), "_r"), "validation", "InResponseTo")


def test_saml11_and_non_trust_are_refused():
    rp = RelyingParty.create(config())
    rejects(lambda: post(rp, wresult(token=saml11_assertion(), token_type="urn:oasis:names:tc:SAML:2.0:assertion"), "_r"), "message", r"SAML 1\.1")
    rejects(lambda: post(rp, wresult(token_type="urn:oasis:names:tc:SAML:1.0:assertion"), "_r"), "message", "SAML 2.0 assertions only")
    rejects(lambda: post(rp, signed_assertion()["xml"], "_r"), "message", "not a WS-Trust")
    rejects(lambda: post(rp, f'<!DOCTYPE x [<!ENTITY e "x">]>{wresult()}', "_r"), "xml", "DOCTYPE")


def test_unsolicited_and_unknown_requests():
    rp = RelyingParty.create(config())
    rejects(lambda: post(rp, wresult(), "_other", "id=_r"), "validation", "not a sign-in this browser")
    rejects(lambda: post(rp, wresult(), None, "id=_r"), "validation", "not a sign-in this browser")
    rejects(lambda: post(rp, wresult(), None), "validation", "unsolicited")
    open_rp = RelyingParty.create(config({"allowUnsolicited": True}))
    who = post(open_rp, wresult(), None, "ru=%2Fthere")
    assert not hasattr(who, "request_id")
    assert who.relay_state == "/there"


def test_replay():
    rp = RelyingParty.create(config())
    result = wresult()
    post(rp, result, "_r")
    rejects(lambda: post(rp, result, "_r"), "replay", None)


def test_decrypts_encrypted_assertions():
    rp = RelyingParty.create(config())
    for cipher in ("aes-256-gcm", "aes-128-cbc"):
        who = post(rp, wresult(token=encrypt(signed_assertion()["xml"], cipher)), "_r")
        assert who.name_id == "alice-1234"
        assert who.encrypted is True
    who = post(rp, wresult(token=encrypt(signed_assertion()["xml"], "aes-256-gcm", "oaep256", None)), "_r")
    assert who.encrypted is True


def test_want_assertions_encrypted_and_tampered_ciphertext():
    rp = RelyingParty.create(config({"wantAssertionsEncrypted": True}))
    rejects(lambda: post(rp, wresult(), "_r"), "validation", "not encrypted")
    rejects(lambda: post(rp, wresult(token=encrypt(assertion_xml()["xml"])), "_r"), "validation", "not signed")
    enc = encrypt(signed_assertion()["xml"])
    values = re.findall(r"<xenc:CipherValue>([^<]+)</xenc:CipherValue>", enc)
    last = values[-1]
    raw = bytearray(base64_of(last))
    raw[20] ^= 1
    import base64

    replaced = enc.replace(last, base64.b64encode(raw).decode())
    rejects(lambda: post(rp, wresult(token=replaced), "_r"), "decryption", None)


def base64_of(value: str) -> bytes:
    import base64

    return base64.b64decode(value)


def test_encrypted_attribute_and_missing_key():
    keyless = RelyingParty.create({"realm": REALM, "replyUrl": REPLY, "idpMetadata": idp_metadata()})
    rejects(lambda: post(keyless, wresult(token=encrypt(signed_assertion()["xml"])), "_r"), "decryption", "no privateKey")
    rp = RelyingParty.create(config())
    secret = encrypt(
        '<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="employeeNumber"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>',
        "aes-256-gcm",
        "oaep256",
        "EncryptedAttribute",
    )
    made = assertion_xml(extra_attributes=secret)
    who = post(rp, wresult(token=sign_xml(made["xml"], made["id"])), "_r")
    assert who.attributes["employeeNumber"] == ["E-42"]


def test_reply_url_refuses_get_wrong_wa_and_wresultptr():
    rp = RelyingParty.create(config())
    from urllib.parse import quote

    rejects(lambda: rp.handle_reply({"method": "GET", "url": f"/wsfed?wa=wsignin1.0&wresult={quote(wresult())}"}), "message", "POSTed")
    rejects(lambda: rp.handle_reply({"method": "POST", "url": "/wsfed", "body": {"wa": "wattr1.0", "wresult": wresult()}}), "message", "not wsignin1.0")
    rejects(lambda: rp.handle_reply({"method": "POST", "url": "/wsfed", "body": {"wa": "wsignin1.0", "wresultptr": "https://evil.test/"}}), "message", "wresultptr")
    rejects(lambda: rp.handle_reply({"method": "POST", "url": "/wsfed", "body": {"wa": "wsignin1.0"}}), "message", "no wresult")


def test_sign_out_cleanup():
    rp = RelyingParty.create(config())
    assert rp.is_sign_out_cleanup({"method": "GET", "url": "/wsfed?wa=wsignoutcleanup1.0"}) is True
    assert rp.is_sign_out_cleanup({"method": "POST", "url": "/wsfed", "body": "wa=wsignout1.0"}) is True
    assert rp.is_sign_out_cleanup({"method": "POST", "url": "/wsfed", "body": {"wa": "wsignin1.0"}}) is False
    rejects(lambda: rp.handle_reply({"method": "GET", "url": "/wsfed?wa=wsignoutcleanup1.0"}), "message", "sign-out")
