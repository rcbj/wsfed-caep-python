# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A stub WS-Federation identity provider. It signs with the fixture key and the library's canonicalization."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

from wsfed_caep.signature import EXC_C14N, _c14n

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


RP_KEY = _fixture("rp.key")
RP_CERT = _fixture("rp.crt")
IDP_KEY = _fixture("idp.key")
IDP_CERT = _fixture("idp.crt")

IDP_ENTITY = "https://idp.test"
PASSIVE = "https://idp.test/wsfed"
REALM = "https://rp.test/"
REPLY = "https://rp.test/wsfed"

_DS = "http://www.w3.org/2000/09/xmldsig#"
_XENC = "http://www.w3.org/2001/04/xmlenc#"
_XENC11 = "http://www.w3.org/2009/xmlenc11#"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_CLAIMS = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


def _pem_body(pem: str) -> str:
    return "".join(line for line in pem.splitlines() if "-----" not in line).replace(" ", "")


def _iso(offset_ms: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(milliseconds=offset_ms)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _id() -> str:
    return "_" + secrets.token_hex(16)


def idp_metadata(key_in: str = "sts", token_types: list[str] | None = None, fed_prefix: str = "fed", no_sts: bool = False) -> str:
    fed = fed_prefix
    key = (
        '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
        f"{_pem_body(IDP_CERT)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
    )
    types = "".join(f'<{fed}:TokenType Uri="{token}"/>' for token in (token_types or [
        "urn:oasis:names:tc:SAML:1.0:assertion",
        "urn:oasis:names:tc:SAML:2.0:assertion",
    ]))
    sts = "" if no_sts else f"""
  <md:RoleDescriptor xsi:type="{fed}:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    {"" if key_in == "idpsso" else key}
    <{fed}:TokenTypesOffered>{types}</{fed}:TokenTypesOffered>
    <{fed}:SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/sts</wsa:Address></wsa:EndpointReference></{fed}:SecurityTokenServiceEndpoint>
    <{fed}:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>{PASSIVE}</wsa:Address></wsa:EndpointReference></{fed}:PassiveRequestorEndpoint>
  </md:RoleDescriptor>"""
    return (
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{_DS}" '
        f'xmlns:{fed}="http://docs.oasis-open.org/wsfed/federation/200706" '
        'xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'entityID="{IDP_ENTITY}">{sts}\n'
        '  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f"    {key}\n"
        '    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/saml2/sso"/>\n'
        "  </md:IDPSSODescriptor>\n</md:EntityDescriptor>"
    )


def assertion_xml(
    audience: str | None = None,
    recipient: str | None = REPLY,
    recipient_set: bool = True,
    in_response_to: str | None = None,
    not_on_or_after_ms: int = 300_000,
    issuer: str | None = None,
    name_id: str | None = None,
    session_index: str | None = None,
    extra_attributes: str = "",
    bare_confirmation: bool = False,
    no_conditions_expiry: bool = False,
) -> dict:
    aid = _id()
    if not recipient_set:
        recipient_attr = ""
    else:
        recipient_attr = f' Recipient="{recipient}"' if recipient else ""
    irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    confirmation = (
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>'
        if bare_confirmation
        else (
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData{recipient_attr} NotOnOrAfter="{_iso(not_on_or_after_ms)}"{irt}/>'
            "</saml:SubjectConfirmation>"
        )
    )
    expiry = "" if no_conditions_expiry else f' NotOnOrAfter="{_iso(not_on_or_after_ms)}"'
    xml = (
        f'<saml:Assertion xmlns:saml="{_SAML}" ID="{aid}" Version="2.0" IssueInstant="{_iso(0)}">'
        f"<saml:Issuer>{issuer or IDP_ENTITY}</saml:Issuer>"
        f"<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{name_id or 'alice-1234'}</saml:NameID>"
        f"{confirmation}</saml:Subject>"
        f'<saml:Conditions NotBefore="{_iso(-5000)}"{expiry}>'
        f"<saml:AudienceRestriction><saml:Audience>{audience or REALM}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
        f'<saml:AttributeStatement><saml:Attribute Name="{_CLAIMS}/nameidentifier"><saml:AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute>'
        f'<saml:Attribute Name="{_CLAIMS}/emailaddress" FriendlyName="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>'
        '<saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">'
        "<saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>"
        f"{extra_attributes}</saml:AttributeStatement>"
        f'<saml:AuthnStatement AuthnInstant="{_iso(-1000)}" SessionIndex="{session_index or "_session1"}">'
        "<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
        "</saml:Assertion>"
    )
    return {"xml": xml, "id": aid}


def sign_xml(xml: str, element_id: str, key: str = IDP_KEY, cert: str = IDP_CERT) -> str:
    """Enveloped RSA-SHA256 over exclusive c14n, inserted after Issuer. The same c14n the verifier uses."""
    root = etree.fromstring(xml.encode("utf-8"))
    target = root if root.get("ID") == element_id else root.find(f".//*[@ID='{element_id}']")
    if target is None:
        raise RuntimeError(f"no element ID {element_id}")
    issuer = None
    for child in list(target):
        if isinstance(child.tag, str) and etree.QName(child).localname == "Issuer":
            issuer = child
            break
    if issuer is None:
        raise RuntimeError("the signed element has no Issuer")
    signature = _signature_element(element_id, cert)
    index = list(target).index(issuer) + 1
    target.insert(index, signature)
    parent = signature.getparent()
    parent.remove(signature)
    try:
        digest = base64.b64encode(hashlib.sha256(_c14n(target, EXC_C14N, None)).digest()).decode("ascii")
    finally:
        parent.insert(index, signature)
    signature.find(f".//{{{_DS}}}DigestValue").text = digest
    signed_info = signature.find(f"{{{_DS}}}SignedInfo")
    info = _c14n(signed_info, EXC_C14N, None)
    private = serialization.load_pem_private_key(key.encode(), password=None)
    value = private.sign(info, padding.PKCS1v15(), hashes.SHA256())
    signature.find(f"{{{_DS}}}SignatureValue").text = base64.b64encode(value).decode("ascii")
    return etree.tostring(root, encoding="unicode")


def _signature_element(element_id: str, cert: str) -> etree._Element:
    nsmap = {"ds": _DS}
    signature = etree.Element(f"{{{_DS}}}Signature", nsmap=nsmap)
    signed_info = etree.SubElement(signature, f"{{{_DS}}}SignedInfo")
    etree.SubElement(signed_info, f"{{{_DS}}}CanonicalizationMethod").set("Algorithm", EXC_C14N)
    etree.SubElement(signed_info, f"{{{_DS}}}SignatureMethod").set("Algorithm", _RSA_SHA256)
    reference = etree.SubElement(signed_info, f"{{{_DS}}}Reference")
    reference.set("URI", f"#{element_id}")
    transforms = etree.SubElement(reference, f"{{{_DS}}}Transforms")
    etree.SubElement(transforms, f"{{{_DS}}}Transform").set("Algorithm", _ENVELOPED)
    etree.SubElement(transforms, f"{{{_DS}}}Transform").set("Algorithm", EXC_C14N)
    etree.SubElement(reference, f"{{{_DS}}}DigestMethod").set("Algorithm", _SHA256)
    etree.SubElement(reference, f"{{{_DS}}}DigestValue")
    key_info = etree.SubElement(signature, f"{{{_DS}}}KeyInfo")
    data = etree.SubElement(key_info, f"{{{_DS}}}X509Data")
    encoded = etree.SubElement(data, f"{{{_DS}}}X509Certificate")
    encoded.text = _pem_body(cert)
    etree.SubElement(signature, f"{{{_DS}}}SignatureValue")
    return signature


def signed_assertion(**options) -> dict:
    made = assertion_xml(**options)
    return {"xml": sign_xml(made["xml"], made["id"]), "id": made["id"]}


def _pkcs7(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def encrypt(plain: str, cipher: str = "aes-256-gcm", transport: str = "mgf1p", wrapper: str | None = "EncryptedAssertion") -> str:
    if cipher == "aes-256-gcm":
        key = os.urandom(32)
        iv = os.urandom(12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        blob = AESGCM(key).encrypt(iv, plain.encode("utf-8"), None)
        value = iv + blob
        alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    elif cipher == "aes-128-cbc":
        key = os.urandom(16)
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        padded = _pkcs7(plain.encode("utf-8"))
        value = iv + encryptor.update(padded) + encryptor.finalize()
        alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    else:
        raise ValueError(cipher)
    certificate = x509.load_pem_x509_certificate(RP_CERT.encode())
    public = certificate.public_key()
    if transport == "mgf1p":
        wrapped = public.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
        key_method = f'<xenc:EncryptionMethod Algorithm="{_XENC}rsa-oaep-mgf1p"/>'
    elif transport == "oaep256":
        wrapped = public.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        key_method = (
            f'<xenc:EncryptionMethod Algorithm="{_XENC11}rsa-oaep">'
            f'<ds:DigestMethod Algorithm="{_SHA256}"/>'
            f'<xenc11:MGF xmlns:xenc11="{_XENC11}" Algorithm="{_XENC11}mgf1sha256"/>'
            "</xenc:EncryptionMethod>"
        )
    else:
        raise ValueError(transport)
    data = (
        f'<xenc:EncryptedData xmlns:xenc="{_XENC}" Type="{_XENC}Element">'
        f'<xenc:EncryptionMethod Algorithm="{alg}"/>'
        f'<ds:KeyInfo xmlns:ds="{_DS}"><xenc:EncryptedKey>{key_method}'
        f"<xenc:CipherData><xenc:CipherValue>{base64.b64encode(wrapped).decode()}</xenc:CipherValue></xenc:CipherData>"
        "</xenc:EncryptedKey></ds:KeyInfo>"
        f"<xenc:CipherData><xenc:CipherValue>{base64.b64encode(value).decode()}</xenc:CipherValue></xenc:CipherData>"
        "</xenc:EncryptedData>"
    )
    if wrapper is None:
        return data
    return f'<saml:{wrapper} xmlns:saml="{_SAML}">{data}</saml:{wrapper}>'


def wresult(token: str | None = None, trust: str = "2005", applies_to: str | None = None, token_type: str | None = None, expires_ms: int = 3_600_000) -> str:
    ns = "http://docs.oasis-open.org/ws-sx/ws-trust/200512" if trust == "1.3" else "http://schemas.xmlsoap.org/ws/2005/02/trust"
    body = token if token is not None else signed_assertion()["xml"]
    wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    rstr = (
        f'<t:RequestSecurityTokenResponse xmlns:t="{ns}">'
        f'<t:Lifetime><wsu:Created xmlns:wsu="{wsu}">{_iso(0)}</wsu:Created>'
        f'<wsu:Expires xmlns:wsu="{wsu}">{_iso(expires_ms)}</wsu:Expires></t:Lifetime>'
        '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">'
        '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">'
        f"<wsa:Address>{applies_to or REALM}</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>"
        f"<t:RequestedSecurityToken>{body}</t:RequestedSecurityToken>"
        f"<t:TokenType>{token_type or 'urn:oasis:names:tc:SAML:2.0:assertion'}</t:TokenType>"
        f"<t:RequestType>{ns}/Issue</t:RequestType><t:KeyType>{ns}/Bearer</t:KeyType>"
        "</t:RequestSecurityTokenResponse>"
    )
    if trust == "1.3":
        return f'<t:RequestSecurityTokenResponseCollection xmlns:t="{ns}">{rstr}</t:RequestSecurityTokenResponseCollection>'
    return rstr


def saml11_assertion() -> str:
    return (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" '
        f'AssertionID="{_id()}" Issuer="{IDP_ENTITY}" IssueInstant="{_iso(0)}">'
        "<saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement>"
        "</saml:Assertion>"
    )
