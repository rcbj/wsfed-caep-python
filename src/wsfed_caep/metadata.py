# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Federation metadata: read the identity provider, write this relying party (WS-Federation 1.2 section 3)."""

from __future__ import annotations

from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from wsfed_caep.errors import WsFedError
from wsfed_caep.xmlutil import (
    NS,
    SAML2_TOKEN_TYPES,
    attr,
    children,
    descendants,
    escape_xml,
    is_el,
    parse_xml,
    pem_body,
    text,
    to_pem,
    wsa_addresses,
    xsi_type,
)

ENCRYPTION_METHODS = [
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
]


class IdpMetadata:
    def __init__(self, entity_id: str, passive_requestor_endpoint: str, token_types_offered: list[str], signing_certificates: list[x509.Certificate]):
        self.entity_id = entity_id
        self.passive_requestor_endpoint = passive_requestor_endpoint
        self.token_types_offered = token_types_offered
        self.signing_certificates = signing_certificates


def _is_sts_role(el) -> bool:
    if not is_el(el, NS["md"], "RoleDescriptor"):
        return False
    kind = xsi_type(el)
    return bool(kind and kind["ns"] == NS["fed"] and kind["local"] == "SecurityTokenServiceType")


def _certificates_of(role, use: str) -> list[x509.Certificate]:
    out: list[x509.Certificate] = []
    for descriptor in children(role, NS["md"], "KeyDescriptor"):
        declared = attr(descriptor, "use")
        if declared and declared != use:
            continue
        for data in descendants(descriptor, NS["ds"], "X509Data"):
            first = children(data, NS["ds"], "X509Certificate")
            if not first:
                continue
            try:
                out.append(x509.load_pem_x509_certificate(to_pem(text(first[0])).encode()))
            except Exception as err:
                raise WsFedError("metadata", f"a {use} certificate in the identity provider's metadata cannot be read", err) from err
    return out


def _addresses(role, local: str) -> list[str]:
    return [address for endpoint in children(role, NS["fed"], local) for address in wsa_addresses(endpoint)]


def read_idp_metadata(xml: str, entity_id: str | None = None) -> IdpMetadata:
    root = parse_xml(xml, "the identity provider metadata")

    def has_sts(element) -> bool:
        return any(_is_sts_role(role) for role in children(element, NS["md"], "RoleDescriptor"))

    entity = None
    if is_el(root, NS["md"], "EntityDescriptor"):
        entity = root
    elif is_el(root, NS["md"], "EntitiesDescriptor"):
        all_entities = [item for item in descendants(root, NS["md"], "EntityDescriptor") if has_sts(item)]
        if entity_id:
            entity = next((item for item in all_entities if attr(item, "entityID") == entity_id), None)
        elif len(all_entities) == 1:
            entity = all_entities[0]
        if entity is None:
            if entity_id:
                raise WsFedError("metadata", f"the metadata aggregate has no WS-Federation identity provider {entity_id}")
            raise WsFedError("metadata", f"the metadata aggregate holds {len(all_entities)} WS-Federation identity providers; name one with idpEntityId")
    else:
        raise WsFedError("metadata", "the identity provider metadata is not an EntityDescriptor")
    identifier = attr(entity, "entityID")
    if not identifier:
        raise WsFedError("metadata", "the identity provider metadata has no entityID")
    if entity_id and identifier != entity_id:
        raise WsFedError("metadata", f"the metadata describes {identifier}, not {entity_id}")
    role = next((item for item in children(entity, NS["md"], "RoleDescriptor") if _is_sts_role(item)), None)
    if role is None:
        raise WsFedError("metadata", f"{identifier}'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider")
    passive = _addresses(role, "PassiveRequestorEndpoint")
    if not passive:
        raise WsFedError("metadata", f"{identifier}'s metadata names no PassiveRequestorEndpoint")
    endpoint = passive[0]
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("https", "http"):
        raise WsFedError("metadata", f"{identifier}'s PassiveRequestorEndpoint {endpoint} is not an http(s) URL")
    offered = []
    for types in children(role, NS["fed"], "TokenTypesOffered"):
        for token in children(types, NS["fed"], "TokenType"):
            uri = attr(token, "Uri") or ""
            if uri:
                offered.append(uri)
    if offered and not any(token in SAML2_TOKEN_TYPES for token in offered):
        raise WsFedError("metadata", f"{identifier} offers no SAML 2.0 token (it offers {', '.join(offered)})")
    signing = _certificates_of(role, "signing")
    if not signing:
        idp = children(entity, NS["md"], "IDPSSODescriptor")
        if idp:
            signing = _certificates_of(idp[0], "signing")
    if not signing:
        raise WsFedError("metadata", f"{identifier}'s metadata names no signing certificate")
    return IdpMetadata(identifier, endpoint, offered, signing)


def write_rp_metadata(realm: str, reply_url: str, certificate: x509.Certificate | None = None) -> str:
    key = ""
    if certificate is not None:
        body = pem_body(certificate.public_bytes(serialization.Encoding.PEM).decode())
        methods = "".join(f'\n      <md:EncryptionMethod Algorithm="{method}"/>' for method in ENCRYPTION_METHODS)
        key = (
            '    <md:KeyDescriptor use="encryption">\n'
            f"      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>{methods}\n"
            "    </md:KeyDescriptor>\n"
        )

    def endpoint(local: str, address: str) -> str:
        return f"    <fed:{local}><wsa:EndpointReference><wsa:Address>{escape_xml(address)}</wsa:Address></wsa:EndpointReference></fed:{local}>"

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<md:EntityDescriptor xmlns:md="{NS["md"]}" xmlns:ds="{NS["ds"]}" xmlns:fed="{NS["fed"]}" '
        f'xmlns:wsa="{NS["wsa"]}" xmlns:xsi="{NS["xsi"]}" entityID="{escape_xml(realm)}">\n'
        f'  <md:RoleDescriptor xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="{NS["fed"]}">\n'
        f"{key}    <fed:TokenTypesOffered><fed:TokenType Uri=\"{SAML2_TOKEN_TYPES[0]}\"/></fed:TokenTypesOffered>\n"
        f"    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>{escape_xml(realm)}</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n"
        f"{endpoint('ApplicationServiceEndpoint', reply_url)}\n"
        f"{endpoint('SingleSignOutNotificationEndpoint', reply_url)}\n"
        f"{endpoint('PassiveRequestorEndpoint', reply_url)}\n"
        "  </md:RoleDescriptor>\n"
        "</md:EntityDescriptor>\n"
    )
