# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""XML read and written by this library. A DOCTYPE is refused before the parser sees it."""

from __future__ import annotations

import re

from lxml import etree

from wsfed_caep.errors import WsFedError

NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml1": "urn:oasis:names:tc:SAML:1.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "fed": "http://docs.oasis-open.org/wsfed/federation/200706",
    "trust2005": "http://schemas.xmlsoap.org/ws/2005/02/trust",
    "trust13": "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
    "wsa": "http://www.w3.org/2005/08/addressing",
    "wsa2004": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsp": "http://schemas.xmlsoap.org/ws/2004/09/policy",
    "wsp15": "http://www.w3.org/ns/ws-policy",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
}

SAML2_TOKEN_TYPES = (
    "urn:oasis:names:tc:SAML:2.0:assertion",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
)
SAML2_TOKEN_TYPE = "urn:oasis:names:tc:SAML:2.0:assertion"
CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
ID_NAMES = {"ID", "Id", "id"}

_DOCTYPE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


def parse_xml(text: str, what: str = "the message") -> etree._Element:
    if _DOCTYPE.search(text):
        raise WsFedError("xml", f"{what} carries a DOCTYPE or an entity declaration, which WS-Federation never needs")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_blank_text=False)
    try:
        data = text.encode("utf-8") if isinstance(text, str) else text
        root = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as err:
        raise WsFedError("xml", f"{what} is not well-formed XML: {err}") from err
    if root is None:
        raise WsFedError("xml", f"{what} is not well-formed XML: no document element")
    return root


def serialize(node: etree._Element) -> str:
    return etree.tostring(node, encoding="unicode")


def qname(el: etree._Element) -> etree.QName:
    return etree.QName(el)


def children(el: etree._Element, ns: str, local: str) -> list[etree._Element]:
    out = []
    for node in el:
        if not isinstance(node.tag, str):
            continue
        q = etree.QName(node)
        if q.namespace == ns and q.localname == local:
            out.append(node)
    return out


def element_children(el: etree._Element) -> list[etree._Element]:
    return [node for node in el if isinstance(node.tag, str)]


def child(el: etree._Element, ns: str, local: str) -> etree._Element | None:
    found = children(el, ns, local)
    if len(found) > 1:
        raise WsFedError("validation", f"<{qname(el).localname}> has more than one <{local}>")
    return found[0] if found else None


def descendants(el: etree._Element, ns: str, local: str) -> list[etree._Element]:
    return el.findall(f".//{{{ns}}}{local}")


def text_content(el: etree._Element | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext())


def text(el: etree._Element | None) -> str:
    return text_content(el).strip()


def attr(el: etree._Element, name: str) -> str | None:
    if name in el.attrib:
        return el.attrib.get(name)
    return None


def wsa_addresses(el: etree._Element) -> list[str]:
    found = [*descendants(el, NS["wsa"], "Address"), *descendants(el, NS["wsa2004"], "Address")]
    return [value for value in (text(node) for node in found) if value]


def is_el(el: etree._Element | None, ns: str, local: str) -> bool:
    if el is None or not isinstance(el.tag, str):
        return False
    q = etree.QName(el)
    return q.namespace == ns and q.localname == local


def assert_unique_ids(root: etree._Element) -> None:
    """Refuse a document where two elements share an ID. wsu:Id counts: local name, any namespace."""
    seen: set[str] = set()
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for name, value in el.attrib.items():
            local = etree.QName(name).localname
            if local not in ID_NAMES or not value:
                continue
            if value in seen:
                raise WsFedError("signature", f"two elements carry the ID {value}")
            seen.add(value)


def escape_xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def pem_body(pem: str) -> str:
    return re.sub(r"-----(BEGIN|END) CERTIFICATE-----", "", pem).replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")


def to_pem(b64: str) -> str:
    body = re.sub(r"\s+", "", b64)
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def lookup_namespace(el: etree._Element, prefix: str | None) -> str | None:
    current: etree._Element | None = el
    while current is not None:
        nsmap = current.nsmap
        if prefix in nsmap:
            return nsmap[prefix]
        current = current.getparent()
    return None


def xsi_type(el: etree._Element) -> dict[str, str | None] | None:
    value = el.get(f"{{{NS['xsi']}}}type")
    if not value:
        return None
    if ":" in value:
        prefix, local = value.split(":", 1)
        prefix = prefix.strip()
    else:
        prefix, local = None, value
    return {"ns": lookup_namespace(el, prefix), "local": local.strip()}
