# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Enveloped XML Signature on a SAML 2.0 assertion. The signed bytes are what is read afterwards."""

from __future__ import annotations

import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

from wsfed_caep.errors import WsFedError
from wsfed_caep.xmlutil import NS, attr, child, children

EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
EXC_C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
EC_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"

SIGNATURE_ALGORITHMS = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "sha512",
}
DIGEST_ALGORITHMS = {
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
}
TRANSFORMS = {ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, C14N}
CANONICALIZATIONS = {EXC_C14N, EXC_C14N_COMMENTS, C14N}

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
_DIGESTLIB = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}


def is_signed(el: etree._Element) -> bool:
    return len(children(el, NS["ds"], "Signature")) > 0


def _algorithm_of(parent: etree._Element, local: str) -> str:
    element = child(parent, NS["ds"], local)
    return (attr(element, "Algorithm") or "") if element is not None else ""


def _prefixes(method: etree._Element | None) -> list[str] | None:
    if method is None:
        return None
    for node in method:
        if not isinstance(node.tag, str):
            continue
        q = etree.QName(node)
        if q.localname == "InclusiveNamespaces":
            raw = node.get("PrefixList") or ""
            return [part for part in raw.split() if part] or []
    return None


def _c14n(element: etree._Element, algorithm: str, prefixes: list[str] | None) -> bytes:
    exclusive = algorithm.startswith(EXC_C14N)
    comments = algorithm.endswith("WithComments")
    kwargs = {}
    if exclusive and prefixes:
        kwargs["inclusive_ns_prefixes"] = prefixes
    return etree.tostring(element, method="c14n", exclusive=exclusive, with_comments=comments, **kwargs)


def _b64(element: etree._Element | None) -> bytes:
    raw = "".join((element.text or "").split()) if element is not None else ""
    return base64.b64decode(raw)


def verify_signed(xml: str, el: etree._Element, certs: list[x509.Certificate], what: str) -> str | None:
    """Verify the enveloped signature on `el`. Returns the canonical XML that was signed, or None if unsigned."""
    del xml  # the element is read from the parsed document; exclusive c14n does not use the raw text
    sig_el = child(el, NS["ds"], "Signature")
    if sig_el is None:
        return None
    element_id = attr(el, "ID")
    if not element_id:
        raise WsFedError("signature", f"{what} is signed but has no ID for the signature to refer to")
    signed_info = child(sig_el, NS["ds"], "SignedInfo")
    if signed_info is None:
        raise WsFedError("signature", f"{what}'s signature has no SignedInfo")
    c14n_alg = _algorithm_of(signed_info, "CanonicalizationMethod")
    if c14n_alg not in CANONICALIZATIONS:
        raise WsFedError("signature", f"{what}'s signature uses the canonicalization {c14n_alg or '(none)'}, which is refused")
    sig_alg = _algorithm_of(signed_info, "SignatureMethod")
    hash_name = SIGNATURE_ALGORITHMS.get(sig_alg)
    if not hash_name:
        raise WsFedError("signature", f"{what}'s signature uses {sig_alg or '(none)'}, which is refused (SHA-1 and non-RSA algorithms are not accepted)")
    refs = children(signed_info, NS["ds"], "Reference")
    if len(refs) != 1:
        raise WsFedError("signature", f"{what}'s signature has {len(refs)} references; exactly one is accepted")
    ref = refs[0]
    if attr(ref, "URI") != f"#{element_id}":
        raise WsFedError("signature", f"{what}'s signature refers to {attr(ref, 'URI') or '(nothing)'}, not to {what} itself (#{element_id})")
    digest_alg = _algorithm_of(ref, "DigestMethod")
    if digest_alg not in DIGEST_ALGORITHMS:
        raise WsFedError("signature", f"{what}'s signature digests with {digest_alg or '(none)'}, which is refused")
    transforms = child(ref, NS["ds"], "Transforms")
    transform_els = children(transforms, NS["ds"], "Transform") if transforms is not None else []
    for transform in transform_els:
        alg = attr(transform, "Algorithm") or ""
        if alg not in TRANSFORMS:
            raise WsFedError("signature", f"{what}'s signature uses the transform {alg or '(none)'}, which is refused")
    if not certs:
        raise WsFedError("signature", f"no signing certificate is known for the identity provider, so {what} cannot be verified")

    ref_c14n = _reference_c14n(el, sig_el, transform_els)
    digest_value = child(ref, NS["ds"], "DigestValue")
    got = _DIGESTLIB[_digest_name(digest_alg)](ref_c14n).digest()
    if got != _b64(digest_value):
        raise WsFedError("signature", f"{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")

    info_bytes = _c14n(signed_info, c14n_alg, _prefixes(child(signed_info, NS["ds"], "CanonicalizationMethod")))
    signature = _b64(child(sig_el, NS["ds"], "SignatureValue"))
    reason = "the signature does not verify"
    for cert in certs:
        try:
            cert.public_key().verify(signature, info_bytes, padding.PKCS1v15(), _HASHES[hash_name]())
            return ref_c14n.decode("utf-8")
        except WsFedError:
            raise
        except Exception as err:
            reason = str(err)
    raise WsFedError("signature", f"{what}'s signature does not verify against the identity provider's certificate: {reason}")


def _digest_name(algorithm: str) -> str:
    return {"http://www.w3.org/2001/04/xmlenc#sha256": "sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384", "http://www.w3.org/2001/04/xmlenc#sha512": "sha512"}[algorithm]


def _reference_c14n(element: etree._Element, signature: etree._Element, transforms: list[etree._Element]) -> bytes:
    algorithm = EXC_C14N
    prefixes: list[str] | None = None
    enveloped = False
    for transform in transforms:
        alg = attr(transform, "Algorithm") or ""
        if alg == ENVELOPED:
            enveloped = True
        elif alg in CANONICALIZATIONS:
            algorithm = alg
            prefixes = _prefixes(transform)
    parent = signature.getparent()
    index = list(parent).index(signature) if parent is not None else None
    if enveloped and parent is not None:
        parent.remove(signature)
    try:
        return _c14n(element, algorithm, prefixes)
    finally:
        if enveloped and parent is not None and index is not None and signature.getparent() is None:
            parent.insert(index, signature)
