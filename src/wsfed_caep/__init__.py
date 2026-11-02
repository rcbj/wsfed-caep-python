# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Server-side WS-Federation relying party that accepts SAML 2.0 assertions, and a CAEP and RISC receiver.

``signals: false`` turns the receiver off. The relying party does not start one itself. The default is
on. Sign-in does not change, because WS-Federation does not send OAuth scopes. The flag only gates the
receiver and the requirement for transmitter metadata.

    from wsfed_caep import RelyingParty

    rp = RelyingParty.from_file("wsfed.json")
    request = rp.login(relay_state="/")
    who = rp.handle_reply({"method": method, "url": url, "body": body}, request_id)
"""

from wsfed_caep.config import read_config_file, resolve_config
from wsfed_caep.errors import WsFedError
from wsfed_caep.metadata import IdpMetadata
from wsfed_caep.relying_party import RelyingParty
from wsfed_caep.replay import MemoryReplayCache
from wsfed_caep.ssf import (
    CAEP_EVENTS,
    DEFAULT_ENDING_EVENTS,
    DEFAULT_EVENTS_REQUESTED,
    EVENT,
    RISC_EVENTS,
    MemorySessionIndex,
    SignalsReceiver,
    subject_of,
    tracked_from,
)
from wsfed_caep.ssf.session_index import DEFAULT_SUBJECT_ATTRIBUTE
from wsfed_caep.token import WsFedLogin
from wsfed_caep.x509util import KeyPair, create_self_signed_key_pair

__version__ = "0.1.0"

__all__ = [
    "CAEP_EVENTS",
    "DEFAULT_ENDING_EVENTS",
    "DEFAULT_EVENTS_REQUESTED",
    "DEFAULT_SUBJECT_ATTRIBUTE",
    "EVENT",
    "IdpMetadata",
    "KeyPair",
    "MemoryReplayCache",
    "MemorySessionIndex",
    "RISC_EVENTS",
    "RelyingParty",
    "SignalsReceiver",
    "WsFedError",
    "WsFedLogin",
    "create_self_signed_key_pair",
    "read_config_file",
    "resolve_config",
    "subject_of",
    "tracked_from",
]
