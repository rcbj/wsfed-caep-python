# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Which local sessions belong to which person and which identity-provider session."""

from __future__ import annotations

from datetime import datetime, timezone

DEFAULT_SUBJECT_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
MAIL_ATTRIBUTES = (
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
)


class MemorySessionIndex:
    def __init__(self, max_entries: int = 100_000):
        self._sessions: dict[str, dict] = {}
        self._max = max_entries

    def add(self, session: dict) -> None:
        if len(self._sessions) >= self._max and session["local_id"] not in self._sessions:
            now = datetime.now(timezone.utc).timestamp()
            for key, value in list(self._sessions.items()):
                expires = value.get("expires_at")
                if expires is not None and expires.timestamp() <= now:
                    del self._sessions[key]
            while len(self._sessions) >= self._max:
                del self._sessions[next(iter(self._sessions))]
        stored = dict(session)
        if stored.get("email"):
            stored["email"] = stored["email"].lower()
        self._sessions[session["local_id"]] = stored

    def remove(self, local_id: str) -> None:
        self._sessions.pop(local_id, None)

    def _find(self, match) -> list[str]:
        now = datetime.now(timezone.utc).timestamp()
        out = []
        for key, value in list(self._sessions.items()):
            expires = value.get("expires_at")
            if expires is not None and expires.timestamp() <= now:
                del self._sessions[key]
                continue
            if match(value):
                out.append(key)
        return out

    def by_person(self, person: str) -> list[str]:
        return self._find(lambda session: session.get("person") == person)

    def by_email(self, email: str) -> list[str]:
        wanted = email.lower()
        return self._find(lambda session: session.get("email") == wanted)

    def by_idp_session(self, idp_session: str) -> list[str]:
        return self._find(lambda session: session.get("idp_session") == idp_session)


def tracked_from(local_id: str, login, subject_attribute: str | None = None, expires_at: datetime | None = None) -> dict:
    attribute = subject_attribute or DEFAULT_SUBJECT_ATTRIBUTE
    person = (getattr(login, "attributes", {}) or {}).get(attribute, [None])[0]
    email = next((getattr(login, "attributes", {}).get(name, [None])[0] for name in MAIL_ATTRIBUTES if getattr(login, "attributes", {}).get(name)), None)
    if email is None and getattr(login, "name_id_format", None) == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
        email = login.name_id
    session = {
        "local_id": local_id,
        "person": person,
        "email": email,
        "idp_session": getattr(login, "session_index", None),
    }
    expiry = expires_at if expires_at is not None else getattr(login, "session_not_on_or_after", None)
    if expiry is not None:
        session["expires_at"] = expiry
    return session
