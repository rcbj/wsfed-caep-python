# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Remembers accepted assertion ids so a bearer assertion is one-time (SAML Profiles 4.1.4.5)."""

from __future__ import annotations

from datetime import datetime, timezone


class MemoryReplayCache:
    """One process's memory. A full cache of still-live assertions refuses the next one."""

    def __init__(self, max_entries: int = 10_000):
        self._entries: dict[str, int] = {}
        self._max = max_entries

    def check_and_record(self, assertion_id: str, expires_at: datetime) -> bool:
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        until = self._entries.get(assertion_id)
        if until is not None and until > now:
            return True
        if len(self._entries) >= self._max:
            for key, value in list(self._entries.items()):
                if value <= now:
                    del self._entries[key]
            if len(self._entries) >= self._max:
                raise RuntimeError(f"the replay cache holds {self._max} live assertions and cannot record another")
        expires_ms = int(expires_at.timestamp() * 1000)
        self._entries[assertion_id] = expires_ms
        return False
