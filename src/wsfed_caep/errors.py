# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Failures this library reports. Applications treat them as a failed sign-in and log the code."""


class WsFedError(Exception):
    """A config, metadata, message, xml, signature, validation, replay, decryption, or ssf failure."""

    def __init__(self, code: str, message: str, cause: BaseException | None = None):
        super().__init__(message)
        self.code = code
        if cause is not None:
            self.__cause__ = cause
