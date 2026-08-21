"""Domain exceptions."""

from __future__ import annotations


class ThotError(Exception):
    """Base class for every Thot domain error."""


class AuthorizationError(ThotError):
    """Raised when the audit is not authorized for the target repository."""


class ScopeError(ThotError):
    """Raised when the target repository cannot be scoped."""
