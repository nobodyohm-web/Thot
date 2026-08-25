"""Domain exceptions."""

from __future__ import annotations


class ThotError(Exception):
    """Base class for every Thot domain error."""


class AuthorizationError(ThotError):
    """Raised when the audit is not authorized for the target repository."""


class ScopeError(ThotError):
    """Raised when the target repository cannot be scoped."""


class StateError(ThotError):
    """Raised when one of ~/.thot's databases will not open.

    Its own class rather than a bare ThotError: the CLI answers EXIT_ERROR
    for it, never EXIT_USAGE — nobody mistyped anything — and never the
    uncaught-exception 1, which is EXIT_FINDINGS.
    """
