"""Plugins: extend Thot without patching it.

Adapted from Hermes Agent's PluginManager (MIT, Copyright (c) 2025 Nous
Research), narrowed to what auditing needs.
"""

from thot.plugins.notify import (
    annotate_findings,
    forget_plugins,
    notify_verdict,
    notify_write,
)
from thot.plugins.loader import (
    VALID_HOOKS,
    Plugin,
    bundled,
    discover,
    invoke_hook,
    load_from,
)

__all__ = [
    "VALID_HOOKS",
    "Plugin",
    "bundled",
    "discover",
    "annotate_findings",
    "forget_plugins",
    "invoke_hook",
    "notify_verdict",
    "notify_write",
    "load_from",
]
