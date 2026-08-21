"""Plugins: extend Thot without patching it.

Adapted from Hermes Agent's PluginManager (MIT, Copyright (c) 2025 Nous
Research), narrowed to what auditing needs.
"""

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
    "invoke_hook",
    "load_from",
]
