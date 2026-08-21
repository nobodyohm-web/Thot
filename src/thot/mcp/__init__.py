"""The MCP catalogue Thot inherited from Hermes Agent.

Twenty vetted servers, described once and installed through the official
`claude` CLI — which already owns OAuth, token refresh, and the health
check. Thot curates; it does not reimplement an OAuth client it would get
wrong.
"""

from thot.mcp.catalog import (
    Server,
    as_json,
    catalog,
    catalog_dir,
    find,
    install,
    installed,
    remove,
)

__all__ = [
    "Server",
    "as_json",
    "catalog",
    "catalog_dir",
    "find",
    "install",
    "installed",
    "remove",
]
