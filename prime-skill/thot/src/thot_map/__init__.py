"""Thot's map, reachable from Prime's kernel.

Prime connects to an MCP server over streamable HTTP and nothing else:
`mcp-manager.js` drops every configured entry whose `type` is not `"http"`,
and the Python runtime has no stdio transport at all. So this is how Thot
gets in — the same shape as the Linear and Notion integrations Prime ships,
pointed at a loopback server instead of a hosted one.

Neither the URL nor the token is written here. `_resolve_config` asks the
host, which reads `mcpServers.thot` from `settings.json`, and the credential
comes from `auth.json` under `mcp:thot`. Both are written by
`thot fusion wire`, so moving the port is a rewiring and not an edit to this
file.
"""

from __future__ import annotations

from rlm import McpIntegration

__all__ = ["Thot", "thot"]


class Thot(McpIntegration):
    server = "thot"
    # The fallback for a host that cannot answer `mcp.config` — the wiring
    # normally overrides it with whatever port the server was given.
    url = "http://127.0.0.1:8787/mcp"
    # Read only if `auth.json` holds nothing: the wiring prefers the
    # credential file, and this leaves a way to run without touching it.
    bearer_token_env = "THOT_MCP_TOKEN"


thot = Thot()


# Names the kernel bootstrap probes to decide whether a module is a callable
# skill. Forwarding them would make `getattr(module, "run")` return an MCP tool
# stub, the module would be wrapped as callable, and `await thot_map.<tool>()`
# would stop dispatching.
_RESERVED = {"run", "__wrapped__", "__call__"}


def __getattr__(name: str):
    # So `import thot_map; await thot_map.find_symbol(...)` works without
    # reaching through the instance.
    if name.startswith("_") or name in _RESERVED:
        raise AttributeError(name)
    return getattr(thot, name)
