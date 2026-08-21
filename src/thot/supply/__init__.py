"""Supply-chain audit: what this repository depends on, and what is known about it."""

from thot.supply.audit import SupplyResult, audit_dependencies
from thot.supply.discover import Component, discover, from_mcp_command
from thot.supply.osv import Advisory, OsvClient

__all__ = [
    "Advisory",
    "Component",
    "OsvClient",
    "SupplyResult",
    "audit_dependencies",
    "discover",
    "from_mcp_command",
]
