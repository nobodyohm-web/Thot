"""A live Python namespace, in a process Thot controls.

Prime Agent's thesis, ported: an agent that writes Python into a kernel
whose variables survive between cells beats one that spends a turn per
tool call. Thot's constraint added: audited code never runs in Thot's own
process, so the namespace is always a subprocess — and inside the
container when a sandbox is configured.
"""

from thot.kernel.client import (
    DEFAULT_TIMEOUT,
    MAX_CALLS_PER_CELL,
    MAX_CALLS_PER_KERNEL,
    Kernel,
    KernelError,
)
from thot.kernel.protocol import Outcome

__all__ = [
    "DEFAULT_TIMEOUT",
    "Kernel",
    "KernelError",
    "MAX_CALLS_PER_CELL",
    "MAX_CALLS_PER_KERNEL",
    "Outcome",
]
