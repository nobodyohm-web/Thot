"""`python -m thot` — the same entry point as the `thot` command.

Without this, `python -m thot.cli` imported the module, defined `main`, never
called it, and exited 0 saying nothing. A caller that shells out to Thot in
an environment where the console script is not on the PATH — a subprocess
launched from inside Thot itself, which is exactly what `evolve.thot_metrics`
does — read that silence as an empty audit.
"""

from __future__ import annotations

from thot.cli import run

if __name__ == "__main__":
    run()
