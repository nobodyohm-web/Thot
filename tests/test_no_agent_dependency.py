"""The audit core must run with neither agent present.

Thot ships Hermes and Prime in the same repository now, and depends on
Hermes as a workspace member. What that must not cost is the property the
Engine port exists for: `thot audit` has to work on a locked-down machine
and in CI, where neither agent is installed and nothing may reach the
network. This file is the executable form of that promise."""

from pathlib import Path

FORBIDDEN = (
    "import hermes", "from hermes", "import prime", "from prime",
    "pi_coding_agent", "prime_agent",
)

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "thot"

# The deterministic core: analysis that must stay pure, offline and free.
# The llm/, session and ui layers are allowed to reach the network.
CORE_PACKAGES = (
    "codemap", "taint", "scope", "scoring", "store", "report", "analysis",
    "guard", "memory",
)

# A verdict store that lives on another machine is a network client by
# definition, like `llm/`. It is excluded from the *static* scan and held to
# a stricter promise instead: the transitive test below proves that opening
# the default memory never reaches it. Naming the file here is deliberate —
# a second network module inside the core would fail the scan and have to be
# argued for on its own.
NETWORK_BY_DESIGN = {"remote.py"}


def core_files():
    yield SOURCE_ROOT / "contracts.py"
    yield SOURCE_ROOT / "pipeline.py"
    for package in CORE_PACKAGES:
        for path in (SOURCE_ROOT / package).rglob("*.py"):
            if path.name not in NETWORK_BY_DESIGN:
                yield path


def test_core_imports_nothing_from_the_agents():
    offenders = []
    for path in SOURCE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN:
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == [], f"Le noyau doit rester autonome : {offenders}"


def test_the_core_audits_with_neither_agent_importable(tmp_path):
    """Blocked at import time, not merely absent — a chain of re-exports
    reaching `hermes` would raise here instead of passing quietly."""
    import subprocess
    import sys

    (tmp_path / "app.py").write_text(
        "import os, sys\n\ndef main():\n    os.system(sys.argv[1])\n"
    )

    program = (
        "import sys\n"
        "class Blocked:\n"
        "    def find_module(self, name, path=None):\n"
        "        if name.split('.')[0] in ('hermes', 'hermes_cli', 'agent',\n"
        "                                  'tools', 'prime'):\n"
        "            raise ImportError(name + ' is not available here')\n"
        "sys.meta_path.insert(0, Blocked())\n"
        "from thot.pipeline import run_audit\n"
        f"result = run_audit({str(tmp_path)!r}, require_authorization=False)\n"
        "print('findings', len(result.findings))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True,
        cwd=str(SOURCE_ROOT.parents[1]),
    )
    assert done.returncode == 0, done.stderr
    assert "findings 1" in done.stdout or "findings 2" in done.stdout


def test_core_makes_no_network_calls():
    """No HTTP client is imported anywhere in the deterministic core.

    Only the core is checked: `llm/` talks to model providers by design.

    Matches real import statements only: `catalog.py` legitimately contains
    strings like "requests.get" as detection patterns, and a naive substring
    scan would flag them.
    """
    network_modules = {"requests", "httpx", "urllib", "socket", "http"}
    offenders = []
    for path in core_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("import "):
                module = stripped[len("import "):].split()[0].split(".")[0]
            elif stripped.startswith("from "):
                module = stripped[len("from "):].split()[0].split(".")[0]
            else:
                continue
            if module in network_modules:
                offenders.append(f"{path.name}:{lineno} imports {module}")
    assert offenders == [], f"Le noyau ne doit faire aucun appel réseau : {offenders}"


def test_the_core_imports_cleanly_without_any_network_library():
    """Transitive proof, not a substring scan.

    The scan above only sees direct imports. This blocks every HTTP client at
    import time and loads the core anyway: if any core module reached one
    through a chain of re-exports, this would raise instead of pass.
    """
    import subprocess
    import sys

    program = (
        "import sys\n"
        "for name in ('httpx', 'requests', 'urllib.request', 'socket'):\n"
        "    sys.modules[name] = None\n"
        "import thot.pipeline\n"
        "import thot.analysis.probe\n"
        "import thot.engine.base\n"
        # The default verdict store must be buildable offline: the remote
        # backends are imported only when one is actually configured.
        "from thot.memory import build_memory\n"
        "build_memory(None, config={})\n"
        "print('ok')\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True,
        cwd=str(SOURCE_ROOT.parents[1]),
    )
    assert done.returncode == 0, done.stderr
    assert "ok" in done.stdout
