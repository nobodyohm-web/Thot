"""The core must never depend on Prime Agent or Hermes — that is the whole
point of the Engine port. This test is the executable form of that promise."""

from pathlib import Path

FORBIDDEN = (
    "import hermes", "from hermes", "import prime", "from prime",
    "pi_coding_agent", "prime_agent",
)

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "thot"


def test_core_imports_nothing_from_the_agents():
    offenders = []
    for path in SOURCE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN:
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == [], f"Le noyau doit rester autonome : {offenders}"


def test_declared_dependencies_stay_minimal():
    pyproject = (SOURCE_ROOT.parents[1] / "pyproject.toml").read_text()
    for forbidden in ("hermes", "prime-agent", "anthropic", "openai"):
        assert forbidden not in pyproject


def test_core_makes_no_network_calls():
    """No HTTP client is *imported* anywhere in the deterministic core.

    Matches real import statements only: `catalog.py` legitimately contains
    strings like "requests.get" as detection patterns, and a naive substring
    scan would flag them.
    """
    network_modules = {"requests", "httpx", "urllib", "socket", "http"}
    offenders = []
    for path in SOURCE_ROOT.rglob("*.py"):
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
