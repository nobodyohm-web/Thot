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
    """No HTTP client anywhere in the deterministic core."""
    offenders = []
    for path in SOURCE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in ("import requests", "import httpx", "urllib.request", "socket."):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == [], f"Le noyau ne doit faire aucun appel réseau : {offenders}"
