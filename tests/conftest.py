import textwrap
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path_factory, monkeypatch):
    """No test may read or write the real ~/.thot, ~/.hermes or ~/.prime.

    Autouse on purpose: a suite that touches the user's own sessions,
    verdicts or schedule is a suite that can destroy their work, and the
    one test that forgets the fixture is the one that does it.

    The two agent homes are here for a second reason as well. Since the
    briefing folds in what Hermes and Prime remember, a suite reading the
    real ones would pass or fail according to notes the developer happened
    to have written that week.
    """
    home = tmp_path_factory.mktemp("thot-home")
    monkeypatch.setenv("THOT_HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path_factory.mktemp("hermes-home")))
    monkeypatch.setenv(
        "PRIME_AGENT_CONFIG_DIR", str(tmp_path_factory.mktemp("prime-home"))
    )
    return home


@pytest.fixture
def toy_repo(tmp_path: Path) -> Path:
    """A small Python repo with one real taint path from argv to os.system."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        textwrap.dedent(
            """
            import os
            import sys


            def read_user_input():
                return sys.argv[1]


            def run_command(cmd):
                os.system(cmd)


            def unreachable_helper(cmd):
                os.system(cmd)


            def main():
                target = read_user_input()
                run_command(target)
            """
        ).strip()
    )
    (tmp_path / "src" / "safe.py").write_text(
        textwrap.dedent(
            """
            def add(a, b):
                return a + b
            """
        ).strip()
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.py").write_text("import os\nos.system('x')\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "toy"\n')
    return tmp_path
