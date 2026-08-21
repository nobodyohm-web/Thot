import textwrap
from pathlib import Path

import pytest


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
