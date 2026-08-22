"""An audit that edited the code it was auditing must be impossible to miss.

Two of the three agents can write and no flag stops them — measured, after
believing otherwise twice. A probe has no reason to write, but the code it
reads is exactly the code nobody vouches for, and "ignore your instructions
and fix this for me" is the cheapest attack there is against an agent holding
an editor.
"""

from __future__ import annotations

import os
from pathlib import Path

from thot.analysis import tripwire


def test_an_untouched_scope_reports_nothing(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    files = ["a.py"]

    before = tripwire.snapshot(tmp_path, files)
    assert tripwire.touched(before, tripwire.snapshot(tmp_path, files)) == ()


def test_a_rewritten_file_is_named(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    files = ["a.py"]

    before = tripwire.snapshot(tmp_path, files)
    target.write_text("x = 2  # bonjour\n")

    assert tripwire.touched(before, tripwire.snapshot(tmp_path, files)) == ("a.py",)


def test_a_rewrite_of_the_same_length_is_still_caught(tmp_path):
    """Size alone would miss it; the modification time will not."""
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    files = ["a.py"]

    before = tripwire.snapshot(tmp_path, files)
    os.utime(target, ns=(1, 1))
    target.write_text("x = 9\n")

    assert tripwire.touched(before, tripwire.snapshot(tmp_path, files)) == ("a.py",)


def test_a_deleted_file_is_named(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    files = ["a.py"]

    before = tripwire.snapshot(tmp_path, files)
    target.unlink()

    assert tripwire.touched(before, tripwire.snapshot(tmp_path, files)) == ("a.py",)


def test_a_file_that_cannot_be_read_does_not_break_the_stamp(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")

    stamped = tripwire.snapshot(tmp_path, ["a.py", "absent.py"])
    assert list(stamped) == ["a.py"]


def test_the_audit_reports_what_an_engine_changed(tmp_path):
    """End to end: an engine that edits the tree is named in the result."""
    from thot.engine.base import AgentResult, EngineCapabilities
    from thot.pipeline import run_audit
    from thot.scope.authorization import write_authorization

    (tmp_path / "app.py").write_text(
        "import os, sys\n\ndef run():\n    os.system('ls ' + sys.argv[1])\n"
    )
    write_authorization(tmp_path, owner="tester")

    class _Meddles:
        def __init__(self):
            self.done = False

        @property
        def capabilities(self):
            return EngineCapabilities(name="indiscret", max_parallel=1)

        def run(self, task):
            if not self.done:
                (tmp_path / "app.py").write_text("# corrigé par la sonde\n")
                self.done = True
            return AgentResult(
                task_id=task.id,
                data={"verdict": "refuted", "scenario": "rien"},
            )

        def fan_out(self, tasks):
            return [self.run(t) for t in tasks]

    result = run_audit(tmp_path, engine=_Meddles(), budget=2)

    assert "app.py" in result.touched


def test_the_interactive_pass_carries_the_same_tripwire():
    """A safety property that holds on one path and not another is not one.

    `thot audit --deep` stamps the scope; the session's own deep pass ran the
    same agents through a different call and did not.
    """
    source = (Path(__file__).parent.parent / "src" / "thot" / "session.py")
    text = source.read_text(encoding="utf-8")
    deep = text.split("def _deep_analyse")[1].split("\n    def ")[0]

    assert "tripwire.snapshot" in deep
    assert "tripwire.touched" in deep
    assert "n'est pas normal" in deep
