"""The first-run screen, when there is nobody at the keyboard.

`thot` with a closed stdin is the shape a CI job or a `nohup` takes. It used
to raise RuntimeError: input(): lost sys.stdin — a traceback, on the very
first screen the tool ever shows.
"""

from __future__ import annotations

import pytest

from thot import onboarding


def _raising(exception):
    def answer(prompt=""):
        raise exception

    return answer


@pytest.mark.parametrize(
    "exception", [EOFError(), KeyboardInterrupt(), RuntimeError("input(): lost sys.stdin")]
)
def test_no_one_at_the_keyboard_is_not_an_error(exception, monkeypatch):
    monkeypatch.setattr("builtins.input", _raising(exception))

    assert onboarding._ask("[1-4]") == ""


def test_a_secret_nobody_can_type_is_empty_not_fatal(monkeypatch):
    monkeypatch.setattr("getpass.getpass",
                        _raising(RuntimeError("lost sys.stdin")))

    assert onboarding._secret("clé API") == ""


# --- the fusion is what Thot is, so it is the first thing offered ---------


def _agents(monkeypatch, *names):
    monkeypatch.setattr("thot.engine.factory.available_engines",
                        lambda: list(names))


def test_the_fusion_is_offered_first_when_both_agents_are_there(monkeypatch, capsys):
    """Thot is the fusion of Hermes and Prime. A first-run screen that
    offered every model *except* the two it is made of asked the user to
    configure their way out of the program's own premise."""
    _agents(monkeypatch, "hermes", "prime", "claude")
    monkeypatch.setattr(onboarding, "_ask", lambda *a, **k: "")

    config = onboarding.first_run()
    screen = capsys.readouterr().out

    assert "Fusion" in screen
    assert config is not None and config.provider == "fusion"


def test_one_agent_alone_is_offered_as_itself(monkeypatch, capsys):
    _agents(monkeypatch, "prime")
    monkeypatch.setattr(onboarding, "_ask", lambda *a, **k: "")

    config = onboarding.first_run()

    assert config is not None and config.provider == "prime"
    assert "Prime" in capsys.readouterr().out


def test_without_either_agent_the_screen_is_what_it_always_was(monkeypatch, capsys):
    _agents(monkeypatch)
    monkeypatch.setattr(onboarding, "_ask", lambda *a, **k: "9")

    onboarding.first_run()
    screen = capsys.readouterr().out

    assert "Fusion" not in screen
    assert "Claude" in screen and "OpenAI" in screen
