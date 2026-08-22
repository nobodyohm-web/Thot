

# --- une absence de code n'est pas une preuve d'innocence ------------------
#
# `excerpt` rendait une chaîne vide quand le fichier était illisible, et les
# trois constructeurs de tâche l'inséraient sous l'intitulé « Code : ». Un
# agent à qui l'on demande si le candidat est « réellement exploitable dans ce
# code, tel qu'il est écrit », et qui ne voit aucun code, peut répondre
# `refuted` — et une réfutation est mémorisée pour de bon. C'est le scénario
# que la docstring de `_scope_note` raconte comme la pire issue possible,
# atteint par un autre chemin.


def _ref(path="perdu.py", line=3):
    from thot.contracts import CodeRef

    return CodeRef(path=path, line=line, symbol="s", ast_hash="h")


def test_an_unreadable_file_says_so_instead_of_nothing(tmp_path):
    from thot.analysis.probe import excerpt

    text = excerpt(tmp_path, _ref())

    assert text.strip(), "un extrait vide se lit comme du code sans danger"
    assert "perdu.py" in text
    assert "illisible" in text.lower()


def test_the_marker_tells_the_agent_not_to_conclude(tmp_path):
    from thot.analysis.probe import excerpt

    assert "conclus" in excerpt(tmp_path, _ref()).lower()


def test_a_readable_file_is_unchanged(tmp_path):
    from thot.analysis.probe import excerpt

    (tmp_path / "a.py").write_text("un\ndeux\ntrois\n", encoding="utf-8")

    text = excerpt(tmp_path, _ref(path="a.py", line=2))

    assert "deux" in text
    assert "illisible" not in text.lower()


def test_every_task_carries_the_marker_when_the_file_is_gone(tmp_path):
    """All three builders embed `excerpt`; none may hand over a blank."""
    from thot.analysis.probe import _probe_task, _refute_task, _review_task
    from thot.contracts import Confidence, Finding, Severity

    finding = Finding(
        id="x", rule="sink.eval", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE, location=_ref(),
        failure_scenario="une entrée atteint eval",
    )

    built = [
        _probe_task(tmp_path, finding),
        _refute_task(tmp_path, finding, "une entrée atteint eval"),
        _review_task(tmp_path, finding, "une entrée atteint eval",
                     "réfuté sans preuve"),
    ]
    for task in built:
        assert "illisible" in task.context.lower(), task.id


def test_two_calls_on_one_line_reach_the_agent_as_two_different_tasks(tmp_path):
    """`site` decides identity; it has to reach the one who judges.

    Both tasks used to carry `Emplacement : a.ts:219` verbatim, so an agent
    judging the second saw exactly what it had seen for the first — for two
    calls that `compute_id` deliberately keeps apart.
    """
    from thot.analysis.probe import _probe_task
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    def at(site):
        location = CodeRef(path="a.ts", line=219, symbol="load", ast_hash="h",
                           site=site)
        return Finding(
            id=Finding.compute_id("sink.js.path", location),
            rule="sink.js.path", severity=Severity.LOW,
            confidence=Confidence.PLAUSIBLE, location=location,
            failure_scenario="une valeur atteint join",
        )

    first = _probe_task(tmp_path, at("join#0")).context
    second = _probe_task(tmp_path, at("join#1")).context

    assert "join#0" in first and "join#1" in second
    assert first != second, "deux appels, un seul énoncé"
