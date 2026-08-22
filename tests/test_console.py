

# --- un chemin qu'on ne peut pas lire ne sert à rien -----------------------
#
# La colonne « Emplacement » n'avait aucun réglage de débordement, donc Rich
# la tronquait : `packages/codi…`. La colonne « Symbole » juste à côté, elle,
# se repliait. Le champ dont on a besoin pour ouvrir le fichier était le seul
# coupé, et le symbole — qu'on devine souvent depuis le chemin — était
# préservé. Mesuré sur Prime, la moitié des lignes du rapport était concernée.


def _deep_finding():
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    return Finding(
        id="f1", rule="pattern.child_process_exec", severity=Severity.HIGH,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(
            path="packages/coding-agent/src/tools/terminal/session-runner.ts",
            line=412, symbol=None, ast_hash="h",
        ),
        failure_scenario="une valeur atteint exec",
    )


def test_a_deep_path_is_readable_in_the_table():
    import io

    from rich.console import Console

    from thot import console as module

    from types import SimpleNamespace

    from thot.scope.detect import ScopeManifest

    buffer = io.StringIO()
    narrow = Console(file=buffer, width=100, force_terminal=False)
    real = module.console
    module.console = narrow
    try:
        module.print_report(SimpleNamespace(
            findings=[_deep_finding()],
            manifest=ScopeManifest(root=".", files=["a.ts"], languages={"typescript": 1},
                                   entrypoints=(), test_command=""),
            elapsed=0.1, engine=None,
        ))
    finally:
        module.console = real

    raw = buffer.getvalue()

    # Le chemin se replie sur plusieurs lignes, et les cellules voisines
    # s'intercalent entre ses morceaux : on ne peut pas aplatir la sortie
    # entière. Ce qui caractérise le défaut est l'ellipse — Rich ne l'écrit
    # que lorsqu'il coupe — et la présence des deux extrémités du chemin.
    assert "…" not in raw, raw
    assert "packages/coding-agent/src/tools/terminal/sessi" in raw, raw
    assert "on-runner.ts:412" in raw, raw


# --- une réfutation sous le seuil reste une réfutation ---------------------
#
# Observé en direct : une passe `--deep` sur Prime réfute deux findings par
# `hermes` et `claude-cli`, les deux tombent sous le seuil d'affichage — et le
# pied de page annonce « Chaque finding est PLAUSIBLE : détecté par analyse
# statique, pas encore prouvé par exécution ». `_confidence_note` sait
# pourtant compter les réfutations ; sa docstring dit même que c'est la raison
# de son existence. Elle ne recevait que les findings retenus par le seuil,
# donc le filtrage défaisait la correction.


def _mixed():
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    def one(identifier, severity, confidence):
        return Finding(
            id=identifier, rule="sink.js.exec", severity=severity,
            confidence=confidence,
            location=CodeRef(path="a.ts", line=1, symbol="s", ast_hash="h"),
            failure_scenario="x",
        )

    kept = [one("k", Severity.HIGH, Confidence.PLAUSIBLE)]
    judged = kept + [
        one("r1", Severity.INFO, Confidence.REFUTED),
        one("r2", Severity.INFO, Confidence.REFUTED),
    ]
    return kept, judged


def test_the_note_counts_what_the_pass_judged_not_what_the_threshold_kept():
    from thot.console import _confidence_note

    kept, judged = _mixed()

    assert "réfuté" in _confidence_note(kept, judged)
    assert "2 réfuté" in _confidence_note(kept, judged)


def test_without_a_deep_pass_the_note_is_unchanged():
    from thot.console import _confidence_note

    kept, _ = _mixed()

    assert "PLAUSIBLE" in _confidence_note(kept, kept)
