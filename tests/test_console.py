

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
