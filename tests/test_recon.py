

# --- ce que le modèle reçoit doit dire ce qu'il ne reçoit pas --------------
#
# Un modèle sur-utilise ce qu'il a en contexte : « Symboles (487) : a, b, c… »
# le laisse deviner, « 60 des 128 fonctions » le lui dit. Et le marqueur était
# faux — il comparait le nombre total de symboles à la limite, alors que la
# ligne ne liste que les fonctions, donc il annonçait une coupe même quand
# rien n'avait été retiré.


def _recon_with(symbols=(), findings=(), entrypoints=()):
    from types import SimpleNamespace

    from thot.recon import Recon

    manifest = SimpleNamespace(languages={"python": 1}, test_command="",
                               entrypoints=tuple(entrypoints), files=["a.py"])
    return Recon(root="/r", manifest=manifest, symbols=list(symbols),
                 findings=list(findings))


def _symbol(name, kind="function"):
    from thot.contracts import Symbol

    return Symbol(name=name, kind=kind, path="a.py", lineno=1, end_lineno=2,
                  ast_hash="h")


def test_no_cut_is_announced_when_nothing_was_cut():
    from thot.recon import context_brief

    # beaucoup de symboles, peu de fonctions : la ligne les liste toutes
    symbols = [_symbol(f"f{i}") for i in range(5)]
    symbols += [_symbol(f"C{i}", kind="class") for i in range(100)]

    line = [l for l in context_brief(_recon_with(symbols)).splitlines()
            if l.startswith("Fonctions")]

    assert line, "la ligne des fonctions a disparu"
    # Le décompte porte sur les fonctions, pas sur tous les symboles : sans le
    # filtre la ligne annoncerait « 60 des 105 » et compterait des classes.
    assert line[0].startswith("Fonctions (5) :"), line[0]
    assert "C0" not in line[0], "une classe s'est glissée dans les fonctions"


def test_a_real_cut_says_how_much_was_left_out():
    from thot.recon import context_brief

    symbols = [_symbol(f"f{i}") for i in range(200)]

    line = [l for l in context_brief(_recon_with(symbols)).splitlines()
            if l.startswith("Fonctions")][0]

    assert "60" in line and "200" in line, line


def test_the_findings_line_says_how_many_it_shows(monkeypatch):
    from thot.contracts import CodeRef, Confidence, Finding, Severity
    from thot.recon import context_brief

    findings = [
        Finding(id=str(i), rule="sink.eval", severity=Severity.LOW,
                confidence=Confidence.PLAUSIBLE,
                location=CodeRef(path="a.py", line=i, symbol="s", ast_hash="h"),
                failure_scenario="x")
        for i in range(20)
    ]

    line = [l for l in context_brief(_recon_with(findings=findings)).splitlines()
            if l.startswith("Findings")][0]

    assert "8" in line and "20" in line, line


def test_the_entrypoints_line_names_the_remainder():
    from thot.recon import context_brief

    points = tuple(f"mod.entry{i}" for i in range(30))

    line = [l for l in context_brief(_recon_with(entrypoints=points)).splitlines()
            if l.startswith("Points d'entrée")][0]

    assert "12" in line and "30" in line, line
