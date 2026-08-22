

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


# --- un fichier pathologique ne doit pas coûter l'audit ---------------------
#
# Mesuré : un seul fichier contenant `x = (((…200 fois…)))` fait tomber
# `sweep()` entier sur `RecursionError: maximum recursion depth exceeded
# during ast construction`. Pas « saute le fichier » — s'arrête. Un
# générateur de code en produit, un dépôt hostile aussi, et lire du code
# auquel on ne fait pas confiance est exactement le métier de cet outil.
#
# `taint/engine.py` attrapait déjà `RecursionError` ; `python_indexer` et
# `scope/detect` ne le faisaient pas. Le remède était connu et appliqué à un
# endroit sur trois.


def _pathological_repo(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    # Une longue chaîne d'additions, pas une imbrication de parenthèses :
    # `0 + 1 + … + 4999` construit un arbre BinOp de 5 000 niveaux, et c'est
    # lui qui épuise la pile. Deux cents parenthèses passent sans broncher —
    # la première version de ce test les utilisait et passait déjà.
    (source / "chain.py").write_text(
        "y = " + " + ".join(str(i) for i in range(5000)) + "\n", encoding="utf-8"
    )
    (source / "ordinary.py").write_text(
        "import os\nimport sys\n\n\ndef run():\n    os.system(sys.argv[1])\n",
        encoding="utf-8",
    )
    return tmp_path


def test_a_pathological_expression_does_not_stop_the_sweep(tmp_path, monkeypatch):
    import thot.recon as recon

    # monkeypatch, pas une affectation : remplacer l'attribut du module fuit
    # dans les autres tests, et la suite me l'a dit.
    monkeypatch.setattr(recon, "_remember", lambda findings, root=None: findings)
    result = recon.sweep(_pathological_repo(tmp_path))

    assert result.file_count >= 2


def test_the_other_files_are_still_indexed(tmp_path, monkeypatch):
    import thot.recon as recon

    monkeypatch.setattr(recon, "_remember", lambda findings, root=None: findings)
    result = recon.sweep(_pathological_repo(tmp_path))

    assert any(s.name.endswith("run") for s in result.symbols), (
        "le fichier sain a été perdu avec le fichier pathologique"
    )


def test_the_scope_detection_survives_it_too(tmp_path):
    from thot.scope.detect import detect_scope

    scope = detect_scope(_pathological_repo(tmp_path))

    assert len(scope.files) >= 2
