from thot.codemap.graph import CodeGraph
from thot.codemap.python_indexer import PythonIndexer
from thot.scope.detect import detect_scope
from thot.taint.engine import find_candidates


def analyse(repo):
    manifest = detect_scope(repo)
    symbols = []
    for relative in manifest.files:
        symbols.extend(PythonIndexer().index_file(repo, relative))
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    return find_candidates(repo, graph)


def test_argv_to_os_system_is_found(toy_repo):
    candidates = analyse(toy_repo)
    rules = {c.rule for c in candidates}
    assert "sink.os.system" in rules


def test_candidate_carries_the_full_path(toy_repo):
    candidate = next(c for c in analyse(toy_repo) if c.rule == "sink.os.system")
    assert len(candidate.path) >= 2
    assert candidate.sink.path == "src/app.py"


def test_unreachable_helper_is_not_reported(toy_repo):
    """unreachable_helper hits os.system too, but nobody feeds it tainted data."""
    candidates = analyse(toy_repo)
    assert all(
        c.sink.symbol != "src.app.unreachable_helper" for c in candidates
    )


def test_clean_file_produces_nothing(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "clean.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    assert find_candidates(tmp_path, graph) == []


def test_constant_argument_is_not_tainted(tmp_path):
    (tmp_path / "const.py").write_text(
        "import os\n\n\ndef main():\n    os.system('ls -la')\n"
    )
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "const.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    assert find_candidates(tmp_path, graph) == []


def test_direct_source_to_sink_in_one_body(tmp_path):
    (tmp_path / "direct.py").write_text(
        "import os\nimport sys\n\n\ndef main():\n"
        "    cmd = sys.argv[1]\n    os.system(cmd)\n"
    )
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, "direct.py")
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    candidates = find_candidates(tmp_path, graph)
    assert len(candidates) == 1
    assert candidates[0].rule == "sink.os.system"


def _analyse_source(tmp_path, code, filename="v.py"):
    (tmp_path / filename).write_text(code)
    manifest = detect_scope(tmp_path)
    symbols = PythonIndexer().index_file(tmp_path, filename)
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    return find_candidates(tmp_path, graph)


def test_sql_injection_through_concatenation_is_found(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n\ndef main():\n"
        "    name = sys.argv[1]\n"
        "    cursor.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\")\n",
    )
    assert {c.rule for c in candidates} == {"sink.sql"}


def test_command_injection_through_fstring_is_found(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nimport sys\n\n\ndef main():\n"
        "    branch = sys.argv[1]\n"
        "    os.system(f'git checkout {branch}')\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_subprocess_with_concatenated_argument_is_found(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import subprocess\nimport sys\n\n\ndef main():\n"
        "    branch = sys.argv[1]\n"
        "    subprocess.run('git checkout ' + branch, shell=True)\n",
    )
    assert {c.rule for c in candidates} == {"sink.subprocess.shell"}


def test_int_conversion_breaks_the_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nimport sys\n\n\ndef main():\n"
        "    count = int(sys.argv[1])\n"
        "    os.system('sleep ' + str(count))\n",
    )
    assert candidates == []


def test_shlex_quote_breaks_the_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nimport shlex\nimport sys\n\n\ndef main():\n"
        "    branch = sys.argv[1]\n"
        "    os.system('git checkout ' + shlex.quote(branch))\n",
    )
    assert candidates == []


def test_tainted_parameter_through_concatenation_crosses_functions(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n\ndef lookup(conn, name):\n"
        "    conn.execute('SELECT * FROM t WHERE n = ' + name)\n\n\n"
        "def main():\n"
        "    value = sys.argv[1]\n"
        "    lookup(None, value)\n",
    )
    assert {c.rule for c in candidates} == {"sink.sql"}


def test_subprocess_with_argument_list_is_not_a_finding(tmp_path):
    """A list argv without shell=True cannot be injected — no shell parses it."""
    candidates = _analyse_source(
        tmp_path,
        "import subprocess\nimport sys\n\n\ndef main():\n"
        "    branch = sys.argv[1]\n"
        "    subprocess.run(['git', 'checkout', branch])\n",
    )
    assert candidates == []


def test_subprocess_list_with_shell_true_is_still_a_finding(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import subprocess\nimport sys\n\n\ndef main():\n"
        "    branch = sys.argv[1]\n"
        "    subprocess.run(['sh', '-c', branch], shell=True)\n",
    )
    assert {c.rule for c in candidates} == {"sink.subprocess.shell"}


def test_parameterised_sql_is_not_a_finding(tmp_path):
    """A literal query with bound parameters is the safe form."""
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n\ndef main():\n"
        "    name = sys.argv[1]\n"
        "    conn.execute('SELECT * FROM t WHERE n = ?', (name,))\n",
    )
    assert candidates == []


def test_taint_in_a_non_command_argument_is_ignored(tmp_path):
    """os.system's danger is its first argument; a tainted second one is not it."""
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n\ndef main():\n"
        "    name = sys.argv[1]\n"
        "    conn.execute('SELECT 1', name)\n",
    )
    assert candidates == []


def test_recursive_function_does_not_crash_the_fixed_point(tmp_path):
    """A self-call used to mutate param_sinks while it was being iterated."""
    candidates = _analyse_source(
        tmp_path,
        "import os\nimport sys\n\n\n"
        "def walk(target, depth):\n"
        "    os.system('ls ' + target)\n"
        "    if depth:\n"
        "        walk(target, depth - 1)\n\n\n"
        "def main():\n"
        "    arg = sys.argv[1]\n"
        "    walk(arg, 3)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_mutually_recursive_functions_do_not_crash(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nimport sys\n\n\n"
        "def ping(value):\n"
        "    pong(value)\n\n\n"
        "def pong(value):\n"
        "    os.system(value)\n"
        "    ping(value)\n\n\n"
        "def main():\n"
        "    arg = sys.argv[1]\n"
        "    ping(arg)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_subprocess_without_shell_true_is_not_a_command_injection(tmp_path):
    """Without shell=True Python never spawns a shell, whatever the argv shape.

    `list(args)` and `cmd + ["install"]` are not ast.List literals, so a
    shape-based guard misses them — the criterion has to be shell=True itself.
    """
    candidates = _analyse_source(
        tmp_path,
        "import subprocess\nimport sys\n\n\ndef main():\n"
        "    args = sys.argv[1:]\n"
        "    subprocess.run(list(args), capture_output=True)\n",
    )
    assert candidates == []


def test_dict_get_is_not_reported_as_a_network_sink(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n\ndef main():\n"
        "    payload = {'a': sys.argv[1]}\n"
        "    value = payload.get(sys.argv[1])\n"
        "    return value\n",
    )
    assert candidates == []


# -- one verdict, one sink ---------------------------------------------------


def _two_sinks(tmp_path):
    import textwrap

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        textwrap.dedent(
            """
            import os
            import sys


            def main():
                first = sys.argv[1]
                second = sys.argv[2]
                os.system("echo " + first)
                os.system("rm -rf " + second)
            """
        )
    )
    return tmp_path


def test_two_sinks_in_one_function_are_two_findings(tmp_path):
    """Same rule, same file, same symbol, same body — different calls.

    They used to share one identity, so a verdict on either one spoke for
    both. On a real repository that merged 22 groups of findings, one of
    them five network calls deep.
    """
    from thot.contracts import Finding

    candidates = [c for c in analyse(_two_sinks(tmp_path))
                  if c.rule == "sink.os.system"]
    assert len(candidates) == 2

    ids = {Finding.compute_id(c.rule, c.sink) for c in candidates}
    assert len(ids) == 2, "deux appels dangereux, deux identités"


def test_refuting_one_sink_does_not_silence_its_neighbour(tmp_path):
    from thot.contracts import Confidence
    from thot.memory import Decision, Verdict
    from thot.memory.sqlite import SqliteMemory
    from thot.pipeline import run_audit

    root = tmp_path / "repo"
    root.mkdir()
    repo = _two_sinks(root)
    (tmp_path / "m").mkdir(parents=True, exist_ok=True)
    memory = SqliteMemory.open(tmp_path / "m" / "m.db")
    try:
        first = run_audit(repo, require_authorization=False)
        shell = [f for f in first.findings if f.rule == "sink.os.system"]
        assert len(shell) == 2

        memory.remember(Verdict.of(shell[0], Decision.REFUTED, "littéral", "dev"))
        again = run_audit(repo, require_authorization=False, memory=memory)

        refuted = [f for f in again.findings
                   if f.confidence is Confidence.REFUTED]
        assert len(refuted) == 1, "une décision ne parle que pour son propre site"
    finally:
        memory.close()


def test_a_site_that_moves_keeps_its_verdict(tmp_path):
    """The discriminator must not undo what `compute_id` exists for."""
    import textwrap

    from thot.contracts import Finding

    repo = _two_sinks(tmp_path)
    before = {Finding.compute_id(c.rule, c.sink)
              for c in analyse(repo) if c.rule == "sink.os.system"}

    # A comment above the function: every line moves, nothing behaves
    # differently.
    source = (repo / "src" / "app.py").read_text()
    (repo / "src" / "app.py").write_text("# en-tête ajouté\n\n" + source)

    after = {Finding.compute_id(c.rule, c.sink)
             for c in analyse(repo) if c.rule == "sink.os.system"}
    assert before == after


# --- deux fonctions homonymes ne sont pas la même fonction -----------------
#
# Trouvé en vérifiant une réfutation du panel sur Hermes, et elle avait
# raison : `agent/command_token_source.py` définit `_mint(command, label)` qui
# fait `subprocess.run(command, shell=True)`, et `tests/plugins/
# test_chronos_verify.py` définit son propre `_mint(priv, claims)` qui signe un
# JWT. Le test appelle le sien ; le moteur a relié l'appel à l'autre module
# parce que le dernier segment du nom correspondait, et a rapporté un chemin
# HIGH d'une donnée d'attaquant jusqu'à `shell=True`.
#
# `resolve` rendait toutes les fonctions de l'arbre partageant un nom court.
# La définition du module appelant l'emporte désormais, et la correspondance
# globale ne sert plus que de repli — ce que le moteur JS fait déjà.


def test_a_local_definition_wins_over_a_namesake_elsewhere(tmp_path):
    from thot.codemap.index import index_files
    from thot.taint.engine import find_candidates

    (tmp_path / "dangerous.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def _mint(command):\n"
        "    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "harmless.py").write_text(
        "import sys\n"
        "\n"
        "\n"
        "def _mint(value):\n"
        "    return value.upper()\n"
        "\n"
        "\n"
        "def run():\n"
        "    return _mint(sys.argv[1])\n",
        encoding="utf-8",
    )
    from thot.codemap.graph import CodeGraph

    files = ["dangerous.py", "harmless.py"]
    graph = CodeGraph.build(index_files(tmp_path, files))
    found = find_candidates(tmp_path, graph)

    culprits = [c for c in found if c.sink.path == "dangerous.py"]
    assert culprits == [], culprits


def test_a_call_with_no_local_namesake_still_resolves(tmp_path):
    """The fallback stays: an imported helper has no definition here."""
    from thot.codemap.index import index_files
    from thot.taint.engine import find_candidates

    (tmp_path / "helpers.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def launch(command):\n"
        "    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import sys\n"
        "from helpers import launch\n"
        "\n"
        "\n"
        "def run():\n"
        "    launch(sys.argv[1])\n",
        encoding="utf-8",
    )
    from thot.codemap.graph import CodeGraph

    files = ["helpers.py", "app.py"]
    graph = CodeGraph.build(index_files(tmp_path, files))
    found = find_candidates(tmp_path, graph)

    assert any(c.sink.path == "helpers.py" for c in found), found


# --- pourquoi la teinte suit ce que le graphe refuse -----------------------
#
# `CodeGraph.build` s'abstient quand un nom court a plusieurs définitions non
# locales : « recording no edge is right; concluding unreachable is not ». Le
# moteur de teinte, lui, les suit toutes. L'écart est délibéré et les coûts
# sont inverses : une arête fausse dans le graphe *augmente* une sévérité en
# rapprochant un finding d'un point d'entrée, tandis qu'une arête manquante
# dans la teinte *cache* une vulnérabilité.
#
# Mesuré avant de trancher : sur Hermes, 53 % des résolutions d'appels sont
# ambiguës (122 589 sur 232 404 — `close` a 235 définitions, `_run` 246).
# S'abstenir ramènerait Hermes de 412 findings à 358 et Thot de 4 à 2. Mais
# des deux que Thot perdrait, l'un est réel — `report(new_findings)` →
# `broadcast(text)` → le POST HTTP — et l'autre non. Un vrai pour un faux
# n'est pas un gain, donc rien n'est changé et ce test dit pourquoi.


def test_an_ambiguous_import_is_still_followed(tmp_path):
    """Two namesakes elsewhere, none here: the call is followed, not dropped."""
    from thot.codemap.graph import CodeGraph
    from thot.codemap.index import index_files
    from thot.taint.engine import find_candidates

    (tmp_path / "sender.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def deliver(payload):\n"
        "    subprocess.run(payload, shell=True)\n",
        encoding="utf-8",
    )
    # A second `deliver`, so the short name is ambiguous tree-wide.
    (tmp_path / "other.py").write_text(
        "def deliver(payload):\n    return payload\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        "import sys\n"
        "from sender import deliver\n"
        "\n"
        "\n"
        "def run():\n"
        "    value = sys.argv[1]\n"
        "    deliver(value)\n",
        encoding="utf-8",
    )
    files = ["sender.py", "other.py", "app.py"]
    graph = CodeGraph.build(index_files(tmp_path, files))

    found = find_candidates(tmp_path, graph)

    assert any(c.sink.path == "sender.py" for c in found), (
        "la teinte s'est abstenue sur un nom ambigu et a perdu un vrai chemin"
    )


# --- un paramètre nommé obligatoire porte la teinte comme un autre ---------
#
# `params` ne retenait que `child.args.args` : ni les paramètres nommés
# obligatoires (`def f(*, command)`), ni les positionnels stricts
# (`def f(a, /)`). Or le premier est l'idiome Python *recommandé* pour une API
# dangereuse — on force l'appelant à écrire le nom. Le moteur était donc
# aveugle précisément là où le code soigneux met ses paramètres sensibles :
#
#   def launch(command):      → 1 chemin
#   def launch(*, command):   → 0 chemin


def _two_files(tmp_path, signature, call):
    (tmp_path / "helpers.py").write_text(
        "import subprocess\n\n\n" + signature
        + "\n    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import sys\nfrom helpers import launch\n\n\ndef run():\n"
        "    cmd = sys.argv[1]\n" + call + "\n",
        encoding="utf-8",
    )
    from thot.codemap.graph import CodeGraph
    from thot.codemap.index import index_files
    from thot.taint.engine import find_candidates

    graph = CodeGraph.build(index_files(tmp_path, ["helpers.py", "app.py"]))
    return find_candidates(tmp_path, graph)


def test_a_keyword_only_parameter_carries_taint(tmp_path):
    found = _two_files(tmp_path, "def launch(*, command):", "    launch(command=cmd)")

    assert any(c.sink.path == "helpers.py" for c in found), found


def test_a_positional_only_parameter_carries_taint(tmp_path):
    found = _two_files(tmp_path, "def launch(command, /):", "    launch(cmd)")

    assert any(c.sink.path == "helpers.py" for c in found), found


def test_an_ordinary_parameter_still_does(tmp_path):
    found = _two_files(tmp_path, "def launch(command):", "    launch(cmd)")

    assert any(c.sink.path == "helpers.py" for c in found), found
