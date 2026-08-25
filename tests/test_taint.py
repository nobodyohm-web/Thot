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
        "import sqlite3\nimport sys\n\n\ndef main():\n"
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
        "import sqlite3\nimport sys\n\n\ndef lookup(conn, name):\n"
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


# -- `execute` is a method name, not a database ---------------------------
#
# `sink.sql` matches any method called `execute`, whatever holds it. On
# Hermes that was 110 candidates, none ever confirmed, and among them
# `relay_llm.execute(kwargs)`, `pipeline.execute(ctx)`, `env.execute(cmd)`
# and a console engine's `engine.execute("cron pause 4")`.


def _tree(tmp_path, source: str):
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "app.py").write_text(source, encoding="utf-8")
    return tmp_path


QUERY = '''\
import sys
{importation}

def handler():
    name = sys.argv[1]
    run(name)


def run(name):
    {receveur}.execute(f"SELECT * FROM t WHERE n = '{{name}}'")
'''


def test_execute_is_a_sink_where_a_database_is_imported(tmp_path):
    repo = _tree(tmp_path, QUERY.format(importation="import sqlite3",
                                        receveur="conn"))
    assert "sink.sql" in {c.rule for c in analyse(repo)}


def test_execute_with_neither_a_driver_nor_a_query_is_not_a_sink(tmp_path):
    """A console engine, an LLM relay and a pipeline all have one.

    This is what the gate is still for. No driver imported *and* no query
    written anywhere in the file: nothing here says the word `execute` means
    a database.
    """
    repo = _tree(tmp_path, "import sys\n\n\ndef handler():\n"
                           "    engine.execute(sys.argv[1])\n")
    assert "sink.sql" not in {c.rule for c in analyse(repo)}


def test_a_driver_reached_through_a_package_still_counts(tmp_path):
    repo = _tree(tmp_path, QUERY.format(importation="from django.db import connection",
                                        receveur="conn"))
    assert "sink.sql" in {c.rule for c in analyse(repo)}


def test_a_rule_that_needs_no_module_is_unaffected(tmp_path):
    repo = _tree(tmp_path, "import sys, os\n\n"
                           "def handler():\n"
                           "    os.system(sys.argv[1])\n")
    assert "sink.os.system" in {c.rule for c in analyse(repo)}


def test_a_connection_handed_in_without_a_driver_is_seen_by_its_query(tmp_path):
    """The gate's old price, and why it was too high to keep paying.

    A file that receives a connection and imports no driver used to go
    unseen. It was pinned here as a known cost — one production site on
    Hermes out of 110 candidates — on the assumption that hiding the driver
    was the exception.

    It is the rule. Measured against 100 labelled SQL-injection cases whose
    sink was `db.execute` behind `from app_runtime import db`, the import
    gate scored **0 out of 100**. So the query itself now opens the gate: a
    file that spells out `SELECT ... FROM` is composing SQL, whatever local
    wrapper runs it.
    """
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n\ndef lookup(conn, name):\n"
        "    conn.execute('SELECT * FROM t WHERE n = ' + name)\n\n\n"
        "def main():\n"
        "    value = sys.argv[1]\n"
        "    lookup(None, value)\n",
    )
    assert "sink.sql" in {c.rule for c in candidates}


def test_a_query_elsewhere_in_the_file_is_what_opens_the_gate(tmp_path):
    """The residual cost, pinned in its turn.

    The evidence is file-wide, not call-wide: an unrelated `pipeline.execute`
    in a file that also holds a query will now be reported. That is the price
    of not needing to resolve what `db` is bound to, and it is a far smaller
    one than 0/100.
    """
    candidates = _analyse_source(
        tmp_path,
        "import sys\n\n"
        "TEMPLATE = 'SELECT id FROM users'\n\n\n"
        "def main():\n"
        "    pipeline.execute(sys.argv[1])\n",
    )
    assert "sink.sql" in {c.rule for c in candidates}


# --- toute forme d'affectation lie un nom, pas seulement `x = ...` ---------
#
# `ast.Assign` n'est qu'une des façons d'écrire la même vulnérabilité. Mesuré
# sur un fichier où le même chemin `request.args` -> `os.system` est écrit de
# quatorze façons : 2 sites détectés sur 14 avant, plus un faux positif. Un
# faux négatif de classe, puisque c'est la syntaxe qui décide, pas le code.


def _hit(candidates, symbol_suffix):
    return any(c.sink.symbol.endswith(symbol_suffix) for c in candidates)


def test_an_annotated_assignment_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    host: str = request.args.get('host')\n"
        "    os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_a_for_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    for host in request.args.getlist('host'):\n"
        "        os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_an_async_for_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\nasync def view():\n"
        "    async for host in request.args.getlist('host'):\n"
        "        os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_a_tuple_unpacking_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    host, port = request.args.get('host'), 80\n"
        "    os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_tuple_unpacking_pairs_element_to_element(tmp_path):
    """`host, port = request.args.get('host'), 80` taints `host` and nothing
    else — flattening both sides would call the literal 80 untrusted."""
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    host, port = request.args.get('host'), 80\n"
        "    os.system('ping -c1 ' + host)\n"
        "    os.system('ping -p ' + str(port))\n",
    )
    assert [c.sink.line for c in candidates] == [7]


def test_a_starred_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    first, *rest = request.args.getlist('host')\n"
        "    os.system('ping -c1 ' + rest[0])\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_a_walrus_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    if (host := request.args.get('host')):\n"
        "        os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_an_augmented_assignment_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    host = ''\n"
        "    host += request.args.get('host')\n"
        "    os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_an_augmented_assignment_keeps_the_taint_of_its_own_target(tmp_path):
    """`buffer += ' --now'` reads `buffer`; a constant right-hand side must not
    launder what the target already carried."""
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    command = request.args.get('cmd')\n"
        "    command += ' --now'\n"
        "    os.system(command)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_a_with_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    with request.args.get('host') as host:\n"
        "        os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_an_async_with_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\nasync def view():\n"
        "    async with request.args.get('host') as host:\n"
        "        os.system('ping -c1 ' + host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_an_attribute_target_carries_taint(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view(box):\n"
        "    box.host = request.args.get('host')\n"
        "    os.system('ping -c1 ' + box.host)\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_a_comprehension_target_carries_taint(tmp_path):
    """The sink is inside the comprehension, so the `for` clause is the only
    place the name is ever bound."""
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    [os.system('ping -c1 ' + h) for h in request.args.getlist('host')]\n",
    )
    assert {c.rule for c in candidates} == {"sink.os.system"}


def test_an_except_target_drops_the_taint_the_name_carried(tmp_path):
    """`except ... as host` rebinds `host` to an exception, exactly as
    `host = 'safe'` would — the caught object is not what the request sent."""
    candidates = _analyse_source(
        tmp_path,
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    host = request.args.get('host')\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as host:\n"
        "        os.system('ping -c1 ' + str(host))\n",
    )
    assert candidates == []


def test_a_loop_over_an_untainted_iterable_taints_nothing(tmp_path):
    candidates = _analyse_source(
        tmp_path,
        "import os\n\n\ndef view():\n"
        "    for host in ('localhost', '127.0.0.1'):\n"
        "        os.system('ping -c1 ' + host)\n",
    )
    assert candidates == []


# --- ce que le moteur Python ouvre, et ce qu'il garde ouvert ---------------


def test_a_typescript_symbol_is_left_to_the_javascript_engine(tmp_path):
    """`graph.symbols` holds both languages, and this engine used to hand every
    one of them to `ast.parse`: measured on hermes/, 1957 .ts/.tsx/.js files
    read and parsed for 0 successes."""
    (tmp_path / "app.ts").write_text(
        "import os\nfrom flask import request\n\n\ndef view():\n"
        "    host = request.args.get('host')\n"
        "    os.system('ping -c1 ' + host)\n",
        encoding="utf-8",
    )
    symbols = PythonIndexer().index_file(tmp_path, "app.ts")
    graph = CodeGraph.build(symbols)
    assert find_candidates(tmp_path, graph) == []


def test_a_syntax_tree_does_not_outlive_the_file_it_came_from(tmp_path):
    """Holding every function body of the repository at once costs 2035 MB of
    peak RSS on hermes/ (4457 files, 75 243 bodies) against 136 MB one file at
    a time. The engine parses a file, takes its facts, and lets the tree go."""
    import gc
    import weakref

    from thot.taint import engine

    for name in ("a", "b"):
        (tmp_path / f"{name}.py").write_text(
            f"import os\n\n\ndef {name}_view(value):\n"
            "    os.system('echo ' + value)\n",
            encoding="utf-8",
        )

    trees: list[weakref.ref] = []
    survivors: list[int] = []
    real = engine._analyse_body

    def spy(symbol, node, imported=frozenset()):
        gc.collect()
        survivors.append(sum(1 for ref in trees if ref() is not None))
        trees.append(weakref.ref(node))
        return real(symbol, node, imported)

    engine._analyse_body = spy
    try:
        symbols = PythonIndexer().index_file(tmp_path, "a.py")
        symbols += PythonIndexer().index_file(tmp_path, "b.py")
        find_candidates(tmp_path, CodeGraph.build(symbols))
    finally:
        engine._analyse_body = real

    assert survivors == [0, 0], survivors


def test_the_fixed_point_does_not_rescan_what_it_has_already_merged(tmp_path):
    """Deduplicating by linear search through a list of frozen dataclasses is
    quadratic in the sinks a parameter accumulates: measured on hermes/, 4.5 M
    membership tests scanning 121 M entries."""
    from thot.contracts import CodeRef

    sinks = "".join(f"    os.system('echo {i} ' + cmd)\n" for i in range(120))
    callers = "".join(
        f"def caller{i}(value):\n    propagate(value)\n\n\n" for i in range(12)
    )
    (tmp_path / "wide.py").write_text(
        f"import os\n\n\ndef propagate(cmd):\n{sinks}\n\n{callers}",
        encoding="utf-8",
    )
    symbols = PythonIndexer().index_file(tmp_path, "wide.py")
    graph = CodeGraph.build(symbols)

    comparisons = [0]
    real = CodeRef.__eq__

    def counting(self, other):
        comparisons[0] += 1
        return real(self, other)

    CodeRef.__eq__ = counting
    try:
        find_candidates(tmp_path, graph)
    finally:
        CodeRef.__eq__ = real

    assert comparisons[0] < 5_000, comparisons[0]


# Deux gardes sur les corrections apportées aux correctifs, pas sur les
# défauts eux-mêmes : elles passaient déjà, et elles doivent continuer.


def test_a_self_recursive_propagator_lists_its_own_sink_once(tmp_path):
    """The membership index of the fixed point is seeded from the list, not
    from the empty set: `_analyse_body` has already recorded this body's own
    sinks, and a call to itself would otherwise append them a second time."""
    from thot.codemap.catalog import using
    from thot.codemap.rules import load_catalog
    from thot.taint import engine

    (tmp_path / "r.py").write_text(
        "import os\n\n\ndef propagate(cmd):\n"
        "    os.system(cmd)\n"
        "    propagate(cmd)\n",
        encoding="utf-8",
    )
    symbols = PythonIndexer().index_file(tmp_path, "r.py")
    graph = CodeGraph.build(symbols)

    captured: dict[str, object] = {}
    real = engine._analyse_body

    def spy(symbol, node, imported=frozenset()):
        facts = real(symbol, node, imported)
        captured[symbol.name] = facts
        return facts

    engine._analyse_body = spy
    try:
        with using(load_catalog(tmp_path)):
            engine._find_candidates(tmp_path, graph, 3)
    finally:
        engine._analyse_body = real

    sinks = captured["r.propagate"].param_sinks["cmd"]
    assert len(sinks) == len(set(sinks)), sinks


# --- reading *through* a tainted value ------------------------------------
#
# `handle.read()`, `payload.decode()`, `body.strip()` — the ordinary way a
# value travels in Python. The engine rendered these as one dotted name,
# `handle.read`, and looked *that* up in a map that only ever holds `handle`.
# Measured before the fix: five of ten propagation forms lost, including
# every method call on a tainted name.


def _one(tmp_path, body: str) -> set[str]:
    (tmp_path / "a.py").write_text("import os, sys, shlex\n" + body)
    manifest = detect_scope(tmp_path)
    symbols = [
        s for relative in manifest.files
        for s in PythonIndexer().index_file(tmp_path, relative)
    ]
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    return {c.rule for c in find_candidates(tmp_path, graph)}


def test_a_method_call_on_a_tainted_value_keeps_the_taint(tmp_path):
    assert "sink.os.system" in _one(tmp_path, """
def main():
    command = sys.argv[1]
    os.system(command.strip())
""")


def test_an_attribute_of_a_tainted_value_keeps_the_taint(tmp_path):
    assert "sink.os.system" in _one(tmp_path, """
def main():
    payload = sys.argv[1]
    os.system(payload.data)
""")


def test_a_method_call_on_a_tainted_parameter_keeps_the_taint(tmp_path):
    assert "sink.os.system" in _one(tmp_path, """
def run(payload):
    os.system(payload.decode())

def main():
    run(sys.argv[1])
""")


def test_a_source_read_through_a_method_is_a_path(tmp_path):
    assert "sink.os.system" in _one(tmp_path, """
def main():
    os.system(sys.argv[1].strip())
""")


def test_a_file_opened_on_a_tainted_path_yields_tainted_content(tmp_path):
    assert "sink.os.system" in _one(tmp_path, """
def main():
    with open(sys.argv[1]) as handle:
        os.system(handle.read())
""")


def test_a_sibling_attribute_is_not_tainted(tmp_path):
    """`box.host` tainted says nothing about `box.name`. Widening the lookup
    the other way — root tainted implies attribute tainted — must not become
    attribute tainted implies root tainted."""
    assert _one(tmp_path, """
def main():
    box = Box()
    box.host = sys.argv[1]
    os.system(box.name)
""") == set()


def test_a_sanitiser_still_ends_the_path_through_a_method(tmp_path):
    assert _one(tmp_path, """
def main():
    command = sys.argv[1]
    os.system(shlex.quote(command.strip()))
""") == set()


def test_the_receiver_is_not_an_input_channel(tmp_path):
    """`self` is a parameter the way a hand is a tool. A constant read off
    the instance is a constant, whatever the method's signature says."""
    assert _one(tmp_path, """
class Store:
    TABLES = ("notes", "tags")

    def rebuild(self, conn):
        for table in self.TABLES:
            os.system("vacuum " + table)
""") == set()


def test_a_message_from_a_rejected_value_is_tainted(tmp_path):
    """`int(x)` sanitises when it succeeds. When it fails it raises with the
    text it refused — which is how the value leaves the try block."""
    assert "sink.os.system" in _one(tmp_path, """
def main():
    try:
        int(sys.argv[1])
    except ValueError as failure:
        os.system(str(failure))
""")


def test_an_exception_from_a_clean_block_is_not_tainted(tmp_path):
    assert _one(tmp_path, """
def main():
    try:
        int("12")
    except ValueError as failure:
        os.system(str(failure))
""") == set()


def test_the_caught_name_still_loses_what_it_carried(tmp_path):
    """Rebinding is rebinding: `failure` held a command, now it holds an
    exception raised by a block that touched nothing untrusted."""
    assert _one(tmp_path, """
def main():
    failure = sys.argv[1]
    try:
        int("12")
    except ValueError as failure:
        os.system(str(failure))
""") == set()


# --- where the value came from is half of how serious it is ----------------
#
# `open(args.output, "w")` in a command-line tool is the operator naming a
# file: whoever supplies argv already has the filesystem, and the call grants
# nothing. `open(request.args["f"])` in a handler is arbitrary file read.
# Same rule, same sink, and the engine ranked them identically because a
# candidate recorded where its source *was* and never which rule matched it.
# Measured on Hermes the day attribute chains started resolving: 48 findings
# of the first kind, 9 from one CI script, all at medium.


def _candidates(tmp_path, body: str) -> list:
    (tmp_path / "a.py").write_text("import os, sys\n" + body)
    manifest = detect_scope(tmp_path)
    symbols = [
        s for relative in manifest.files
        for s in PythonIndexer().index_file(tmp_path, relative)
    ]
    graph = CodeGraph.build(symbols, manifest.entrypoints)
    return find_candidates(tmp_path, graph)


def test_a_candidate_says_which_source_started_it(tmp_path):
    found = _candidates(tmp_path, """
def main():
    os.system(sys.argv[1])
""")

    assert [c.source_rule for c in found] == ["source.argv"]


def test_a_path_named_on_the_command_line_ranks_below_one_from_a_request(tmp_path):
    from thot.contracts import Severity

    local = _candidates(tmp_path, """
def main():
    open(sys.argv[1]).read()
""")
    remote = _candidates(tmp_path, """
from flask import request

def handler():
    open(request.args["f"]).read()
""")

    assert [c.impact for c in local] == [Severity.LOW]
    assert [c.impact for c in remote] == [Severity.MEDIUM]


def test_the_discount_applies_to_the_path_and_not_to_the_shell(tmp_path):
    """Only the sinks whose seriousness depends on the distance travelled.
    A command built from argv is still a command."""
    from thot.contracts import Severity

    found = _candidates(tmp_path, """
def main():
    os.system(sys.argv[1])
""")

    assert [c.impact for c in found] == [Severity.CRITICAL]


def test_a_named_source_wins_over_an_unattributed_duplicate(tmp_path):
    """The same sink is reached twice: once inside the helper, whose
    parameter is tainted by assumption and names no rule, and once from the
    caller that actually fed it `sys.argv`. Both produce the same finding,
    and the first one emitted used to win — so the run kept the version that
    knew nothing about where the value came from."""
    found = _candidates(tmp_path, """
def helper(path):
    handle = open(path)
    return handle.read()

def main():
    helper(sys.argv[1])
""")

    assert [c.source_rule for c in found] == ["source.argv"]


def test_a_local_derived_from_a_parameter_still_reaches_its_caller(tmp_path):
    """`target = path.strip()` and the link to `path` was gone: the sink was
    registered against no parameter, so no caller was ever paired with it.
    The path was still reported — from inside the helper, starting nowhere."""
    found = _candidates(tmp_path, """
def helper(path):
    target = path.strip()
    open(target).read()

def main():
    helper(sys.argv[1])
""")

    assert [c.source_rule for c in found] == ["source.argv"]
    # And the reported path goes through the call, not just the helper.
    assert len(found[0].path) == 3


# --- quel paramètre un argument remplit -----------------------------------
#
# Le moteur appariait un appelant avec *tous* les sinks du callee, sans
# regarder où l'argument atterrissait : `helper(untrusted, "ls")` contre
# `def helper(safe, cmd)` était rapporté comme un chemin vers le shell que
# seul `cmd` atteint. Le moteur JavaScript lit déjà `callee.params[index]` ;
# ces tests tiennent les deux bouts, le faux positif retiré et les vrais
# positifs conservés.


_TWO_SLOTS = """
def helper(safe, cmd):
    os.system(cmd)

def main():
    helper(%s)
"""


def test_a_value_handed_to_a_safe_parameter_reaches_no_sink(tmp_path):
    """The whole point: `safe` goes nowhere near `os.system`."""
    assert _one(tmp_path, _TWO_SLOTS % 'sys.argv[1], "ls"') == set()


def test_the_same_value_in_the_dangerous_slot_is_still_reported(tmp_path):
    """The guard against over-correcting: move the argument one slot right
    and the finding must come back."""
    assert "sink.os.system" in _one(tmp_path, _TWO_SLOTS % '"ls", sys.argv[1]')


def test_a_keyword_argument_is_matched_by_name(tmp_path):
    assert _one(tmp_path, _TWO_SLOTS % 'safe=sys.argv[1], cmd="ls"') == set()
    assert "sink.os.system" in _one(
        tmp_path, _TWO_SLOTS % 'cmd=sys.argv[1], safe="ls"'
    )


def test_a_starred_argument_leaves_every_parameter_open(tmp_path):
    """`helper(*argv)` settles no position, so the engine keeps the answer it
    gave before slots were tracked. Losing a real path to a spread argument
    would be the expensive half of this trade."""
    assert "sink.os.system" in _one(tmp_path, """
def helper(safe, cmd):
    os.system(cmd)

def main():
    argv = [sys.argv[1], "ls"]
    helper(*argv)
""")


def test_a_receiver_shifts_the_positions_by_one(tmp_path):
    """`Runner().go(x)` renders as a bare `go` — the call site cannot say
    whether a receiver was passed, so the callee's signature decides."""
    method = """
class Runner:
    def go(self, safe, cmd):
        os.system(cmd)

def main():
    Runner().go(%s)
"""
    assert _one(tmp_path, method % 'sys.argv[1], "ls"') == set()
    assert "sink.os.system" in _one(tmp_path, method % '"ls", sys.argv[1]')


def test_the_slot_survives_a_second_hop(tmp_path):
    """The fixed point propagates `param_sinks` across call edges, and it
    matched slots just as loosely as the emission did — so a two-hop chain
    would have re-introduced the false positive one level up."""
    relayed = """
def inner(safe, cmd):
    os.system(cmd)

def outer(first, second):
    inner(first, second)

def main():
    outer(%s)
"""
    assert _one(tmp_path, relayed % 'sys.argv[1], "ls"') == set()
    assert "sink.os.system" in _one(tmp_path, relayed % '"ls", sys.argv[1]')


# -- a value that travels through a container --------------------------------
#
# Measured on a labelled corpus: 27 % of the cases still missed in categories
# where Thot already had a working rule were this one shape. `parts` was
# assigned an empty list and never re-assigned, so nothing in the walk made it
# untrusted and the sink saw a clean name — the engine's answer depended on
# whether the author happened to use a list.


def _findings(tmp_path, source: str):
    from thot.pipeline import run_audit

    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_audit(tmp_path, require_authorization=False, budget=0).findings


def test_a_value_appended_to_a_list_taints_the_list(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "import sys\n\n"
        "def main():\n"
        "    parts = []\n"
        "    for token in sys.argv[1].split(','):\n"
        "        parts.append(token.strip())\n"
        "    os.system('echo ' + ','.join(parts))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_appending_a_constant_leaves_the_list_alone(tmp_path):
    found = _findings(tmp_path, (
        "import os\n\n"
        "def main():\n"
        "    parts = []\n"
        "    parts.append('ls')\n"
        "    os.system(' '.join(parts))\n"
    ))
    assert found == []


def test_appending_a_constant_does_not_launder_what_the_list_held(tmp_path):
    """The same reason `AugAssign` reads its own target: a second, clean
    append must not wash out the first, dirty one."""
    found = _findings(tmp_path, (
        "import os\n"
        "import sys\n\n"
        "def main():\n"
        "    parts = []\n"
        "    parts.append(sys.argv[1])\n"
        "    parts.append('--now')\n"
        "    os.system(' '.join(parts))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_set_and_a_dict_carry_a_value_like_a_list(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "import sys\n\n"
        "def main():\n"
        "    seen = set()\n"
        "    seen.add(sys.argv[1])\n"
        "    os.system(' '.join(seen))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_container_reached_through_an_attribute_is_not_invented(tmp_path):
    """`self.items.append(x)` mutates something the engine does not track as
    a name. Tainting `items` would taint a name that does not exist here."""
    from thot.taint.engine import _mutated_container
    import ast

    call = ast.parse("self.items.append(x)").body[0].value
    assert _mutated_container(call) is None

    bare = ast.parse("items.append(x)").body[0].value
    assert _mutated_container(bare) == "items"


def test_a_method_that_reads_rather_than_writes_is_not_a_mutation(tmp_path):
    from thot.taint.engine import _mutated_container
    import ast

    call = ast.parse("parts.index(x)").body[0].value
    assert _mutated_container(call) is None


# -- guards that prove a destination, not a value ----------------------------
#
# Recognising these took `ssrf` from J -8 % to +65 %, `cloud_ssrf_metadata`
# from 0 % to +79 % and `pathtraver` from +23 % to +56 %, over 18 300 labelled
# cases, without losing one true positive. Every test below that ends in a
# finding being KEPT exists because an adversarial probe on the first version
# of this code turned a real vulnerability into silence: a range check on an
# IP says nothing about shell metacharacters, and a path confined under a
# directory is still a string full of semicolons.


def test_a_host_allow_list_clears_an_outgoing_request(tmp_path):
    found = _findings(tmp_path, (
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('url', '')\n"
        "    parsed = urlparse(url)\n"
        "    if parsed.hostname not in ('a.example', 'b.example'):\n"
        "        return 'no', 403\n"
        "    requests.get(url)\n"
    ))
    assert found == []


def test_a_host_allow_list_does_not_clear_a_shell(tmp_path):
    """The guard constrains where the request goes. The string still holds
    whatever the attacker put after the host."""
    found = _findings(tmp_path, (
        "import os\n"
        "from urllib.parse import urlparse\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('url', '')\n"
        "    parsed = urlparse(url)\n"
        "    if parsed.hostname not in ('a.example',):\n"
        "        return 'no', 403\n"
        "    os.system('curl ' + url)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_host_attribute_on_any_object_clears_nothing(tmp_path):
    """`payload.host` is not a parsed URL. Without the origin requirement any
    attribute spelled `host` launders any value."""
    found = _findings(tmp_path, (
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    payload = request.get_json()\n"
        "    if payload.host not in ('a.example',):\n"
        "        return 'no', 403\n"
        "    os.system(payload.host)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_resolved_address_range_check_clears_an_outgoing_request(tmp_path):
    found = _findings(tmp_path, (
        "import ipaddress\n"
        "import socket\n"
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('url', '')\n"
        "    parsed = urlparse(url)\n"
        "    resolved = socket.gethostbyname(parsed.hostname or url)\n"
        "    if ipaddress.ip_address(resolved).is_private:\n"
        "        return 'no', 403\n"
        "    target = url.replace(parsed.hostname, resolved)\n"
        "    requests.get(target)\n"
    ))
    assert found == [], "la valeur dérivée après la garde doit l'être aussi"


def test_a_range_check_does_not_clear_a_shell(tmp_path):
    found = _findings(tmp_path, (
        "import ipaddress\n"
        "import socket\n"
        "import os\n"
        "from urllib.parse import urlparse\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('url', '')\n"
        "    parsed = urlparse(url)\n"
        "    resolved = socket.gethostbyname(parsed.hostname or url)\n"
        "    if ipaddress.ip_address(resolved).is_private:\n"
        "        return 'no', 403\n"
        "    os.system('curl -s ' + url)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_range_check_needs_an_address_that_was_resolved(tmp_path):
    """On a hostname the check answers about the wrong thing entirely."""
    found = _findings(tmp_path, (
        "import ipaddress\n"
        "import requests\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    host = request.args.get('host', '')\n"
        "    if ipaddress.ip_address(host).is_private:\n"
        "        return 'no', 403\n"
        # https, so the only rule under test here is the taint one — plain
        # http is a finding of its own now, and correctly so.
        "    requests.get('https://' + host)\n"
    ))
    assert [f.rule for f in found] == ["sink.network"]


def test_a_path_confined_under_a_constant_root_clears_a_read(tmp_path):
    found = _findings(tmp_path, (
        "from pathlib import Path\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('name', '')\n"
        "    base = Path('/var/app/data').resolve()\n"
        "    candidate = (base / data).resolve()\n"
        "    if base not in candidate.parents and candidate != base:\n"
        "        return 'no', 403\n"
        "    return open(str(candidate)).read()\n"
    ))
    assert found == []


def test_a_confined_path_does_not_clear_a_shell(tmp_path):
    """`realpath` keeps every shell metacharacter it was given. A path under
    the right directory is still `x; rm -rf /`."""
    found = _findings(tmp_path, (
        "import os\n"
        "from pathlib import Path\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('name', '')\n"
        "    base = Path('/var/app/data').resolve()\n"
        "    candidate = (base / data).resolve()\n"
        "    if base not in candidate.parents and candidate != base:\n"
        "        return 'no', 403\n"
        "    os.system('cat ' + str(candidate))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_root_the_attacker_chose_confines_nothing(tmp_path):
    found = _findings(tmp_path, (
        "from pathlib import Path\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    root = request.args.get('root', '')\n"
        "    data = request.args.get('name', '')\n"
        "    base = Path(root).resolve()\n"
        "    candidate = (base / data).resolve()\n"
        "    if base not in candidate.parents and candidate != base:\n"
        "        return 'no', 403\n"
        "    return open(str(candidate)).read()\n"
    ))
    assert [f.rule for f in found] == ["sink.fs.read"]


def test_a_constant_prefix_check_clears_a_read(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('name', '')\n"
        "    base_dir = '/var/app/data'\n"
        "    full = os.path.realpath(os.path.join(base_dir, data))\n"
        "    if not full.startswith(base_dir + os.sep):\n"
        "        return 'no', 403\n"
        "    return open(full).read()\n"
    ))
    assert found == []


def test_an_allow_list_given_a_name_is_the_same_guard_as_one_written_inline(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    allowed = {'config.json', 'index.html'}\n"
        "    data = request.args.get('name', '')\n"
        "    if data not in allowed:\n"
        "        return 'no', 403\n"
        "    return open('/var/app/data/' + data).read()\n"
    ))
    assert found == []


def test_an_allow_list_that_was_widened_stops_being_one(tmp_path):
    """`allowed.add(user_value)` two lines up makes the membership test say
    nothing at all, and the name must stop counting at that line."""
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    allowed = {'config.json'}\n"
        "    data = request.args.get('name', '')\n"
        "    allowed.add(data)\n"
        "    if data not in allowed:\n"
        "        return 'no', 403\n"
        "    return open('/var/app/data/' + data).read()\n"
    ))
    assert [f.rule for f in found] == ["sink.fs.read"]


# -- a fullmatch pattern that forbids one character is not an allow-list ------


def test_a_negated_character_class_is_a_deny_list_however_it_is_anchored(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "import re\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    if not re.fullmatch('^[^\\\\x00]+$', data):\n"
        "        return 'no', 400\n"
        "    os.system('echo ' + data)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_an_enumerated_character_class_still_counts(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "import re\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    if not re.fullmatch('[a-z0-9_-]+', data):\n"
        "        return 'no', 400\n"
        "    os.system('echo ' + data)\n"
    ))
    assert found == []


# -- HTML that is told not to be escaped -------------------------------------


def test_marking_request_data_as_safe_html_is_a_finding(tmp_path):
    found = _findings(tmp_path, (
        "from django.utils.safestring import mark_safe\n"
        "from django.http import HttpResponse\n\n"
        "def show(request):\n"
        "    value = request.GET.get('q', '')\n"
        "    return HttpResponse(mark_safe('<div>' + str(value) + '</div>'))\n"
    ))
    assert [f.rule for f in found] == ["sink.xss"]


def test_escaping_before_marking_it_safe_is_not(tmp_path):
    found = _findings(tmp_path, (
        "import html\n"
        "from django.utils.safestring import mark_safe\n"
        "from django.http import HttpResponse\n\n"
        "def show(request):\n"
        "    value = request.GET.get('q', '')\n"
        "    clean = html.escape(value)\n"
        "    return HttpResponse(mark_safe('<div>' + clean + '</div>'))\n"
    ))
    assert found == []


def test_a_html_cleaner_answers_for_html_and_not_for_a_shell(tmp_path):
    """`bleach.clean` strips tags. It leaves `x; rm -rf /` exactly as it found
    it, so it clears `sink.xss` and must not clear `sink.os.system`."""
    found = _findings(tmp_path, (
        "import bleach\n"
        "import os\n"
        "from django.utils.safestring import mark_safe\n\n"
        "def show(request):\n"
        "    value = request.GET.get('q', '')\n"
        "    clean = bleach.clean(value)\n"
        "    os.system('echo ' + clean)\n"
        "    return mark_safe('<div>' + clean + '</div>')\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_returning_through_a_response_is_not_by_itself_a_finding(tmp_path):
    """Django escapes on the way out. A rule on the response would have fired
    on the safe half of the corpus too and separated nothing."""
    found = _findings(tmp_path, (
        "from django.http import HttpResponse\n\n"
        "def show(request):\n"
        "    value = request.GET.get('q', '')\n"
        "    return HttpResponse(value)\n"
    ))
    assert found == []


# -- open redirect: the host guard proves it, the range guard does not -------
#
# CWE-601 was the one weakness class a rule already claimed — `sink.js.redirect`
# names it — while no Python sink could ever fire on it. The corpus makes the
# separation plain: every vulnerable case is `redirect(tainted)`, and every
# safe one puts `urlparse(...).hostname not in (...)` in front of it. That is
# the guard the engine already understood for outgoing requests.
#
# Which is exactly why the proof had to be split. `_DESTINATION_PROOFS` kept
# host allow-lists and resolved-range checks under one name, "network", and
# they do not prove the same thing. An allow-list says the value names a host
# somebody approved — true for a request and true for a redirect. A range
# check says the resolved address is not private, which stops an SSRF and
# says nothing at all about sending a *user* to an attacker's public site.


def test_a_tainted_redirect_is_an_open_redirect(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request, redirect\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('next', '')\n"
        "    return redirect(url)\n"
    ))
    assert [f.rule for f in found] == ["sink.redirect"]


def test_a_redirect_response_reached_by_keyword_is_caught(tmp_path):
    """FastAPI spells it `RedirectResponse(url=...)`, and the argument is
    named rather than positional."""
    found = _findings(tmp_path, (
        "from fastapi import Request\n"
        "from fastapi.responses import RedirectResponse\n\n"
        "@app.post('/x')\n"
        "async def handler(request: Request):\n"
        "    data = request.headers.get('x-next', '')\n"
        "    return RedirectResponse(url=data)\n"
    ))
    assert [f.rule for f in found] == ["sink.redirect"]


def test_a_host_allow_list_clears_a_redirect(tmp_path):
    found = _findings(tmp_path, (
        "from urllib.parse import urlparse\n"
        "from flask import request, redirect\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('next', '')\n"
        "    parsed = urlparse(url)\n"
        "    if parsed.hostname not in ('a.example', 'b.example'):\n"
        "        return 'no', 403\n"
        "    return redirect(url)\n"
    ))
    assert found == []


def test_a_resolved_range_check_does_not_clear_a_redirect(tmp_path):
    """The guard proves the address is public. A public address is precisely
    where an open redirect sends its victim."""
    found = _findings(tmp_path, (
        "import ipaddress\n"
        "import socket\n"
        "from urllib.parse import urlparse\n"
        "from flask import request, redirect\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('next', '')\n"
        "    parsed = urlparse(url)\n"
        "    resolved = socket.gethostbyname(parsed.hostname or url)\n"
        "    if ipaddress.ip_address(resolved).is_private:\n"
        "        return 'no', 403\n"
        "    return redirect(url)\n"
    ))
    assert [f.rule for f in found] == ["sink.redirect"]


def test_a_range_check_still_clears_an_outgoing_request(tmp_path):
    """The split must not cost the proof it was already making."""
    found = _findings(tmp_path, (
        "import ipaddress\n"
        "import socket\n"
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    url = request.args.get('url', '')\n"
        "    parsed = urlparse(url)\n"
        "    resolved = socket.gethostbyname(parsed.hostname or url)\n"
        "    if ipaddress.ip_address(resolved).is_private:\n"
        "        return 'no', 403\n"
        "    requests.get(resolved)\n"
    ))
    assert found == []


# -- three injection sinks the corpus reaches and the catalog did not --------


def test_a_tainted_django_template_source_is_ssti(tmp_path):
    found = _findings(tmp_path, (
        "from django.template import Template, Context\n"
        "from django.http import HttpResponse\n\n"
        "def view(request):\n"
        "    data = request.META.get('HTTP_USER_AGENT', '')\n"
        "    return HttpResponse(Template(data).render(Context()))\n"
    ))
    assert [f.rule for f in found] == ["sink.template"]


def test_a_literal_template_rendering_tainted_context_is_not_ssti(tmp_path):
    """The distinction the whole rule rests on. `Template('{{ v }}')` compiles
    a constant and hands the value to an engine that escapes it; the corpus
    safe half of `xss` is exactly this shape, and a rule on the call rather
    than on its first argument would have fired on all of it."""
    found = _findings(tmp_path, (
        "from django.template import Template, Context\n"
        "from django.http import HttpResponse\n\n"
        "def view(request):\n"
        "    data = request.META.get('HTTP_USER_AGENT', '')\n"
        "    return HttpResponse("
        "Template('{{ value }}').render(Context({'value': data})))\n"
    ))
    assert found == []


def test_render_template_string_is_the_flask_spelling(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request, render_template_string\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('t', '')\n"
        "    return render_template_string(data)\n"
    ))
    assert [f.rule for f in found] == ["sink.template"]


def test_a_shape_guard_clears_a_template(tmp_path):
    found = _findings(tmp_path, (
        "import re\n"
        "from flask import request, render_template_string\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('t', '')\n"
        "    if not re.fullmatch(r'[a-zA-Z0-9_-]+', data):\n"
        "        return 'no', 400\n"
        "    return render_template_string(data)\n"
    ))
    assert found == []


def test_a_tainted_xpath_expression_is_caught(tmp_path):
    found = _findings(tmp_path, (
        "from lxml import etree\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('n', '')\n"
        "    tree = etree.fromstring(b'<u/>')\n"
        "    tree.xpath('/users/user[@name=\"' + data + '\"]')\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.xpath"]


def test_a_tainted_ldap_filter_is_caught(tmp_path):
    """The filter is the third argument; the base and the scope are not it."""
    found = _findings(tmp_path, (
        "import ldap\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('u', '')\n"
        "    conn = ldap.initialize('ldap://localhost:389')\n"
        "    conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE,"
        " '(uid=' + data + ')')\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.ldap"]


def test_a_tainted_ldap_base_is_not_the_filter(tmp_path):
    """`dangerous_args` earns its keep here: a search base is chosen by the
    application, and treating it as the injection point would double the
    rule's surface for nothing."""
    found = _findings(tmp_path, (
        "import ldap\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('u', '')\n"
        "    conn = ldap.initialize('ldap://localhost:389')\n"
        "    conn.search_s(data, ldap.SCOPE_SUBTREE, '(uid=admin)')\n"
        "    return 'ok'\n"
    ))
    assert found == []


# -- NoSQL: the same lesson `sql:text` already paid for --------------------
#
# The sink is `.find(...)`, a name every string and list in Python also
# answers to, and the driver is not imported where the query is written —
# `from app_runtime import mongo_db` is the shape, exactly as `db.execute`
# was. An import gate scores zero on that. What says Mongo is the query
# document itself: a quoted `$where`, `$ne`, `$regex` is not something any
# other library writes.


def test_a_tainted_mongo_query_is_caught(tmp_path):
    found = _findings(tmp_path, (
        "from app_runtime import mongo_db\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('u', '')\n"
        "    mongo_db.users.find({'$where': \"this.n == '\" + data + \"'\"})\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.nosql"]


def test_find_without_a_mongo_operator_is_a_string_method(tmp_path):
    """The gate is the whole rule. Without it every `.find(` in Python — and
    there are a great many — becomes a database query."""
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('u', '')\n"
        "    haystack = 'abcdef'\n"
        "    return str(haystack.find(data))\n"
    ))
    assert found == []


def test_an_allow_list_clears_a_mongo_query(tmp_path):
    found = _findings(tmp_path, (
        "from app_runtime import mongo_db\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('sort', '')\n"
        "    if data not in ('asc', 'desc', 'name', 'created'):\n"
        "        return 'no', 400\n"
        "    mongo_db.users.find({'$where': \"this.n == '\" + data + \"'\"})\n"
        "    return 'ok'\n"
    ))
    assert found == []


# -- response headers, and the guard that is only true inside its block -----


def test_a_tainted_response_header_is_caught(tmp_path):
    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    data = request.META.get('HTTP_X_CUSTOM', '')\n"
        "    return JsonResponse({'s': 'ok'}, status=200,"
        " headers={'Content-Language': str(data)})\n"
    ))
    assert [f.rule for f in found] == ["sink.header"]


def test_the_flask_spelling_is_the_third_element_of_a_returned_tuple(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request, jsonify\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('h', '')\n"
        "    return jsonify({'s': 'ok'}), 200, {'Content-Language': str(data)}\n"
    ))
    assert [f.rule for f in found] == ["sink.header"]


def test_a_reflected_origin_is_cors_and_not_header_injection(tmp_path):
    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    data = request.body.decode('utf-8')\n"
        "    return JsonResponse({'s': 'ok'},"
        " headers={'Access-Control-Allow-Origin': str(data)})\n"
    ))
    assert [f.rule for f in found] == ["sink.cors"]


def test_a_dict_of_data_is_not_a_dict_of_headers(tmp_path):
    """Position is the gate. A key that merely looks like a header name is
    not one, and matching on the key alone would make every `{'first-name':
    value}` in the corpus a response header."""
    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    data = request.META.get('HTTP_X_CUSTOM', '')\n"
        "    return JsonResponse({'first-name': str(data)}, status=200)\n"
    ))
    assert found == []


def test_a_positive_allow_list_clears_its_own_block(tmp_path):
    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    data = request.body.decode('utf-8')\n"
        "    allowed = {'https://a.example', 'https://b.example'}\n"
        "    origin = str(data)\n"
        "    if origin in allowed:\n"
        "        return JsonResponse({'s': 'ok'},"
        " headers={'Access-Control-Allow-Origin': origin})\n"
        "    return JsonResponse({'saved': True})\n"
    ))
    assert found == []


def test_a_positive_allow_list_clears_nothing_after_its_block(tmp_path):
    """The whole difference from `if x not in allowed: return`. That one
    refuses, so the constraint holds for everything below it. This one
    constrains the value inside the block and says nothing about the line
    after — treating the two alike would launder the second use."""
    found = _findings(tmp_path, (
        "import os\n\n"
        "def view(request):\n"
        "    data = request.body.decode('utf-8')\n"
        "    if data in ('a', 'b'):\n"
        "        pass\n"
        "    os.system('echo ' + data)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_removing_cr_and_lf_clears_a_header(tmp_path):
    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    data = request.META.get('HTTP_X_CUSTOM', '')\n"
        "    clean = str(data).replace('\\r', '').replace('\\n', '')\n"
        "    return JsonResponse({'s': 'ok'},"
        " headers={'Content-Language': str(clean)})\n"
    ))
    assert found == []


def test_removing_cr_and_lf_clears_nothing_else(tmp_path):
    """It defeats header injection, whose mechanism is those two characters,
    and it defeats nothing else: every metacharacter a shell knows survives
    it untouched."""
    found = _findings(tmp_path, (
        "import os\n\n"
        "def view(request):\n"
        "    data = request.body.decode('utf-8')\n"
        "    clean = str(data).replace('\\r', '').replace('\\n', '')\n"
        "    os.system('echo ' + clean)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_werkzeug_hands_the_raw_body_through_get_data(tmp_path):
    """`request.data` does not cover it: prefix matching reaches
    `request.data.something`, never a different method on the same object."""
    found = _findings(tmp_path, (
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.get_data(as_text=True)\n"
        "    os.system('echo ' + str(data))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_crlf_strip_buried_in_a_larger_expression_still_proves_it(tmp_path):
    """The ordinary shape, and 27 false positives before it was read: the
    chain sits inside `re.sub`, so a helper that only walked the outermost
    call saw a substitution and stopped."""
    found = _findings(tmp_path, (
        "import re\n"
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    data = request.body.decode('utf-8')\n"
        "    clean = re.sub(r'[A-Za-z0-9]{4,}', '****',"
        " str(data).replace('\\r', '').replace('\\n', ''))\n"
        "    return JsonResponse({'s': 'ok'},"
        " headers={'Content-Language': str(clean)})\n"
    ))
    assert found == []


def test_a_crlf_strip_on_one_operand_proves_nothing_about_the_other(tmp_path):
    """What keeps the previous test from being a licence to launder. The
    chain cleaned `first`; `second` reached the header untouched."""
    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    first = request.GET.get('a', '')\n"
        "    second = request.GET.get('b', '')\n"
        "    joined = first.replace('\\r', '').replace('\\n', '') + second\n"
        "    return JsonResponse({'s': 'ok'},"
        " headers={'Content-Language': str(joined)})\n"
    ))
    assert [f.rule for f in found] == ["sink.header"]


# -- a spreadsheet is not a text file --------------------------------------


def test_untrusted_data_written_to_a_csv_is_caught(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('v', '')\n"
        "    with open('output.csv', 'a') as fh:\n"
        "        fh.write(str(data) + ',data\\n')\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.csv"]


def test_writing_the_same_value_to_a_log_is_not_csv_injection(tmp_path):
    """The suffix is the whole rule. `.write` is the most common method name
    in Python and a rule on it alone would fire on every file a program
    opens; what makes a cell dangerous is that a spreadsheet will evaluate
    it."""
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('v', '')\n"
        "    with open('output.log', 'a') as fh:\n"
        "        fh.write(str(data) + '\\n')\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_an_allow_list_clears_a_csv_write(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('v', '')\n"
        "    if data not in ('asc', 'desc'):\n"
        "        return 'no', 400\n"
        "    with open('output.csv', 'a') as fh:\n"
        "        fh.write(str(data) + ',data\\n')\n"
        "    return 'ok'\n"
    ))
    assert found == []


# -- a file called secrets.txt --------------------------------------------


def test_untrusted_data_stored_in_cleartext_is_caught(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.headers.get('Authorization', '')\n"
        "    with open('/var/data/secrets.txt', 'w') as fh:\n"
        "        fh.write(str(data))\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.cleartext"]


def test_an_ordinary_file_is_not_a_secret_store(tmp_path):
    """The name is the whole rule. Writing a request value to a file is what
    programs do; writing it to one called `secrets.txt` is the finding."""
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.headers.get('Authorization', '')\n"
        "    with open('/var/data/report.txt', 'w') as fh:\n"
        "        fh.write(str(data))\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_encrypting_before_the_write_clears_it(tmp_path):
    found = _findings(tmp_path, (
        "import os\n"
        "from cryptography.fernet import Fernet\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.headers.get('Authorization', '')\n"
        "    sealed = Fernet(os.environ['K'].encode()).encrypt(str(data).encode())\n"
        "    with open('/var/data/secrets.enc', 'wb') as fh:\n"
        "        fh.write(sealed)\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_hashing_before_the_write_clears_it_too(tmp_path):
    """And `hashlib.sha256` is the right answer here, which is exactly why it
    is the wrong answer for `weak_password_hash`: a digest is not cleartext,
    and it is also not a password-hashing function."""
    found = _findings(tmp_path, (
        "import hashlib\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.headers.get('Authorization', '')\n"
        "    digest = hashlib.sha256(str(data).encode()).hexdigest()\n"
        "    with open('/var/data/secrets.txt', 'w') as fh:\n"
        "        fh.write(digest)\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_a_digest_still_proves_nothing_to_a_shell(tmp_path):
    """The proof is keyed to storage. Hashing says the value on disk is not
    the secret; it says nothing about handing it to `sh`."""
    found = _findings(tmp_path, (
        "import os\n"
        "import hashlib\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('a', '')\n"
        "    digest = hashlib.sha256(str(data).encode()).hexdigest()\n"
        "    os.system('echo ' + digest)\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


# -- a callback that writes to the scope that made it -----------------------


def test_taint_travels_through_a_nonlocal_callback(tmp_path):
    """The ordinary shape of a callback in Python: a nested function is
    handed the value and writes it into the name the caller reads back.
    Without this the chain broke at `collected`, which is read one line later
    and is exactly as untrusted as what went in."""
    found = _findings(tmp_path, (
        "import os\n\n"
        "def view(request):\n"
        "    incoming = request.COOKIES.get('token', '')\n"
        "    collected = None\n"
        "    def on_ready(value):\n"
        "        nonlocal collected\n"
        "        collected = value\n"
        "    on_ready(incoming)\n"
        "    os.system('echo ' + str(collected))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_callback_handed_a_constant_taints_nothing(tmp_path):
    """The argument is what matters, not the callback."""
    found = _findings(tmp_path, (
        "import os\n\n"
        "def view(request):\n"
        "    collected = None\n"
        "    def on_ready(value):\n"
        "        nonlocal collected\n"
        "        collected = value\n"
        "    on_ready('constant')\n"
        "    os.system('echo ' + str(collected))\n"
    ))
    assert found == []


def test_taint_travels_through_a_dict_used_as_a_relay(tmp_path):
    """`box['k'] = value` marks the container, the way appending to a list
    already did. The read side renders `box['k']` as `box`, so both ends of
    the assignment agree on one name."""
    found = _findings(tmp_path, (
        "import os\n\n"
        "request_state: dict[str, str] = {}\n\n"
        "def view(request):\n"
        "    incoming = request.COOKIES.get('token', '')\n"
        "    request_state['last_input'] = incoming\n"
        "    data = request_state['last_input']\n"
        "    os.system('echo ' + str(data))\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_a_dict_that_only_ever_held_constants_taints_nothing(tmp_path):
    found = _findings(tmp_path, (
        "import os\n\n"
        "def view(request):\n"
        "    box = {}\n"
        "    box['k'] = 'constant'\n"
        "    os.system('echo ' + str(box['k']))\n"
    ))
    assert found == []


def test_django_spells_two_of_its_sources_in_capitals(tmp_path):
    """Their absence hid no taint — `request` is a view's parameter, so what
    is read off it is untrusted whatever the catalogue says. What it hid was
    *which* rule started the path, and for a travel-sensitive sink that is
    the finding: with no source attributed, `impact_for` discounts
    `sink.fs.read` from medium to low, and low is under the floor a default
    report prints. The path was found and nobody saw it."""
    from thot.contracts import Severity

    found = _findings(tmp_path, (
        "from django.http import JsonResponse\n\n"
        "def view(request):\n"
        "    referer = request.META.get('HTTP_REFERER', '')\n"
        "    with open('/var/app/data/' + str(referer), 'w') as fh:\n"
        "        fh.write('x')\n"
        "    return JsonResponse({})\n"
    ))
    assert [(f.rule, f.severity) for f in found] == [
        ("sink.fs.read", Severity.MEDIUM)
    ]


# -- a response that declares itself HTML ----------------------------------


def test_an_html_response_built_from_a_request_value_is_xss(tmp_path):
    """`HTMLResponse` is not `HttpResponse`. Django's escapes on the way out
    and returning a value through it is what a view does — which is why it is
    deliberately absent from this catalogue. Starlette's *declares* the body
    to be HTML and escapes nothing."""
    found = _findings(tmp_path, (
        "from fastapi import Request\n"
        "from starlette.responses import HTMLResponse\n\n"
        "@app.post('/x')\n"
        "async def handler(request: Request):\n"
        "    data = request.headers.get('referer', '')\n"
        "    return HTMLResponse('<div>' + str(data) + '</div>')\n"
    ))
    assert [f.rule for f in found] == ["sink.xss"]


def test_html_escape_from_the_standard_library_clears_it(tmp_path):
    """`markupsafe.escape` and `bleach.clean` were known; the one in the
    standard library was not, and the corpus reaches for it 66 times."""
    found = _findings(tmp_path, (
        "import html\n"
        "from fastapi import Request\n"
        "from starlette.responses import HTMLResponse\n\n"
        "@app.post('/x')\n"
        "async def handler(request: Request):\n"
        "    data = request.headers.get('referer', '')\n"
        "    safe = html.escape(str(data))\n"
        "    return HTMLResponse('<div>' + safe + '</div>')\n"
    ))
    assert found == []


def test_an_autoescaping_render_of_a_literal_template_clears_it(tmp_path):
    """Two facts together, and neither alone would do: the template is a
    constant, so this is not template injection, and the environment escapes,
    so the value it interpolates cannot close a tag."""
    found = _findings(tmp_path, (
        "from jinja2 import Environment\n"
        "from fastapi import Request\n"
        "from starlette.responses import HTMLResponse\n\n"
        "@app.post('/x')\n"
        "async def handler(request: Request):\n"
        "    data = request.headers.get('referer', '')\n"
        "    return HTMLResponse(Environment(autoescape=True)"
        ".from_string('{{ value }}').render(value=data))\n"
    ))
    assert found == []


def test_an_environment_that_does_not_escape_proves_nothing(tmp_path):
    """The keyword is the proof. Without it Jinja2 does not escape, and the
    same call is the same bug."""
    found = _findings(tmp_path, (
        "from jinja2 import Environment\n"
        "from fastapi import Request\n"
        "from starlette.responses import HTMLResponse\n\n"
        "@app.post('/x')\n"
        "async def handler(request: Request):\n"
        "    data = request.headers.get('referer', '')\n"
        "    return HTMLResponse(Environment(autoescape=False)"
        ".from_string('{{ value }}').render(value=data))\n"
    ))
    assert [f.rule for f in found] == ["sink.xss"]


def test_a_route_returning_a_raw_html_body_is_xss(tmp_path):
    """A Flask view that returns a string has it sent as `text/html`. The
    route decorator is the gate: a helper that happens to build markup is
    not a response."""
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    return '<div>' + str(data) + '</div>'\n"
    ))
    assert [f.rule for f in found] == ["sink.xss"]


def test_an_f_string_body_is_the_same_body(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    return f'<div>{data}</div>'\n"
    ))
    assert [f.rule for f in found] == ["sink.xss"]


def test_a_helper_that_builds_markup_is_not_a_response(tmp_path):
    """Without the decorator nothing says this string reaches a browser, and
    a rule on the shape of the text alone would fire on every template
    fragment a program assembles."""
    found = _findings(tmp_path, (
        "from flask import request\n\n"
        "def fragment(value):\n"
        "    return '<div>' + str(value) + '</div>'\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_an_escaped_body_returned_from_a_route_is_clear(tmp_path):
    found = _findings(tmp_path, (
        "import html\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    return '<div>' + html.escape(str(data)) + '</div>'\n"
    ))
    assert found == []


def test_an_html_escape_proves_nothing_to_a_shell(tmp_path):
    """`html.escape` turns five characters into entities. A semicolon is not
    one of them, and neither is a backtick, a pipe or `$(`.

    It sat in the general sanitiser list, where a sanitiser stops the walk
    outright — so the shell below was silenced by a defence that does not
    defend it. The escape is real and it belongs with the other proofs that
    are keyed to the one destination they cover."""
    found = _findings(tmp_path, (
        "import html\n"
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    os.system('ping ' + html.escape(str(data)))\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_an_escape_stored_first_proves_nothing_to_a_shell_either(tmp_path):
    """The same fact, written the way a program usually writes it."""
    found = _findings(tmp_path, (
        "import html\n"
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    safe = html.escape(str(data))\n"
        "    os.system('ping ' + safe)\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_an_autoescaping_render_proves_nothing_to_a_shell(tmp_path):
    """Escaping a template's output makes it safe to put in a page. It says
    nothing about handing the same string to `sh -c`."""
    found = _findings(tmp_path, (
        "import os\n"
        "from jinja2 import Environment\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    os.system('ping ' + Environment(autoescape=True)"
        ".from_string('{{ value }}').render(value=data))\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_markupsafe_escape_still_clears_a_page(tmp_path):
    """What the change must not cost: the escapes are still escapes, and the
    only question is which destination they are allowed to clear."""
    found = _findings(tmp_path, (
        "from markupsafe import escape\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('q', '')\n"
        "    return '<div>' + escape(str(data)) + '</div>'\n"
    ))
    assert found == []


def test_a_doubled_delimiter_quotes_a_sql_identifier(tmp_path):
    """The ANSI way to put a name in a query: wrap it in the delimiter and
    double every one the value contains. `"` becomes `""`, which cannot end
    the identifier, and there is nothing left for the value to escape into.

    These are the last three false positives the corpus produced."""
    found = _findings(tmp_path, (
        "from flask import request\n"
        "from app_runtime import db\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('table', '')\n"
        "    db.execute('SELECT * FROM \"' + str(data).replace('\"', '\"\"')"
        " + '\"')\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_doubling_a_delimiter_the_query_does_not_use_proves_nothing(tmp_path):
    """Doubling `\"` while the query quotes with `'` doubles a character the
    parser will never look at, and leaves the one that ends the string."""
    found = _findings(tmp_path, (
        "from flask import request\n"
        "from app_runtime import db\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('table', '')\n"
        '    db.execute("SELECT * FROM \'" + str(data).replace(\'"\', \'""\')'
        ' + "\'")\n'
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.sql"]


def test_a_doubled_delimiter_with_nothing_around_it_proves_nothing(tmp_path):
    """Escaping a quote is only a defence if the value is inside one."""
    found = _findings(tmp_path, (
        "from flask import request\n"
        "from app_runtime import db\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('table', '')\n"
        "    db.execute('SELECT * FROM ' + str(data).replace('\"', '\"\"'))\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.sql"]


def test_a_quoted_identifier_proves_nothing_to_a_shell(tmp_path):
    """The delimiter belongs to SQL. A shell reads a different alphabet, and
    doubling a double quote hands it `;` untouched."""
    found = _findings(tmp_path, (
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    os.system('echo \"' + str(request.args.get('q', ''))"
        ".replace('\"', '\"\"') + '\"')\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.os.system"]


def test_only_the_quoted_operand_is_cleared(tmp_path):
    """One value quoted does not quote the one concatenated after it."""
    found = _findings(tmp_path, (
        "from flask import request\n"
        "from app_runtime import db\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    table = request.args.get('table', '')\n"
        "    where = request.args.get('where', '')\n"
        "    db.execute('SELECT * FROM \"' + str(table).replace('\"', '\"\"')"
        " + '\" WHERE ' + str(where))\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.sql"]


def test_a_query_quoted_into_a_variable_first_is_cleared_too(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request\n"
        "from app_runtime import db\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    data = request.args.get('table', '')\n"
        "    query = 'SELECT * FROM \"' + str(data).replace('\"', '\"\"')"
        " + '\"'\n"
        "    db.execute(query)\n"
        "    return 'ok'\n"
    ))
    assert found == []


def test_a_variable_query_with_one_operand_left_outside_is_not(tmp_path):
    found = _findings(tmp_path, (
        "from flask import request\n"
        "from app_runtime import db\n\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    table = request.args.get('table', '')\n"
        "    where = request.args.get('where', '')\n"
        "    query = 'SELECT * FROM \"' + str(table).replace('\"', '\"\"')"
        " + '\" WHERE ' + str(where)\n"
        "    db.execute(query)\n"
        "    return 'ok'\n"
    ))
    assert [f.rule for f in found] == ["sink.sql"]
