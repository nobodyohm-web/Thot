from thot.codemap.catalog import DEFAULT_SINKS, match_sink, match_source
from thot.contracts import Severity


def test_os_system_is_a_critical_sink():
    rule = match_sink("os.system")
    assert rule is not None
    assert rule.impact == Severity.CRITICAL


def test_dict_get_is_not_a_network_call():
    """`args.get(...)` must not match `requests.get` — the single largest
    source of false positives when matching on the last segment alone."""
    assert match_sink("args.get") is None
    assert match_sink("payload.post") is None


def test_re_compile_is_not_the_eval_builtin():
    assert match_sink("re.compile") is None
    assert match_sink("py_compile.compile") is None


def test_db_method_matches_on_any_receiver():
    """`execute` is a method: its receiver is never statically known."""
    assert match_sink("cursor.execute") is not None
    assert match_sink("self.conn.execute") is not None


def test_qualified_sink_still_matches_its_full_name():
    assert match_sink("requests.get") is not None
    assert match_sink("subprocess.run") is not None


def test_unknown_call_is_not_a_sink():
    assert match_sink("json.dumps") is None


def test_sys_argv_is_a_source():
    assert match_source("sys.argv") is not None


def test_every_sink_rule_id_is_unique():
    ids = [rule.id for rule in DEFAULT_SINKS]
    assert len(ids) == len(set(ids))


# -- sources reached through a method call -----------------------------------
# `request.args.get("x")` and `os.environ.get("X")` are how untrusted data is
# actually read. Matching only the bare attribute missed every one of them.


def test_http_source_matches_through_get():
    assert match_source("request.args.get") is not None
    assert match_source("request.form.get") is not None
    assert match_source("request.get_json") is not None


def test_environment_source_matches_through_get():
    assert match_source("os.environ.get") is not None


def test_http_source_still_matches_the_bare_attribute():
    assert match_source("request.args") is not None


def test_a_qualified_http_source_matches():
    assert match_source("flask.request.args.get") is not None


def test_an_unrelated_attribute_is_not_a_source():
    assert match_source("self.request_count") is None
    assert match_source("payload.get") is None
    assert match_source("config.args.get") is None


# -- ouvrir un fichier dont l'appelant choisit le chemin --------------------
#
# La traversée de chemin passait entièrement au travers : `sink.fs.write`
# couvre `shutil.move` et `os.remove`, jamais `open`. Un corpus de onze
# classes de vulnérabilité en montrait sept détectées ; celle-ci était l'une
# des quatre manquantes, et c'est CWE-22.
#
# Le prix, mesuré avant d'ajouter la règle : 0 candidat supplémentaire sur
# Thot (14), sur Prime (25) et sur Hermes (401 → 401). Elle ne se déclenche
# que lorsqu'une valeur teintée atteint l'appel, ce qu'aucun de ces trois
# arbres ne fait — et elle transforme au passage trois détections « motif
# seul » du corpus (pickle, yaml.load, `with open(...) as`) en chemins de
# teinte prouvés, puisque le fichier ouvert était déjà le vecteur.


def test_open_is_a_filesystem_sink():
    rule = match_sink("open")

    assert rule is not None
    assert rule.id == "sink.fs.read"


def test_a_method_named_open_is_not_the_builtin():
    """`socket.open`, `driver.open`, `self.open` n'ouvrent pas un chemin."""
    assert match_sink("connexion.open") is None


def test_a_tainted_path_reaching_open_is_found(tmp_path):
    from thot.codemap.graph import CodeGraph
    from thot.codemap.index import forget_symbols, index_files
    from thot.pipeline import findings_from_graph
    from thot.scope.detect import detect_scope

    (tmp_path / "lecture.py").write_text(
        "import sys\n"
        "def main():\n"
        "    return open('/data/' + sys.argv[1]).read()\n",
        encoding="utf-8",
    )
    forget_symbols()
    manifest = detect_scope(tmp_path)
    symbols = index_files(tmp_path, manifest.files)
    findings = findings_from_graph(
        tmp_path, CodeGraph.build(symbols, manifest.entrypoints)
    )

    assert any(f.rule == "sink.fs.read" for f in findings), [f.rule for f in findings]
