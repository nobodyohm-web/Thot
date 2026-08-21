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
