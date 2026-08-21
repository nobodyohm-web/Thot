from thot.codemap.catalog import DEFAULT_SINKS, match_sink, match_source
from thot.contracts import Severity


def test_os_system_is_a_critical_sink():
    rule = match_sink("os.system")
    assert rule is not None
    assert rule.impact == Severity.CRITICAL


def test_bare_call_name_matches_on_the_suffix():
    assert match_sink("system") is not None


def test_unknown_call_is_not_a_sink():
    assert match_sink("json.dumps") is None


def test_sys_argv_is_a_source():
    assert match_source("sys.argv") is not None


def test_every_sink_rule_id_is_unique():
    ids = [rule.id for rule in DEFAULT_SINKS]
    assert len(ids) == len(set(ids))
