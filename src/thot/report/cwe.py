"""The CWE each rule is an instance of.

A SARIF document without a taxonomy is unscoreable. Every labelled corpus
states its ground truth as a CWE — OWASP BenchmarkPython, BenchProctor and
the rest all key their expected results on it — so a scorer given a report
with `ruleId` and nothing else has no way to decide whether `sink.sql`
firing on a SQL-injection case is a hit or a coincidence. It matches on
nothing and reports a true-positive rate of zero, for a wiring reason rather
than a detection one.

Which is the more expensive silence: without a taxonomy Thot cannot be
measured against anything, and a rule that cannot be measured cannot be
retired. `scoring/prior.py` ranks rules on this machine's own history; this
is what lets the same question be asked against a corpus with a known answer.

A rule with no honest mapping is absent from this table rather than assigned
an approximate one. `pattern.github_actions_workflow` warns that a workflow
file is being edited — that is a reminder, not a weakness class, and giving
it a CWE would put a wrong answer in front of a scorer that trusts it.
"""

from __future__ import annotations

from functools import lru_cache

# Sinks answer "what does the dangerous call do", patterns answer "what does
# this shape of code look like"; both land on the same weakness classes.
CWE_BY_RULE: dict[str, tuple[str, ...]] = {
    # -- Python sinks ---------------------------------------------------
    "sink.os.system": ("CWE-78",),
    "sink.subprocess.shell": ("CWE-78",),
    "sink.eval": ("CWE-94", "CWE-95"),
    "sink.xss": ("CWE-79", "CWE-80"),
    "sink.deserialization": ("CWE-502",),
    "sink.sql": ("CWE-89",),
    "sink.fs.write": ("CWE-22",),
    "sink.fs.read": ("CWE-22",),
    "sink.network": ("CWE-918",),
    "sink.redirect": ("CWE-601",),
    # -- JavaScript / TypeScript sinks ----------------------------------
    "sink.js.exec": ("CWE-78",),
    "sink.js.spawn": ("CWE-78",),
    "sink.js.eval": ("CWE-94", "CWE-95"),
    "sink.js.dynamic_require": ("CWE-94", "CWE-829"),
    "sink.js.sql": ("CWE-89",),
    "sink.js.html": ("CWE-79",),
    "sink.js.dangerous_html": ("CWE-79",),
    "sink.js.path": ("CWE-22",),
    "sink.js.redirect": ("CWE-601",),
    "sink.js.prototype": ("CWE-1321",),
    # -- Pattern rules ---------------------------------------------------
    "pattern.child_process_exec": ("CWE-78",),
    "pattern.os_system_injection": ("CWE-78",),
    "pattern.python_subprocess_shell": ("CWE-78",),
    "pattern.go_exec_shell_injection": ("CWE-78",),
    "pattern.eval_injection": ("CWE-95",),
    "pattern.new_function_injection": ("CWE-95",),
    "pattern.innerHTML_xss": ("CWE-79",),
    "pattern.outerHTML_xss": ("CWE-79",),
    "pattern.insertAdjacentHTML_xss": ("CWE-79",),
    "pattern.document_write_xss": ("CWE-79",),
    "pattern.react_dangerously_set_html": ("CWE-79",),
    "pattern.pickle_deserialization": ("CWE-502",),
    "pattern.pickle_variants_load": ("CWE-502",),
    "pattern.pickle_wrapper_load": ("CWE-502",),
    "pattern.marshal_loads": ("CWE-502",),
    "pattern.shelve_open": ("CWE-502",),
    "pattern.torch_unsafe_load": ("CWE-502",),
    "pattern.unsafe_yaml_load": ("CWE-502",),
    "pattern.yaml_unsafe_load_variants": ("CWE-502",),
    "pattern.xml_unsafe_parse": ("CWE-611",),
    "pattern.tls_verification_disabled": ("CWE-295",),
    "pattern.aes_ecb_mode": ("CWE-327",),
    "pattern.node_createcipher_no_iv": ("CWE-327", "CWE-329"),
    "pattern.script_src_without_sri": ("CWE-829",),
    "pattern.hardcoded_credential": ("CWE-798",),
    "pattern.hardcoded_secret_assignment": ("CWE-798",),
}


# Thot's own pattern rules carry their class on the rule itself, so the two
# cannot drift apart. Merged rather than transcribed: a class written twice is
# a class that will disagree with itself, and a wrong one here makes a working
# rule measure as a failure against any labelled corpus.
def _with_thot_rules() -> dict[str, tuple[str, ...]]:
    from thot.guard.audit_rules import cwe_map

    merged = dict(CWE_BY_RULE)
    merged.update(cwe_map())
    return merged


@lru_cache(maxsize=1)
def _all_rules() -> dict[str, tuple[str, ...]]:
    return _with_thot_rules()


def all_rules() -> dict[str, tuple[str, ...]]:
    """Every rule that names a weakness class, forked catalogue and ours.

    Public because asking "does any rule claim this class" is a different
    question from "what class is this rule", and answering it from
    `CWE_BY_RULE` silently leaves out the thirteen rules that carry their
    own class.
    """
    return dict(_all_rules())


def cwes(rule_id: str) -> tuple[str, ...]:
    """The CWE identifiers a rule maps to, empty when none is honest."""
    return _all_rules().get(rule_id, ())


def cwe_tags(rule_id: str) -> list[str]:
    """The same mapping in the tag form scanning services read.

    GitHub code scanning keys off `external/cwe/cwe-089`; the number is
    zero-padded to three digits there and not padded beyond it, so `CWE-1321`
    stays four wide.
    """
    return [f"external/cwe/cwe-{number(rule):03d}" for rule in cwes(rule_id)]


def number(cwe: str) -> int:
    """`CWE-89` → `89`."""
    return int(cwe.split("-", 1)[1])
