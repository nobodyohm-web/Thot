"""One identity is one defect, however many paths reach it.

`compute_id` deliberately leaves the taint path out, so a verdict survives a
refactor of the caller. Two sources reaching one sink therefore share an
identity — and the report printed the row twice, the counts double-counted
it, and the panel could spend its budget arguing it twice. Measured on
Hermes: three identifiers appeared twice each.
"""

from __future__ import annotations

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.pipeline import _keep_stronger


def at(line: int, severity: Severity, *, paths: int | None = None) -> Finding:
    location = CodeRef(path="app.ts", line=line, symbol="run", ast_hash="h")
    return Finding(
        id=Finding.compute_id("sink.js.path", location),
        rule="sink.js.path",
        severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=location,
        provenance=({"chemins": paths} if paths else None),
    )


def test_two_paths_to_one_sink_share_an_identity():
    assert at(10, Severity.LOW).id == at(10, Severity.HIGH).id


def test_the_stronger_score_is_the_one_kept():
    merged = _keep_stronger(at(10, Severity.LOW), at(10, Severity.HIGH))
    assert merged.severity is Severity.HIGH


def test_a_weaker_second_path_does_not_demote():
    merged = _keep_stronger(at(10, Severity.HIGH), at(10, Severity.LOW))
    assert merged.severity is Severity.HIGH


def test_the_number_of_paths_is_kept():
    """Three inputs reaching one sink is worth knowing, not worth hiding."""
    merged = _keep_stronger(at(10, Severity.LOW), at(10, Severity.LOW))
    assert merged.provenance["chemins"] == 2
    again = _keep_stronger(merged, at(10, Severity.LOW))
    assert again.provenance["chemins"] == 3


def test_merging_keeps_what_the_winner_already_said():
    kept = at(10, Severity.LOW)
    other = at(10, Severity.HIGH)
    other = Finding(**{**other.__dict__, "provenance": {"rôle": "test"}})
    merged = _keep_stronger(kept, other)
    assert merged.provenance["rôle"] == "test"
    assert merged.provenance["chemins"] == 2


def test_the_pipeline_returns_one_finding_per_identity(monkeypatch):
    """Two candidates, one sink, one row — measured on Hermes as three
    identifiers appearing twice each before this."""
    from pathlib import Path

    from thot import pipeline
    from thot.taint.engine import TaintCandidate

    sink = CodeRef(path="app.ts", line=219, symbol="run", ast_hash="h")
    source_a = CodeRef(path="app.ts", line=151, symbol="run", ast_hash="h")
    source_b = CodeRef(path="app.ts", line=195, symbol="run", ast_hash="h")

    def two_paths(*args, **kwargs):
        return [
            TaintCandidate("sink.js.path", source_a, sink, (source_a, sink),
                           Severity.HIGH, "Écriture"),
            TaintCandidate("sink.js.path", source_b, sink, (source_b, sink),
                           Severity.HIGH, "Écriture"),
        ]

    monkeypatch.setattr(pipeline, "find_candidates", two_paths)
    monkeypatch.setattr("thot.taint.js_engine.find_candidates",
                        lambda *a, **k: [])

    class Graph:
        entrypoints = ()
        symbols: dict = {}

        def distance_from_entrypoints(self, name):
            return 1

        def reach_unknown(self, name):
            return False

    found = pipeline.findings_from_graph(Path("."), Graph())
    assert len(found) == 1, found
    assert found[0].provenance["chemins"] == 2
