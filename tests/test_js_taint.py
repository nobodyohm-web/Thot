"""Proven source-to-sink paths in JavaScript and TypeScript.

The engine claims one level: inside a single function body. What matters in
these tests is as much what it refuses to report as what it finds — a taint
engine that reports plausible paths instead of proven ones is a pattern
scanner wearing a costume.
"""

from __future__ import annotations

from pathlib import Path

from thot.codemap.index import index_files
from thot.taint import js_engine


def scan(tmp_path: Path, source: str, name: str = "app.ts") -> list:
    (tmp_path / name).write_text(source, encoding="utf-8")
    symbols = index_files(tmp_path, [name])
    return js_engine.find_candidates(tmp_path, symbols)


REQUIRE = 'const { exec } = require("child_process");\n'


def test_a_request_value_reaching_exec_is_a_path(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const target = req.query.host;
          exec("ping -c1 " + target);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.exec"]
    assert found[0].sink.symbol.endswith("handler")


def test_the_path_is_not_reported_without_the_import(tmp_path):
    """`exec` is a name anyone may use. The module gate is what makes it usable."""
    found = scan(tmp_path, """
        function handler(req, res) {
          const target = req.query.host;
          exec("ping -c1 " + target);
        }
        """)
    assert found == []


def test_a_sanitised_value_is_not_a_path(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const target = encodeURIComponent(req.query.host);
          exec("ping -c1 " + target);
        }
        """)
    assert found == []


def test_reassignment_clears_the_taint(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          let target = req.query.host;
          target = "localhost";
          exec("ping -c1 " + target);
        }
        """)
    assert found == []


def test_a_constant_command_is_not_a_path(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          exec("ping -c1 localhost");
        }
        """)
    assert found == []


def test_destructuring_carries_the_taint(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const { host } = req.query;
          exec("ping -c1 " + host);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.exec"]


def test_a_template_literal_carries_the_taint(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const host = req.params.id;
          exec(`ping -c1 ${host}`);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.exec"]


def test_a_call_spread_over_several_lines_is_still_one_statement(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const host = req.query.host;
          exec(
            "ping -c1 " +
            host
          );
        }
        """)
    assert [c.rule for c in found] == ["sink.js.exec"]


def test_innerHTML_assignment_is_a_sink(tmp_path):
    found = scan(tmp_path, """
        function render() {
          const raw = location.hash;
          document.body.innerHTML = raw;
        }
        """)
    assert [c.rule for c in found] == ["sink.js.html"]


def test_a_comment_that_looks_like_a_path_is_not_one(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          // exec("ping " + req.query.host)
          return res.send("ok");
        }
        """)
    assert found == []


def test_two_sinks_in_one_body_keep_separate_identities(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const host = req.query.host;
          exec("ping -c1 " + host);
          exec("traceroute " + host);
        }
        """)
    assert len(found) == 2
    assert found[0].sink.site != found[1].sink.site


def test_the_source_line_is_where_the_value_entered(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const host = req.query.host;
          const message = "ping -c1 " + host;
          exec(message);
        }
        """)
    assert len(found) == 1
    assert found[0].source.line < found[0].sink.line


def test_the_sink_line_is_the_call_not_the_statement(tmp_path):
    """Pointing a reader at `const x = JSON.parse(` when the sink is four
    lines down is how a true finding gets read as a false one."""
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          const host = req.query.host;
          const parsed = JSON.parse(
            String(
              exec("ping -c1 " + host)
            )
          );
        }
        """)
    assert len(found) == 1
    line = (tmp_path / "app.ts").read_text().splitlines()[found[0].sink.line - 1]
    assert "exec(" in line


def test_writing_to_a_socket_is_not_writing_to_the_document(tmp_path):
    """`write` bare is a verb, not a sink: socket.write, stderr.write, stream.write."""
    found = scan(tmp_path, """
        function relay(socket) {
          const raw = location.hash;
          socket.write(raw);
          process.stderr.write(raw);
        }
        """)
    assert found == []


def test_the_document_s_own_write_is_still_a_sink(tmp_path):
    found = scan(tmp_path, """
        function render() {
          const raw = location.hash;
          document.write(raw);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.html"]
