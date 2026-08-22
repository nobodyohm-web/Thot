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


# -- rules the repository declares for itself ---------------------------------


def _rules(tmp_path: Path, body: str) -> None:
    directory = tmp_path / ".thot" / "rules"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "maison.yaml").write_text(body, encoding="utf-8")


def test_a_repository_can_declare_its_own_shell_wrapper(tmp_path):
    """The built-ins know Node. They cannot know your `runShell`."""
    _rules(tmp_path, """
js:
  sinks:
    - id: sink.js.maison
      names: [runShell]
      impact: critical
      description: notre wrapper shell
""")
    found = scan(tmp_path, """
        function handler(req, res) {
          runShell("ping " + req.query.host);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.maison"]
    assert found[0].impact.value == "critical"


def test_a_repository_can_declare_its_own_source(tmp_path):
    _rules(tmp_path, """
js:
  sinks:
    - id: sink.js.maison
      names: [runShell]
      impact: high
      description: wrapper
  sources:
    - id: source.js.file
      patterns: [job.payload]
      description: message de la file
""")
    found = scan(tmp_path, """
        function worker(job) {
          const cmd = job.payload.command;
          runShell(cmd);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.maison"]


def test_a_repository_can_declare_its_own_escaper(tmp_path):
    _rules(tmp_path, """
js:
  sinks:
    - id: sink.js.maison
      names: [runShell]
      impact: high
      description: wrapper
  sanitizers: [escapeArg]
""")
    found = scan(tmp_path, """
        function handler(req, res) {
          runShell(escapeArg(req.query.host));
        }
        """)
    assert found == []


def test_a_repository_rule_replaces_a_built_in_of_the_same_id(tmp_path):
    """What lets a team downgrade a sink they have deliberately accepted."""
    _rules(tmp_path, """
js:
  sinks:
    - id: sink.js.exec
      names: [exec]
      impact: low
      description: accepté chez nous
""")
    found = scan(tmp_path, REQUIRE + """
        function handler(req, res) {
          exec("ping " + req.query.host);
        }
        """)
    assert [c.impact.value for c in found] == ["low"]


def test_a_broken_rules_file_names_itself(tmp_path):
    from thot.codemap.rules import RuleError, load_js_catalog

    _rules(tmp_path, "js:\n  sinks:\n    - names: [x]\n      impact: high\n")
    try:
        load_js_catalog(tmp_path)
    except RuleError as exc:
        assert "maison.yaml" in str(exc)
    else:
        raise AssertionError("un sink sans `id` doit être refusé")


# -- one level in, inside a single file ---------------------------------------


def test_a_helper_in_the_same_file_carries_the_taint(tmp_path):
    """The ordinary shape of a handler that delegates.

    Following a call across files would need a resolved module graph, which
    JavaScript does not offer without a tsconfig and a type checker. Within
    one file the question has an answer.
    """
    found = scan(tmp_path, REQUIRE + """
        function ping(target) {
          exec("ping -c1 " + target);
        }

        function handler(req, res) {
          ping(req.query.host);
        }
        """)
    assert [c.rule for c in found] == ["sink.js.exec"]


def test_a_helper_given_a_constant_is_not_a_path(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function ping(target) {
          exec("ping -c1 " + target);
        }

        function handler(req, res) {
          ping("localhost");
        }
        """)
    assert found == []


def test_a_sanitised_argument_does_not_seed_the_helper(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function ping(target) {
          exec("ping -c1 " + target);
        }

        function handler(req, res) {
          ping(encodeURIComponent(req.query.host));
        }
        """)
    assert found == []


def test_the_tainted_argument_seeds_the_right_parameter(tmp_path):
    """Position matters: the second argument taints the second parameter."""
    found = scan(tmp_path, REQUIRE + """
        function ping(flag, target) {
          exec("ping " + flag);
        }

        function handler(req, res) {
          ping("-c1", req.query.host);
        }
        """)
    assert found == [], "seul `target` est teinté, et il n'atteint pas le sink"


# --- un import relatif se résout sans deviner -------------------------------
#
# Le moteur s'arrêtait au fichier parce que suivre un appel demande un graphe
# de modules, que JavaScript n'offre pas sans tsconfig ni vérificateur de
# types. C'est vrai des spécificateurs nus (`from "lodash"`) et des alias.
# Ça ne l'est pas d'un chemin relatif : `./helpers` depuis `src/app.ts` ne
# désigne qu'un seul fichier, et la règle qui le dit est une règle de
# fichiers, pas une inférence. Le niveau reste unique — ce qui est franchi,
# c'est la frontière, pas la profondeur.


def scan_tree(tmp_path: Path, files: dict) -> list:
    for name, source in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    symbols = index_files(tmp_path, list(files))
    return js_engine.find_candidates(tmp_path, symbols)


def test_a_helper_in_a_relative_module_carries_the_taint(tmp_path):
    found = scan_tree(tmp_path, {
        "app.ts": 'import { ping } from "./helpers";\n'
                  "function handler(req, res) {\n"
                  "  ping(req.query.host);\n"
                  "}\n",
        "helpers.ts": REQUIRE + "export function ping(target) {\n"
                                '  exec("ping -c1 " + target);\n'
                                "}\n",
    })

    assert [c.rule for c in found] == ["sink.js.exec"]
    assert found[0].sink.path == "helpers.ts"


def test_a_constant_handed_across_a_module_is_not_a_path(tmp_path):
    found = scan_tree(tmp_path, {
        "app.ts": 'import { ping } from "./helpers";\n'
                  "function handler(req, res) {\n"
                  '  ping("localhost");\n'
                  "}\n",
        "helpers.ts": REQUIRE + "export function ping(target) {\n"
                                '  exec("ping -c1 " + target);\n'
                                "}\n",
    })

    assert found == []


def test_a_sanitised_argument_does_not_cross_the_module_either(tmp_path):
    found = scan_tree(tmp_path, {
        "app.ts": 'import { ping } from "./helpers";\n'
                  "function handler(req, res) {\n"
                  "  ping(encodeURIComponent(req.query.host));\n"
                  "}\n",
        "helpers.ts": REQUIRE + "export function ping(target) {\n"
                                '  exec("ping -c1 " + target);\n'
                                "}\n",
    })

    assert found == []


def test_a_bare_package_specifier_is_still_refused(tmp_path):
    """`from "some-lib"` needs a resolver Thot does not have. Unchanged."""
    found = scan_tree(tmp_path, {
        "app.ts": 'import { ping } from "some-lib";\n'
                  "function handler(req, res) {\n"
                  "  ping(req.query.host);\n"
                  "}\n",
        "node_modules/some-lib/index.ts": REQUIRE + "export function ping(t) {\n"
                                                    '  exec("ping " + t);\n'
                                                    "}\n",
    })

    assert found == []


def test_a_directory_import_resolves_to_its_index(tmp_path):
    found = scan_tree(tmp_path, {
        "app.ts": 'import { ping } from "./util";\n'
                  "function handler(req, res) {\n"
                  "  ping(req.query.host);\n"
                  "}\n",
        "util/index.ts": REQUIRE + "export function ping(target) {\n"
                                   '  exec("ping -c1 " + target);\n'
                                   "}\n",
    })

    assert [c.rule for c in found] == ["sink.js.exec"]
    assert found[0].sink.path == "util/index.ts"


def test_a_parent_relative_import_resolves(tmp_path):
    found = scan_tree(tmp_path, {
        "src/app.ts": 'import { ping } from "../lib/run";\n'
                      "function handler(req, res) {\n"
                      "  ping(req.query.host);\n"
                      "}\n",
        "lib/run.ts": REQUIRE + "export function ping(target) {\n"
                                '  exec("ping -c1 " + target);\n'
                                "}\n",
    })

    assert [c.rule for c in found] == ["sink.js.exec"]


def test_the_crossing_does_not_add_a_second_level(tmp_path):
    """One level, still. A helper calling another helper is not followed."""
    found = scan_tree(tmp_path, {
        "app.ts": 'import { first } from "./a";\n'
                  "function handler(req, res) {\n"
                  "  first(req.query.host);\n"
                  "}\n",
        "a.ts": 'import { second } from "./b";\n'
                "export function first(value) {\n"
                "  second(value);\n"
                "}\n",
        "b.ts": REQUIRE + "export function second(cmd) {\n"
                          '  exec("ping " + cmd);\n'
                          "}\n",
    })

    assert found == []


def test_a_crossing_shows_where_the_untrusted_value_entered(tmp_path):
    """A proven path must show the whole path.

    Reported only inside the callee, a crossing is unreadable: the reader
    sees `exec(cmd)` in a helper with no idea what `cmd` ever was, and the
    file that actually touches the request never appears.
    """
    found = scan_tree(tmp_path, {
        "app.ts": 'import { ping } from "./helpers";\n'
                  "function handler(req, res) {\n"
                  "  ping(req.query.host);\n"
                  "}\n",
        "helpers.ts": REQUIRE + "export function ping(target) {\n"
                                '  exec("ping -c1 " + target);\n'
                                "}\n",
    })

    assert len(found) == 1
    candidate = found[0]
    assert candidate.source.path == "app.ts", candidate.source
    assert candidate.sink.path == "helpers.ts"
    assert [step.path for step in candidate.path] == [
        "app.ts", "helpers.ts", "helpers.ts"
    ]


def test_a_same_file_helper_keeps_its_two_step_path(tmp_path):
    found = scan(tmp_path, REQUIRE + """
        function ping(target) {
          exec("ping -c1 " + target);
        }

        function handler(req, res) {
          ping(req.query.host);
        }
        """)

    assert len(found) == 1
    assert len(found[0].path) == 2


# --- découper des arguments ne doit pas être quadratique -------------------
#
# Profilé sur Prime : `_split_arguments` pesait 130 des 144 secondes de la
# passe entière, 61 122 appels. La cause n'était pas le nombre d'appels mais
# `current += char` dans la boucle — Python réalloue et recopie la chaîne à
# chaque caractère, donc O(n²) sur un argument long. Un appel dont les
# arguments tiennent en 20 000 signes, chose ordinaire dans un fichier
# généré, coûtait à lui seul plus que tout le reste du fichier.


SPLIT_CASES = [
    "",
    "a",
    "a, b",
    "a, b, c",
    "f(x, y), z",
    "{a: 1, b: 2}, c",
    "[1, 2], [3, 4]",
    "f(g(h(1, 2), 3), 4), tail",
    "a,,b",
    ",leading",
    "trailing,",
    "deep(((1, 2))), after",
]


def test_the_split_agrees_with_the_straightforward_version():
    from thot.taint.js_engine import CLOSERS, OPENERS, _split_arguments

    def naive(text):
        parts, depth, current = [], 0, ""
        for char in text:
            if char in OPENERS:
                depth += 1
            elif char in CLOSERS:
                depth -= 1
            if char == "," and depth == 0:
                parts.append(current)
                current = ""
                continue
            current += char
        parts.append(current)
        return parts

    for case in SPLIT_CASES:
        assert _split_arguments(case) == naive(case), case


def test_a_long_argument_list_does_not_cost_quadratic_time():
    import time

    from thot.taint.js_engine import _split_arguments

    small = "x" * 2_000 + ", y"
    large = "x" * 40_000 + ", y"

    start = time.perf_counter(); _split_arguments(small); small_time = time.perf_counter() - start
    start = time.perf_counter(); _split_arguments(large); large_time = time.perf_counter() - start

    # 20x the input. Linear stays near 20x; quadratic goes to ~400x.
    assert large_time < max(small_time, 1e-4) * 80, (small_time, large_time)


# --- un appel dont les arguments font deux méga-octets n'est pas un appel ---
#
# Profilé sur Prime : `_split_arguments` pesait 130 des 144 secondes de la
# passe, sur 61 122 appels. La distribution dit pourquoi — médiane 16
# caractères, p90 77, maximum 1 859 942. `_arguments` cherche la parenthèse
# fermante correspondante et, quand elle manque, rend tout le reste du
# fichier ; une poignée d'appels pathologiques dans du code généré coûtait
# ainsi plus que l'ensemble des autres. Le résultat n'était pas seulement
# lent, il n'avait aucun sens.


def test_a_balanced_call_is_unchanged(tmp_path):
    from thot.taint.js_engine import _arguments

    assert _arguments("f(a, b)", 0) == "a, b"
    assert _arguments("g(h(1), 2)", 0) == "h(1), 2"


def test_an_unclosed_call_does_not_swallow_the_file(tmp_path):
    from thot.taint.js_engine import ARGUMENT_LIMIT, _arguments

    text = "f(" + "x" * (ARGUMENT_LIMIT + 5_000)

    assert _arguments(text, 0) == ""


def test_a_very_long_argument_list_is_left_unanalysed(tmp_path):
    from thot.taint.js_engine import ARGUMENT_LIMIT, _arguments

    text = "f(" + "x" * (ARGUMENT_LIMIT + 10) + ")"

    assert _arguments(text, 0) == ""


def test_a_long_but_reasonable_call_is_still_read(tmp_path):
    from thot.taint.js_engine import ARGUMENT_LIMIT, _arguments

    body = "x" * (ARGUMENT_LIMIT // 2)

    assert _arguments(f"f({body})", 0) == body


# --- une déstructuration occupe quand même sa place ------------------------
#
# `_params` lisait un identifiant en tête de chaque tranche, et une
# déstructuration ne commence pas par un identifiant. Les positions glissaient
# donc :
#
#   ({opts}, command)    → ('command',)      l'argument 0 désigne 'command'
#   (req, {body}, next)  → ('req', 'next')   l'argument 1 désigne 'next'
#
# C'est la forme la plus répandue en JavaScript — intergiciel Express, props,
# objet d'options — et une teinte portée par le deuxième argument se voyait
# attribuée au troisième paramètre. Faux négatif et attribution fausse à la
# fois. Un jeton vide garde la place sans jamais rien semer.


def test_a_destructured_parameter_keeps_its_position():
    from thot.codemap.ts_indexer import _mask, _params

    def read(signature):
        source = "function f" + signature + " {}"
        return _params(_mask(source), source.index("(") + 1)

    assert read("({opts}, command)") == ("", "command")
    assert read("(req, {body}, next)") == ("req", "", "next")
    assert read("({ command })") == ("",)


def test_ordinary_signatures_are_unchanged():
    from thot.codemap.ts_indexer import _mask, _params

    def read(signature):
        source = "function f" + signature + " {}"
        return _params(_mask(source), source.index("(") + 1)

    assert read("(command)") == ("command",)
    assert read("(a, command)") == ("a", "command")
    assert read("(...args)") == ("args",)
    assert read('(command = "x")') == ("command",)


def test_taint_reaches_the_parameter_it_was_passed_to(tmp_path):
    """`run(cfg, userInput)` must seed `command`, not the name beside it."""
    found = scan_tree(tmp_path, {
        "app.ts": 'import { launch } from "./helpers";\n'
                  "function handler(req, res) {\n"
                  "  launch({}, req.query.host);\n"
                  "}\n",
        "helpers.ts": REQUIRE + "export function launch({opts}, command) {\n"
                                '  exec("ping " + command);\n'
                                "}\n",
    })

    assert [c.rule for c in found] == ["sink.js.exec"], found


def test_an_empty_slot_costs_no_second_pass(tmp_path, monkeypatch):
    """A destructured slot binds no name, so it must not be followed.

    Nothing in the findings can show this: a taint keyed by the empty
    string matches no identifier, so the extra pass is silent — it just
    re-reads the callee's module and finds nothing. The cost is the only
    observable, so the cost is what this measures.
    """
    reads: list[str] = []
    real = js_engine.read_masked
    monkeypatch.setattr(
        js_engine,
        "read_masked",
        lambda path: (reads.append(Path(path).name), real(path))[1],
    )

    found = scan_tree(tmp_path, {
        "app.ts": 'import { launch } from "./helpers";\n'
                  "function handler(req, res) {\n"
                  '  launch(req.query.host, "ping");\n'
                  "}\n",
        "helpers.ts": REQUIRE + "export function launch({opts}, command) {\n"
                                '  exec("run " + command);\n'
                                "}\n",
    })

    assert found == []  # the tainted value reached no named parameter
    assert reads.count("helpers.ts") == 1, reads
