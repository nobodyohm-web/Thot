"""The TypeScript scanner: what it finds, and what it refuses to invent.

912 of Prime's files were invisible to the map. A scanner that answered
"here are 9 000 symbols" while half of them were parenthesised expressions
would be worse than the silence it replaced, so most of what is tested here
is the second half: the shapes it must NOT report.
"""

from __future__ import annotations

from thot.codemap.ts_indexer import TypeScriptIndexer


def index(source: str, name: str = "src/app.ts"):
    return {s.name.split(".")[-1]: s for s in TypeScriptIndexer().index_source(source, name)}


def test_it_finds_the_four_declaration_shapes():
    found = index(
        """
        export function alpha(a: string): void {}
        const beta = async (b: number) => { alpha("x"); };
        export class Gamma {
          async delta(c: boolean) { return c; }
        }
        """
    )
    assert set(found) >= {"alpha", "beta", "Gamma", "delta"}
    assert found["delta"].kind == "method"
    assert found["Gamma"].kind == "class"


def test_a_parenthesised_expression_is_not_a_function():
    """`const total = (a + b);` has the same shape and is not callable."""
    found = index("const total = (a + b);\nconst other = (compute());\n")

    assert "total" not in found
    assert "other" not in found


def test_a_single_argument_arrow_still_counts():
    assert "double" in index("const double = x => x * 2;\n")


def test_a_return_type_between_parameters_and_arrow_is_survivable():
    assert "typed" in index("const typed = (a: number): string => `${a}`;\n")


def test_braces_inside_strings_do_not_close_a_function():
    """A template literal with a brace used to end the body three lines early."""
    found = index(
        """
        function outer(a) {
          const message = `unclosed { brace`;
          const other = "} not a brace";
          return a;
        }
        """
    )
    assert found["outer"].end_lineno - found["outer"].lineno >= 4


def test_a_call_inside_a_comment_is_not_an_edge():
    found = index(
        """
        function speaks() {
          // ignored(); and /* also */ ignored2();
          real();
        }
        """
    )
    assert found["speaks"].calls == ("real",)


def test_keywords_that_look_like_calls_are_not_edges():
    found = index(
        "function guard(x) { if (x) { while (x) { doWork(x); } } }\n"
    )
    assert found["guard"].calls == ("doWork",)


def test_parameters_survive_types_defaults_and_rest():
    found = index(
        "function many(first: string, second = {a: 1}, ...rest: number[]) {}\n"
    )
    assert found["many"].params == ("first", "second", "rest")


def test_the_hash_ignores_formatting_but_not_code():
    tight = index("function f(a) { return a + 1; }\n")["f"]
    loose = index("function f(a) {\n  return a + 1;\n}\n")["f"]
    other = index("function f(a) { return a + 2; }\n")["f"]

    assert tight.ast_hash == loose.ast_hash
    assert tight.ast_hash != other.ast_hash


def test_an_overload_signature_does_not_duplicate_the_symbol():
    found = TypeScriptIndexer().index_source(
        "export function pick(a: string): string;\n"
        "export function pick(a: number): number;\n"
        "export function pick(a: any): any { return a; }\n",
        "src/app.ts",
    )
    assert len([s for s in found if s.name.endswith(".pick")]) == 1


def test_a_symbol_is_named_after_its_module():
    found = TypeScriptIndexer().index_source(
        "function run() {}\n", "packages/agent/src/main.ts"
    )
    assert found[0].name == "packages.agent.src.main.run"
