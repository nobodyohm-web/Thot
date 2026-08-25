"""Source-to-sink propagation.

Three levels of propagation, all deliberately bounded:

1. **Intra-procedural** — assignments are followed inside a single function
   body, so ``x = sys.argv[1]; os.system(x)`` is caught.
2. **Return-value** — a function that returns tainted data marks its callers'
   assignment targets as tainted, so ``x = read_input(); sink(x)`` is caught.
3. **Parameter** — a function whose parameter reaches a sink becomes a
   propagator; any caller passing tainted data into *that* parameter extends
   the path. Which parameter an argument fills is read from the call site,
   so `helper(untrusted, "ls")` against `def helper(safe, cmd)` extends
   nothing: the data lands in `safe`, and only `cmd` reaches a sink.

Levels 2 and 3 are resolved by a small fixed-point loop bounded by
``max_depth`` iterations.

Dynamic dispatch, reflection and metaprogramming are out of reach. The result
is incomplete (false negatives), never fabricated: every reported path exists
in the call graph.
"""

from __future__ import annotations

import ast
import re
from functools import lru_cache
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from thot.codemap.catalog import (
    active,
    impact_for,
    is_html_sanitizer,
    is_sanitizer,
    match_entry,
    match_sink,
    match_source,
    using,
)
from thot.codemap.graph import CodeGraph
from thot.codemap.index import PYTHON_SUFFIXES
from thot.codemap.python_indexer import _called_name
from thot.contracts import CodeRef, Severity, Symbol


@dataclass(frozen=True)
class TaintCandidate:
    """One source-to-sink path found without any model involvement."""

    rule: str
    source: CodeRef
    sink: CodeRef
    path: tuple[CodeRef, ...]
    impact: Severity
    description: str
    # Which source rule started this path — `source.argv`, `source.http`.
    # Empty when the engine could not name it: a parameter seeded by a caller
    # it never resolved. Half of how serious a file-path finding is.
    source_rule: str = ""


def _expression_name(node: ast.AST) -> str | None:
    """Render `sys.argv`, `os.environ`, `f()` as a dotted string when possible."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return node.attr
    if isinstance(node, ast.Subscript):
        return _expression_name(node.value)
    if isinstance(node, ast.Call):
        return _called_name(node)
    return None


def _target_names(node: ast.AST) -> list[str]:
    """Every name an assignment target binds.

    `ast.Attribute` renders dotted, because that is exactly what
    `_referenced_names` produces when the same attribute is later read:
    `box.host = ...` then `os.system(box.host)` has to match on both sides.
    """
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        name = _expression_name(node)
        return [name] if name else []
    if isinstance(node, ast.Subscript):
        # `box['k'] = tainted` marks the container, which is what appending to
        # a list already does. The read side renders `box['k']` as `box`, so
        # both ends agree on one name; keying the taint per subscript would
        # need the two sides to agree on the key as well, and `box[name]`
        # settles nothing. Conservative across keys, and the corpus shows why
        # it is worth having: 504 of its files pass a value through a
        # module-level dict on the way to the sink.
        return _target_names(node.value)
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _target_names(element)]
    return []


def _referenced_names(node: ast.AST, *, through_sanitizers: bool = False) -> set[str]:
    """Every identifier an expression reads, following composite expressions.

    Concatenations, f-strings, `%` formatting and `.format()` calls all carry
    taint — an injection almost always travels through one of them, so a
    `Name`-only view of arguments misses most real defects.

    A dotted name is added *alongside* the expression it was read from, not
    instead of it. `handle.read()` renders as `handle.read`, which is a name
    nothing ever binds — the map holds `handle` — so returning only the
    dotted form dropped the taint of every method call and every attribute
    read. Both go in: `handle.read` for the `box.host = ...` case, where the
    attribute is what was assigned, and `handle` for this one.

    Recursion stops at a sanitizing call: `shlex.quote(x)` reads `x` but does
    not propagate its taint. `through_sanitizers` lifts that, for the one
    caller that needs it — see `except ... as` below.
    """
    names: set[str] = set()

    def visit(current: ast.AST) -> None:
        if isinstance(current, ast.IfExp) and not through_sanitizers \
                and _literal_choice(current):
            # `flag = "true" if value.lower() in ("true", "1") else "false"`
            # reads `value` and cannot carry it: whatever the attacker sends,
            # what comes out is one of two strings the author wrote. Reading
            # the test as propagation was 54 of the 150 false positives in
            # `codeinj` and 0 of its true positives, measured over 18 300
            # labelled cases with none lost.
            #
            # `through_sanitizers` is honoured because the one caller that
            # sets it — `except ... as` — wants what the protected block was
            # *working on*, and a refused value escapes through the message
            # whatever branch the expression would have taken.
            return
        if isinstance(current, ast.Call):
            called = _called_name(current)
            if called and is_sanitizer(called) and not through_sanitizers:
                return
            if called:
                names.add(called)
            if isinstance(current.func, ast.Attribute):
                visit(current.func.value)
            for argument in current.args:
                visit(argument)
            for keyword in current.keywords:
                visit(keyword.value)
            return
        if isinstance(current, ast.Name):
            names.add(current.id)
            return
        if isinstance(current, ast.Attribute):
            full = _expression_name(current)
            if full:
                names.add(full)
            visit(current.value)
            return
        if isinstance(current, (ast.GeneratorExp, ast.ListComp, ast.SetComp)) \
                and not _reads_its_loop(current):
            # `','.join('?' for _ in ids)` — the correct way to parameterise
            # an `IN` clause, and the shape a taint engine most often gets
            # wrong. What comes out is a string of question marks whose
            # length is the number of ids and whose content is the author's;
            # the loop variable is never read, so nothing of the ids is in
            # it. Only the iterables are dropped: a tainted name written in
            # the element is in the output whatever is being looped over,
            # and so is one read by a filter.
            visit(current.elt)
            for clause in current.generators:
                for condition in clause.ifs:
                    visit(condition)
            return
        for child in ast.iter_child_nodes(current):
            visit(child)

    visit(node)
    return names


def _reads_its_loop(node: ast.AST) -> bool:
    """Whether a comprehension's element names anything it iterates over.

    The targets of every clause, because `[a for a in xs for b in ys]` binds
    two and either one is enough to carry the values through.
    """
    bound: set[str] = set()
    for clause in node.generators:
        for target in ast.walk(clause.target):
            if isinstance(target, ast.Name):
                bound.add(target.id)
    return any(isinstance(one, ast.Name) and one.id in bound
               for one in ast.walk(node.elt))


def _literal_choice(node: ast.IfExp) -> bool:
    """A conditional expression every branch of which is a constant.

    Nested on purpose: `"a" if x else ("b" if y else "c")` chooses between
    three constants and carries no more than the flat form does.
    """
    for branch in (node.body, node.orelse):
        if isinstance(branch, ast.IfExp):
            if not _literal_choice(branch):
                return False
        elif not isinstance(branch, ast.Constant):
            return False
    return True


def _is_literal_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _sink_applies(rule_id: str, node: ast.Call) -> bool:
    """False when the call is in a form that cannot be injected.

    Two forms carry no injection risk and would otherwise flood a report:
    a subprocess call whose argv is a list without ``shell=True`` (no shell
    ever parses it), and a SQL call whose query is a plain literal (values
    travel as bound parameters).
    """
    first = node.args[0] if node.args else None

    if rule_id == "sink.subprocess.shell":
        # Without shell=True no shell ever parses the command, whatever the
        # argv shape — `list(args)` and `cmd + ["install"]` are as safe as a
        # literal list. Argument injection remains possible but is a different,
        # far lower-severity defect.
        return any(
            keyword.arg == "shell" and _is_literal_true(keyword.value)
            for keyword in node.keywords
        )

    if rule_id == "sink.sql":
        return not isinstance(first, ast.Constant)

    return True


def _plain_name(node: ast.AST) -> str | None:
    """The name a guard constrains, seen through a harmless coercion.

    `re.fullmatch(pattern, str(data))` constrains `data` exactly as
    `re.fullmatch(pattern, data)` does — `str` and `int` cannot widen what
    the pattern then has to accept.
    """
    if isinstance(node, ast.Call) and _called_name(node) in ("str", "int") \
            and len(node.args) == 1:
        return _plain_name(node.args[0])
    return node.id if isinstance(node, ast.Name) else None


def _all_literals(node: ast.AST) -> bool:
    return (isinstance(node, (ast.Tuple, ast.List, ast.Set))
            and bool(node.elts)
            and all(isinstance(element, ast.Constant) for element in node.elts))


def _enumerates(pattern: object) -> bool:
    """Whether a `fullmatch` pattern says what is *allowed*, not what is not.

    `re.fullmatch(r"[a-z0-9_-]+", value)` enumerates a character set and is
    the shape this guard exists for. `re.fullmatch(r"^[^\x00-\x08]+$", value)`
    wears the same clothes and forbids one control character out of a
    million: everything else — quotes, semicolons, backticks, newlines —
    passes. Anchoring is not the property that matters; a negated class is a
    deny-list whatever it is anchored to, and a deny-list is unbounded by
    construction, which is exactly why `re.search` is refused two lines up.
    
    Measured: 309 vulnerable cases across some forty categories carry this
    disguise, and honouring it cost 24 true positives — 9 in `eval_injection`,
    9 in `sqli`, 3 each in `cmdi` and `codeinj` — for no false positive
    prevented anywhere.
    """
    return isinstance(pattern, str) and "[^" not in pattern


# The two shapes a web application uses to prove a URL is allowed, and the
# origins each one is only trustworthy from.
#
# Measured over 18 300 labelled cases: 234 files guard on a host allow-list
# and 216 on the resolved address's range, and **every one of the 450 is
# labelled safe** — no vulnerable case in any category carries either shape.
# Recognising them takes `ssrf` from J -8 % to +64 % and `cloud_ssrf_metadata`
# from 0 % to +79 %, destroying no true positive anywhere.
#
# Both origin requirements below are load-bearing, and neither is cosmetic.
# Without them `payload.host` on an arbitrary object clears taint — an
# adversarial probe turned a real `os.system` finding into silence — so a
# guard is honoured only when the thing it constrains provably came from a
# URL parser or a name resolver.
_HOST_ATTRS = frozenset({"hostname", "netloc", "host"})
_URL_PARSERS = frozenset({
    "urlparse", "urlsplit", "urllib.parse.urlparse", "urllib.parse.urlsplit",
})
_RESOLVERS = frozenset({
    "socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo",
    "gethostbyname", "getaddrinfo",
})
_IP_CONSTRUCTORS = frozenset({
    "ipaddress.ip_address", "ipaddress.ip_network",
    "ip_address", "ip_network",
})
# Properties that answer "is this address in a range nobody outside may
# reach". `is_global` is deliberately absent: it is the negation, and the
# guards that use it refuse the *public* case, which is the opposite policy.
_IP_RANGE_PROPS = frozenset({
    "is_private", "is_link_local", "is_loopback", "is_reserved",
    "is_multicast", "is_unspecified",
})


def _closure(roots: set[str], derives: Mapping[str, frozenset[str]]) -> set[str]:
    """Every name the guarded value was built from, transitively.

    A guard reads `parsed.hostname`; the sink reads `target_url`, three
    assignments away. Clearing only what the test names clears nothing that
    matters, so the derivation chain is walked back to its source.
    """
    seen: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        pending.extend(derives.get(name, ()))
    return seen


def _base_name(node: ast.AST) -> str | None:
    """The bare identifier an attribute chain hangs off, if it is one."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _came_from(name: str | None, sources: frozenset[str],
               derives: Mapping[str, frozenset[str]]) -> bool:
    """Whether a name was assigned from a call in `sources`.

    `_referenced_names` records the called name alongside the arguments, so
    the assignment `parsed = urlparse(data)` leaves `urlparse` in `parsed`'s
    derivation — which is exactly the evidence needed and costs no extra
    bookkeeping.
    """
    if name is None:
        return False
    return bool(sources & set(derives.get(name, ())))


def _host_allow_listed(test: ast.Compare,
                       derives: Mapping[str, frozenset[str]]) -> set[str]:
    """`if parsed.hostname not in ("a.example", "b.example"): return`."""
    left = test.left
    if not isinstance(left, ast.Attribute) or left.attr not in _HOST_ATTRS:
        return set()
    base = _base_name(left)
    if not _came_from(base, _URL_PARSERS, derives):
        return set()
    return _closure({base} if base else set(), derives)


def _range_checked(test: ast.AST,
                   derives: Mapping[str, frozenset[str]]) -> set[str]:
    """`if ipaddress.ip_address(resolved).is_private: return`.

    The address has to have been *resolved* — the check is worth nothing on
    a hostname — so the constructor's argument must trace back to a name
    resolver. Without that requirement any attribute called `is_private` on
    any object would launder a value.
    """
    if not isinstance(test, ast.Attribute) or test.attr not in _IP_RANGE_PROPS:
        return set()
    call = test.value
    if not isinstance(call, ast.Call) or _called_name(call) not in _IP_CONSTRUCTORS:
        return set()
    if not call.args:
        return set()
    roots = {name for name in _referenced_names(call.args[0])
             if name in derives or name.isidentifier()}
    resolved = {name for name in roots if _came_from(name, _RESOLVERS, derives)}
    if not resolved:
        return set()
    return _closure(resolved, derives)


def _refuses(body: list[ast.stmt]) -> bool:
    """Whether reaching this block means the function stops here."""
    return bool(body) and isinstance(body[-1], (ast.Return, ast.Raise))


# Sinks a proof about *where a value goes* is allowed to clear. A host
# allow-list and a resolved-address range check both say the request will not
# reach somewhere forbidden; neither says anything about the value's shape.
#
# This distinction is not theoretical. An adversarial probe on the first
# version of this code:
#
#     resolved = socket.gethostbyname(parsed.hostname or url)
#     if ipaddress.ip_address(resolved).is_private:
#         return "blocked", 403
#     os.system("curl -s " + url)          # <- silenced, and exploitable
#
# The guard is a correct SSRF defence and says nothing at all about the shell
# metacharacters still in the string. Clearing taint outright bought 174 true
# false-positive removals and one silent command-injection blind spot, which
# is not a trade worth making.
# A destination proof is only worth what it proves *about that destination*.
# A resolved-address range check says the request will not reach a private
# host; a path-confinement check says the open() will not leave a directory.
# Neither says one word about the other, and neither says anything about the
# value's shape — so each is keyed to the sinks it actually covers.
#
# `host` and `network` were one entry until `sink.redirect` arrived, and
# merging them was only ever safe while a single sink read them. A host
# allow-list says the value names a host somebody approved — which is what a
# redirect needs, and what a request needs. A resolved-range check says the
# address is not private: that stops an SSRF, and it is silent about sending
# a user somewhere. Every public address passes it, and a public address is
# exactly where an open redirect sends its victim.
_DESTINATION_PROOFS: dict[str, frozenset[str]] = {
    # Stripping CR and LF proves a header and nothing else — see
    # `_strips_crlf`. It does not reach `sink.cors`: removing newlines from a
    # reflected Origin leaves it reflected.
    "header": frozenset({"sink.header"}),
    # A digest or a ciphertext is not the secret. It proves storage and only
    # storage: handing either to a shell is exactly as dangerous as before.
    "storage": frozenset({"sink.cleartext"}),
    "host": frozenset({"sink.network", "sink.redirect"}),
    "network": frozenset({"sink.network"}),
    "path": frozenset({"sink.fs.read", "sink.fs.write"}),
    "html": frozenset({"sink.xss"}),
    # Doubling the delimiter of a quoted identifier proves SQL and nothing
    # else — see `_quoted_identifier_names`. A shell reads a different
    # alphabet and `""` hands it the semicolon untouched.
    "sql": frozenset({"sink.sql"}),
}


def _proves_for(rule_id: str) -> tuple[str, ...]:
    return tuple(family for family, sinks in _DESTINATION_PROOFS.items()
                 if rule_id in sinks)


def _resolves_path(node: ast.AST) -> bool:
    """Whether an expression yields an already-resolved filesystem path.

    `realpath` and `Path(...).resolve()` are *transformations*, never
    neutralisations — `realpath("/var/app/data/../../etc/passwd")` is
    `/etc/passwd`, and the corpus proves the point with 15 vulnerable cases
    whose only defence is `normpath`. What protects is the guard that
    *follows*, and this only says the guard has something meaningful to
    compare.
    """
    if not isinstance(node, ast.Call):
        return False
    if (_called_name(node) or "") in ("os.path.realpath", "realpath"):
        return True
    # Read structurally, not by name: `_called_name` renders both
    # `Path("/var/app/data").resolve()` and `(base / data).resolve()` as the
    # bare string "resolve", so matching on a dotted name finds neither.
    return isinstance(node.func, ast.Attribute) and node.func.attr == "resolve"


def _constant_rooted_path(node: ast.AST) -> bool:
    """`Path("/var/app/data").resolve()` — resolved, and from a constant.

    Required of the *base* a containment check compares against. Against a
    base the attacker supplied — `Path(request.GET["root"]).resolve()` — the
    same check confines the candidate under a directory they chose, which
    proves nothing while looking exactly like a defence.
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "resolve"):
        return False
    inner = node.func.value
    return (isinstance(inner, ast.Call)
            and (_called_name(inner) or "").split(".")[-1] == "Path"
            and len(inner.args) == 1
            and isinstance(inner.args[0], ast.Constant))


def _prefix_confined(test: ast.AST, derives: Mapping[str, frozenset[str]],
                     constants: frozenset[str]) -> set[str]:
    """`if not full_path.startswith(base_dir + os.sep): return`.

    The prefix has to be constant. Against a base the attacker chose, the
    check confines the path under a directory they picked, which proves
    nothing at all.
    """
    if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
        return set()
    call = test.operand
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return set()
    if call.func.attr != "startswith" or not call.args:
        return set()
    argument = call.args[0]
    roots = {name for name in _referenced_names(argument)}
    if not roots <= (constants | {"os.sep", "os.path.sep", "os"}):
        return set()
    receiver = _base_name(call.func.value)
    return _closure({receiver}, derives) if receiver else set()


def _parents_confined(test: ast.AST, derives: Mapping[str, frozenset[str]],
                      confined: frozenset[str]) -> set[str]:
    """`if base not in candidate.parents and candidate != base: return`.

    `base` must itself be a resolved path built from a constant, for the same
    reason the prefix must be constant above.
    """
    parts = test.values if isinstance(test, ast.BoolOp) else [test]
    for part in parts:
        if not isinstance(part, ast.Compare) or len(part.ops) != 1:
            continue
        if not isinstance(part.ops[0], ast.NotIn):
            continue
        base = _plain_name(part.left)
        if base not in confined:
            continue
        target = part.comparators[0]
        if not isinstance(target, ast.Attribute) or target.attr != "parents":
            continue
        candidate = _base_name(target)
        if candidate:
            return _closure({candidate}, derives)
    return set()


def _destination_validated(statement: ast.If,
                           derives: Mapping[str, frozenset[str]],
                           constants: frozenset[str] = frozenset(),
                           confined: frozenset[str] = frozenset(),
                           ) -> dict[str, set[str]]:
    """Names a guard has proved will not reach a forbidden destination.

    Keyed by which family of sinks the proof covers; see `_DESTINATION_PROOFS`
    for why one global answer would be unsound.
    """
    if statement.orelse or not _refuses(statement.body):
        return {}

    test = statement.test
    proved: dict[str, set[str]] = {}

    if isinstance(test, ast.Compare) and len(test.ops) == 1 \
            and isinstance(test.ops[0], ast.NotIn) \
            and _all_literals(test.comparators[0]) \
            and _plain_name(test.left) is None:
        hosts = _host_allow_listed(test, derives)
        if hosts:
            proved["host"] = hosts

    ranged = _range_checked(test, derives)
    if ranged:
        proved["network"] = proved.get("network", set()) | ranged

    confined = (_prefix_confined(test, derives, constants)
                or _parents_confined(test, derives, confined))
    if confined:
        proved["path"] = confined

    return proved


def _validated_names(statement: ast.If,
                     derives: Mapping[str, frozenset[str]] | None = None,
                     literals: frozenset[str] = frozenset()) -> set[str]:
    """Names a guard clause has constrained to a literal shape.

    ``if data not in ('asc', 'desc'): return`` and
    ``if not re.fullmatch(r'[a-z0-9_-]+', data): return`` both mean the same
    thing to everything below them: execution only continues for a value the
    author enumerated or spelled out. Treating that value as untrusted after
    the guard is not caution, it is a false positive — measured on 300
    labelled safe cases, 235 of them are exactly this shape, and they were
    the bulk of every false positive this engine produced.

    Only *literal* constraints count, and only two of them:

    * membership in a collection of constants — an allow-list;
    * ``re.fullmatch`` against a constant pattern — anchored at both ends.

    Everything else the corpus offers is deliberately refused, because it
    constrains nothing this engine can verify:

    * ``re.match`` is anchored only at the start, so ``ok\n; rm -rf /``
      passes a pattern that looks restrictive;
    * ``if not auth_check(x): return`` is an unknown function — it may check
      a password and never look at the value's shape at all;
    * ``if len(x) > 8192: return`` bounds a size, not a content;
    * ``if re.search(bad, x): return`` is a deny-list, and a deny-list is
      unbounded by construction.

    Refusing those is what keeps this from being a way to silence findings.
    """
    if statement.orelse or not _refuses(statement.body):
        return set()

    test = statement.test
    derives = derives if derives is not None else {}

    # `if x not in (...): return`
    if isinstance(test, ast.Compare) and len(test.ops) == 1 \
            and isinstance(test.ops[0], ast.NotIn) \
            and (_all_literals(test.comparators[0])
                 or _plain_name(test.comparators[0]) in literals):
        # The allow-list written inline and the one given a name are the same
        # guard; only the syntax differs. Refusing the second cost 33 false
        # positives in `pathtraver` alone, and `allowed = {"config.json",
        # "index.html"}` two lines above the check is how anybody actually
        # writes it.
        name = _plain_name(test.left)
        return {name} if name else set()

    # `if not re.fullmatch('...', x): return`
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) \
            and isinstance(test.operand, ast.Call):
        call = test.operand
        if _called_name(call) in ("re.fullmatch", "fullmatch") \
                and len(call.args) >= 2 \
                and isinstance(call.args[0], ast.Constant) \
                and _enumerates(call.args[0].value):
            name = _plain_name(call.args[1])
            return {name} if name else set()

    return set()


_CORS_ORIGIN = "access-control-allow-origin"


_SENSITIVE_NAME = re.compile(
    r"secret|credential|password|passwd|apikey|api[_-]key|token", re.I)

# What turns a value into something a store may hold. A digest is not the
# secret and neither is a ciphertext — and `hashlib.sha256` being the right
# answer here is precisely why it is the wrong answer to "is this a password
# hash": a digest is not a key-derivation function.
_SEALS = ("hexdigest", "digest", "encrypt", "hashpw", "pbkdf2_hmac", "scrypt")


def _sealed(value: ast.AST) -> bool:
    """Whether every call in this expression ends in a digest or a ciphertext."""
    for node in ast.walk(value):
        if isinstance(node, ast.Call):
            name = _called_name(node) or ""
            if name.rpartition(".")[2] in _SEALS:
                return True
    return False


def _header_targets(node: ast.AST) -> list[tuple[str, ast.expr]]:
    """Response headers written at this node, as (rule id, value).

    Two shapes, because the frameworks disagree and both are ordinary:
    Django and FastAPI take `headers={...}` as a keyword, Flask returns
    `body, status, {...}` as the third element of a tuple. The key names the
    header and the value is what must not be attacker-chosen.

    Position is the whole gate. A dict whose keys merely *look* like header
    names — `{'first-name': value}` — is data, and matching on the shape of
    the key alone would have turned every such dict into a response header.
    """
    dicts: list[ast.Dict] = []
    if isinstance(node, ast.Call):
        for keyword in node.keywords:
            if keyword.arg == "headers" and isinstance(keyword.value, ast.Dict):
                dicts.append(keyword.value)
    elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple) \
            and len(node.value.elts) == 3 \
            and isinstance(node.value.elts[2], ast.Dict):
        dicts.append(node.value.elts[2])

    found: list[tuple[str, ast.expr]] = []
    for mapping in dicts:
        for key, value in zip(mapping.keys, mapping.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            rule = ("sink.cors" if key.value.strip().lower() == _CORS_ORIGIN
                    else "sink.header")
            found.append((rule, value))
    return found


def _opens_with_markup(value: ast.AST) -> bool:
    """Whether an expression starts with a literal that opens an HTML tag.

    The leftmost constant, because that is what a browser reads first:
    `'<div>' + value + '</div>'` and `f'<div>{value}</div>'` are the same
    body written two ways, and `value + '</div>'` is a fragment somebody else
    already opened.
    """
    current = value
    while isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
        current = current.left
    if isinstance(current, ast.JoinedStr):
        current = current.values[0] if current.values else None
    return (isinstance(current, ast.Constant)
            and isinstance(current.value, str)
            and current.value.lstrip().startswith("<"))


def _autoescaped_names(value: ast.AST) -> set[str]:
    """Names that reach an escaping render and go no further.

    Only the names *inside* the render, never the whole expression: the
    corpus writes `HTMLResponse('<div>' + render(...) + suffix)`, and
    clearing the expression would clear `suffix` for free.
    """
    found: set[str] = set()
    for node in ast.walk(value):
        if isinstance(node, ast.Call) and _autoescaped_render(node):
            found |= _referenced_names(node)
    return found


# The three characters SQL uses to delimit a name or a string. Doubling one
# of them inside its own quotes is the escape the standard defines, and the
# one `quote_ident` and every driver's identifier quoting implements.
_SQL_DELIMITERS = ("\"", "`", "'")


def _flatten_concat(node: ast.AST) -> list[ast.AST]:
    """`a + b + c` as three operands rather than two nested pairs."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_concat(node.left) + _flatten_concat(node.right)
    return [node]


def _doubled_delimiter(node: ast.AST) -> str:
    """The SQL delimiter a `.replace(d, d + d)` chain doubles, or ``""``."""
    for inner in ast.walk(node):
        if not (isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "replace" and len(inner.args) == 2):
            continue
        first, second = inner.args
        if not (isinstance(first, ast.Constant) and isinstance(second, ast.Constant)):
            continue
        if isinstance(first.value, str) and first.value in _SQL_DELIMITERS \
                and second.value == first.value * 2:
            return first.value
    return ""


def _quoted_identifier_names(value: ast.AST) -> set[str]:
    """Names a correctly quoted SQL identifier covers, and no others.

    Both halves are required and the second is what makes this a proof
    rather than a hopeful pattern. Doubling a `"` says the value cannot end
    an identifier — but only if the query put it inside one, so the literal
    immediately before it must close on that same delimiter and the literal
    immediately after it must open on it. `"SELECT * FROM '" + name + "'"`
    with `"` doubled escapes a character the parser will never read and
    leaves the one that ends the string; so does a value concatenated with
    no delimiter around it at all.

    Only the operand that was quoted. `'... "' + quoted + '" WHERE ' + rest`
    is one safe name and one injection, and clearing the expression would
    clear both.
    """
    found: set[str] = set()
    for node in ast.walk(value):
        parts = _flatten_concat(node)
        if len(parts) < 3:
            continue
        for index in range(1, len(parts) - 1):
            delimiter = _doubled_delimiter(parts[index])
            if not delimiter:
                continue
            before, after = parts[index - 1], parts[index + 1]
            if not (isinstance(before, ast.Constant)
                    and isinstance(before.value, str)
                    and before.value.endswith(delimiter)):
                continue
            if not (isinstance(after, ast.Constant)
                    and isinstance(after.value, str)
                    and after.value.startswith(delimiter)):
                continue
            found |= _referenced_names(parts[index])
    return found


def _html_only_names(value: ast.AST) -> set[str]:
    """Names an HTML-only neutralisation covers, written inside the sink.

    `html.escape(...)` and an autoescaping render both make a value safe to
    put in a page and say nothing about anywhere else it might go. Written
    to a variable first, they are recorded by `note_derivation` against the
    name; written straight into the call, there is no name to record them
    against, so the sink site subtracts them itself — and only when the sink
    is one the `html` family covers.
    """
    found = _autoescaped_names(value)
    for node in ast.walk(value):
        if isinstance(node, ast.Call) \
                and is_html_sanitizer(_called_name(node) or ""):
            found |= _referenced_names(node)
    return found


def _autoescaped_render(value: ast.AST) -> bool:
    """Whether this expression renders a *constant* template through an
    environment that escapes.

    Two facts, and neither alone would do. The template being a literal is
    what makes this not template injection — `sink.template` reads the same
    first argument and finds a constant. The environment escaping is what
    makes the interpolated value unable to close a tag. Written without the
    keyword, Jinja2 does not escape and the same call is the same bug, so
    the keyword is read rather than assumed.
    """
    for node in ast.walk(value):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "render"):
            continue
        current = node.func.value
        literal_template = False
        escaping = False
        while isinstance(current, ast.Call):
            name = _called_name(current) or ""
            if name.rpartition(".")[2] in ("from_string", "get_template"):
                literal_template = bool(current.args) and isinstance(
                    current.args[0], ast.Constant)
            if name.rpartition(".")[2] in ("Environment", "SandboxedEnvironment"):
                escaping = any(
                    word.arg == "autoescape"
                    and isinstance(word.value, ast.Constant)
                    and word.value.value is True
                    for word in current.keywords
                )
            current = (current.func.value
                       if isinstance(current.func, ast.Attribute) else None)
        if literal_template and escaping:
            return True
    return False


def _crlf_stripped_base(value: ast.AST) -> ast.AST | None:
    """The expression a `.replace('\\r','').replace('\\n','')` chain cleans.

    `None` when there is no such chain. Returned rather than a boolean
    because the chain is very often written *inside* something else —
    `re.sub(pattern, '****', str(x).replace('\\r','').replace('\\n',''))` is
    the ordinary shape — and the caller has to check that the value it
    cleaned is the only untrusted thing in the expression before believing it.
    """
    for node in ast.walk(value):
        removed = set()
        current = node
        while isinstance(current, ast.Call) \
                and isinstance(current.func, ast.Attribute):
            if current.func.attr == "replace" and len(current.args) == 2 \
                    and isinstance(current.args[0], ast.Constant) \
                    and isinstance(current.args[1], ast.Constant) \
                    and current.args[1].value == "":
                removed.add(current.args[0].value)
            current = current.func.value
        if "\r" in removed and "\n" in removed:
            return current
    return None


def _body_validated(statement: ast.If,
                    literals: frozenset[str] = frozenset()) -> tuple[set[str], int]:
    """Names an ``if x in (...)`` guard constrains, and where that stops.

    The mirror of `_validated_names`, and separate from it for the one reason
    that matters: ``if x not in allowed: return`` refuses, so the constraint
    holds for everything written after it, and clearing the name from that
    point on is exactly right. ``if x in allowed:`` refuses nothing — it
    constrains the value *inside the block* and says nothing at all about the
    lines that follow. Clearing it the same way would launder the second use.

    So the end line comes back with the names, and the caller gives the taint
    back when the walk passes it.
    """
    test = statement.test
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and (_all_literals(test.comparators[0])
                 or _plain_name(test.comparators[0]) in literals)):
        return set(), 0
    name = _plain_name(test.left)
    if not name:
        return set(), 0
    end = max((getattr(one, "end_lineno", None) or one.lineno)
              for one in statement.body)
    return {name}, end


@dataclass(frozen=True)
class _Handoff:
    """One identifier read inside one argument of a non-sink call.

    `slot` is what the call site says about *where* that argument lands: an
    `int` for a position, a `str` for a keyword, and `None` when the syntax
    settles nothing — `f(*rest)` spreads an unknown number of values, and
    `f(**options)` names none of them.

    Nothing here records whether the call was written `obj.method(...)`:
    the call site cannot tell a bound call from an unbound one — `Cls.m(obj,
    x)` and `obj.m(x)` are both an `ast.Attribute`, and `Runner().go(x)`
    renders as a bare `go` with no dot at all. The callee's own signature is
    what says whether a receiver takes the first slot.
    """

    callee: str
    name: str
    ref: CodeRef
    slot: int | str | None


def _argument_slots(node: ast.Call) -> list[tuple[ast.AST, int | str | None]]:
    """Each argument of a call, paired with the slot it fills.

    A starred argument consumes an unknown number of positions, so it and
    everything after it are unknown rather than merely shifted.
    """
    slots: list[tuple[ast.AST, int | str | None]] = []
    position: int | None = 0
    for argument in node.args:
        if isinstance(argument, ast.Starred):
            slots.append((argument.value, None))
            position = None
            continue
        slots.append((argument, position))
        if position is not None:
            position += 1
    # `keyword.arg` is already `None` for `**options`, which is exactly the
    # "settles nothing" slot.
    slots.extend((keyword.value, keyword.arg) for keyword in node.keywords)
    return slots


def _params_filled(params: tuple[str, ...],
                   slot: int | str | None) -> tuple[str, ...] | None:
    """The callee parameters an argument in this slot can fill.

    `None` means *any of them* — the answer this engine assumed for every
    call before slots were tracked, kept for the cases the syntax leaves
    open so that an unresolved position never silently drops a real path.

    The result is always a subset of what `None` would have allowed, so
    tracking slots can only ever remove a finding, never invent one.

    A receiver is skipped on the callee's word alone: a method is nearly
    always called bound, and the unbound `Cls.m(obj, x)` — the one shape
    this reads one slot short — is rare enough to be worth the trade.
    """
    if slot is None:
        return None
    if isinstance(slot, str):
        return (slot,) if slot in params else ()
    index = slot + 1 if params[:1] and params[0] in ("self", "cls") else slot
    # Past the end means the value landed in a `*args` the indexer does not
    # name, and a parameter with no name has no sink registered against it.
    return (params[index],) if index < len(params) else ()


@dataclass
class _Facts:
    """What one function body does with data, before cross-function resolution."""

    symbol: Symbol
    tainted: dict[str, CodeRef] = field(default_factory=dict)
    # variable -> the id of the source rule its taint came from, when known.
    origin_rule: dict[str, str] = field(default_factory=dict)
    # variable -> the parameter it was derived from. `target = path.strip()`
    # keeps the link to `path`, so a sink reached through `target` is still
    # registered against the parameter a caller fills — without it the chain
    # broke at the first local, and the path was reported from inside the
    # helper, starting nowhere.
    from_param: dict[str, str] = field(default_factory=dict)
    returns_taint: bool = False
    returns_rule: str = ""
    param_sinks: dict[str, list[tuple[str, CodeRef]]] = field(default_factory=dict)
    # Membership index for `param_sinks`, built lazily by the fixed point. The
    # list keeps the insertion order the report depends on; scanning it to
    # dedupe is quadratic in what a parameter accumulates — measured on
    # hermes/: 4.5 M membership tests walking 121 M entries.
    merged: dict[str, set[tuple[str, CodeRef]]] = field(default_factory=dict)
    # Names a guard proved safe *for a destination*, not in themselves. Kept
    # apart from `tainted` on purpose: popping them there would clear every
    # sink, and an SSRF guard is not an argument-injection guard.
    destination_safe: dict[str, set[str]] = field(default_factory=dict)
    sink_calls: list[tuple[str, CodeRef, tuple[str, ...]]] = field(default_factory=list)
    # Writes into a file the program itself named `secrets`, carrying
    # something other than a literal and not sealed by a digest or a cipher.
    # Held apart from `sink_calls` because there is no path to trace: what
    # makes CWE-312 a finding is the destination and the absence of the seal,
    # and the value's provenance decides nothing. `(open site, write site)`.
    unsealed_stores: list[tuple[CodeRef, CodeRef]] = field(default_factory=list)
    calls_out: list[_Handoff] = field(default_factory=list)
    assigns_from_call: list[tuple[str, str, CodeRef]] = field(default_factory=list)


def _sinks_reached(callee: _Facts,
                   handoff: _Handoff) -> list[list[tuple[str, CodeRef]]]:
    """The callee's sink lists this one argument can actually reach.

    Copied rather than aliased: a self-recursive call has the caller append
    to the very list being read, and `list()` on the dict alone left the
    inner lists live.
    """
    filled = _params_filled(callee.symbol.params, handoff.slot)
    if filled is None:
        return [list(sinks) for sinks in callee.param_sinks.values()]
    return [list(callee.param_sinks[name])
            for name in filled if name in callee.param_sinks]


def function_nodes(path: Path) -> dict[int, ast.AST]:
    """Every function body in one file, by the line it starts on.

    One parse per file, and the caller is expected to drop the result before
    moving to the next one. Parsing per symbol would re-read and re-parse a
    file as many times as it has functions; holding every file's bodies at
    once is the other extreme, and it is the expensive one — measured on
    hermes/ (4457 files, 75 243 bodies), keeping them all alive costs 2035 MB
    of peak RSS and 19.8 s against 136 MB and 12.3 s one file at a time.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (SyntaxError, ValueError, OSError, RecursionError):
        return {}
    return {
        node.lineno: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


# Methods that put a value *into* the thing they are called on. Taint has to
# follow, and it did not: measured on a labelled corpus, 27 % of the cases
# still missed in categories where Thot already has a working rule are this
# one shape —
#
#     parts = []
#     for token in str(cookie_value).split(","):
#         parts.append(token.strip())
#     db.execute("SELECT * FROM users WHERE id = " + ",".join(parts))
#
# `parts` was assigned an empty list and never re-assigned, so nothing in the
# walk ever made it untrusted, and the sink saw a clean name. Following a
# value into a container is ordinary taint analysis; leaving it out made the
# engine's answer depend on whether the author used a list.
CONTAINER_MUTATORS = frozenset({
    "append", "add", "extend", "insert", "update", "setdefault",
})


def _mutated_container(node: ast.Call) -> str | None:
    """The name a call mutates in place, or None.

    Only a bare name is answered for. `self.items.append(x)` and
    `rows[0].append(x)` mutate something the engine does not track as a name,
    and inventing one would taint a name that does not exist.
    """
    target = node.func
    if not isinstance(target, ast.Attribute):
        return None
    if target.attr not in CONTAINER_MUTATORS:
        return None
    return target.value.id if isinstance(target.value, ast.Name) else None


# How deep a constant program is followed when it compiles another one. Two
# is one more than anything honest writes and enough that the second level
# is not a place to hide.
_EVAL_DEPTH = 2


def _evaluated_source(node: ast.AST) -> str | None:
    """The constant Python source an `eval` or `exec` call runs, if any.

    `eval(compile(src, ...))` and the bare `exec(src)` are the same act with
    one more wrapper; the wrapper is unwrapped and the mode argument is not
    read, because `ast.parse` accepts what both modes accept.

    A constant, and never a computed string. `exec('total = ' + value)` is
    the injection `sink.eval` already reports, and parsing whatever the
    expression happens to spell at analysis time would be reading one
    possible attacker input as if it were the program.
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in ("eval", "exec") and node.args):
        return None
    argument = node.args[0]
    if isinstance(argument, ast.Call) and isinstance(argument.func, ast.Name) \
            and argument.func.id == "compile" and argument.args:
        argument = argument.args[0]
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    return None


def _inlined_evaluations(node: ast.AST, depth: int = _EVAL_DEPTH) -> list[ast.AST]:
    """Every constant program this body compiles and runs, as nodes.

    `eval` and `exec` run their argument in the calling scope, with the
    calling scope's names — so a string that reads `data` reads *this*
    `data`, and splicing its statements in at the call site is not an
    approximation of what happens, it is what happens.

    The corpus is unanimous and therefore useless as evidence: 48 cases use
    this shape and all 48 are on the vulnerable half. A rule keyed on the
    shape would have collected every one of them and known nothing. What
    decides here is the spliced code — `exec(compile('total = len(x)'))`
    produces nothing, as it should.

    Positions are rewritten before the nodes are returned. The snippet's own
    line numbers name lines of a file that does not exist; a reader can only
    open the `exec`, so every node reports it. Order inside the snippet is
    kept in `col_offset`, because `_ordered_nodes` sorts on it and a sink
    seen before the assignment that taints it would never be paired with it.
    """
    found: list[ast.AST] = []
    if depth <= 0:
        return found
    for child in ast.walk(node):
        source = _evaluated_source(child)
        if source is None:
            continue
        try:
            parsed = ast.parse(source)
        except (SyntaxError, ValueError):
            # Not Python, or Python this interpreter will not parse. The
            # call stays what it was: a compile of a constant.
            continue
        line = getattr(child, "lineno", 1)
        column = getattr(child, "col_offset", 0)
        inner = sorted(ast.walk(parsed),
                       key=lambda one: (getattr(one, "lineno", 0),
                                        getattr(one, "col_offset", 0)))
        for offset, one in enumerate(inner):
            one.lineno = one.end_lineno = line
            one.col_offset = column + 1 + offset
            one.end_col_offset = one.col_offset
        found.extend(inner)
        found.extend(_inlined_evaluations(parsed, depth - 1))
    return found


def _ordered_nodes(node: ast.AST) -> list[ast.AST]:
    """Walk the body in source order — `ast.walk` is breadth-first, which would
    let a sink be seen before the assignment that taints its argument."""
    nodes = list(ast.walk(node)) + _inlined_evaluations(node)
    return sorted(nodes, key=lambda n: (getattr(n, "lineno", 0),
                                        getattr(n, "col_offset", 0)))


_IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", re.M)


# A query written out in the file. Stronger evidence than an import: an
# import says a database library is reachable, this says SQL is being
# composed right here — whatever local wrapper ends up executing it.
# The same idea for Mongo, and for the same reason: `.find(` is a name every
# string and list answers to, and the driver is imported somewhere else. A
# quoted query operator is written by nothing but a Mongo query.
_MONGO_TEXT = re.compile(
    r"""['"]\$(?:where|ne|gt|gte|lt|lte|in|nin|or|and|not|nor|regex|expr"""
    r"""|elemMatch|exists|type|jsonSchema)['"]"""
)


_SQL_TEXT = re.compile(
    r"\b(?:SELECT\s+.*?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+.*?\bSET\b"
    r"|DELETE\s+FROM\b|CREATE\s+TABLE\b|DROP\s+TABLE\b)",
    re.I | re.S,
)


@lru_cache(maxsize=8192)
def _file_gates(path: Path) -> frozenset[str]:
    """What a file offers to satisfy a rule's `needs`.

    Its import names, plus markers for evidence that is not an import at all.
    Textual rather than parsed, for the reason the JavaScript catalog gives
    for the same gate: the indexer has already paid for one parse of every
    file, and an import sitting in a comment costs a gate that fires once too
    often — never one that fires too rarely.

    `sql:text` is the marker that pays for itself. Gating `execute` on a
    database import was right — the name belongs to a cursor, an LLM relay
    and a pipeline alike — but it assumed the database is imported where the
    query is written. Most code hides it behind a local wrapper: measured on
    100 labelled SQL-injection cases whose sink was `db.execute` after
    `from app_runtime import db`, the import gate found **none of them**.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    gates = set(_IMPORT_LINE.findall(text))
    if _SQL_TEXT.search(text):
        gates.add("sql:text")
    if _MONGO_TEXT.search(text):
        gates.add("mongo:text")
    return frozenset(gates)


def _available(rule, imported: frozenset[str]) -> bool:
    """Whether a rule that names required evidence can fire in this file."""
    if not rule.needs:
        return True
    return any(
        name == need or name.startswith(need + ".")
        for need in rule.needs
        for name in imported
    )


def _imports(package: str, imported: frozenset[str]) -> bool:
    """Whether a file imports a package, under any of its module names.

    `_file_gates` records what the import line said, and `from django.http
    import JsonResponse` records `django.http`; asking for `django` in that
    set finds nothing.
    """
    return any(name == package or name.startswith(package + ".")
               for name in imported)


def _analyse_body(symbol: Symbol, node: ast.AST,
                  imported: frozenset[str] = frozenset()) -> _Facts:
    facts = _Facts(symbol=symbol)
    # A view that returns a string has it sent as `text/html`. The decorator
    # is the gate and not the shape of the text: a helper that assembles a
    # fragment is not a response, and a rule on the markup alone would fire
    # on every template piece a program builds.
    from thot.scope.detect import _is_django_view, _is_route_decorated

    published = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
        and (_is_route_decorated(node)
             or _is_django_view(node, _imports("django", imported)))
    # `self` and `cls` are not input channels. Every other parameter is a
    # value some caller chose and may therefore be untrusted; the receiver is
    # the object the method is already part of, and its fields are tracked by
    # name (`self.host`) anyway. Counting it made every `self.anything` read
    # count as reading a parameter — measured on Hermes, that alone was most
    # of a 285-candidate jump, including `for tbl in self._FTS_TABLES`.
    params = set(symbol.params) - {"self", "cls"}

    # A function a registry calls has no caller in this graph, so its
    # parameters would stay merely "conditionally tainted" for ever — waiting
    # on a caller that lives in a framework. When a rule says this is an
    # entry point, they are tainted outright, because the thing that fills
    # them is a model or a request and not another function here.
    # A route's parameters are filled by the request. That is what makes it
    # a route, and it is the one thing the engine could not say about them:
    # every parameter is held untrusted until a caller proves otherwise, but
    # *untrusted* and *remote* are different facts and only the second decides
    # a travel-sensitive sink. With no source attributed, `impact_for` ranks
    # `open(url_capture)` one step down, into `low`, under the floor a default
    # report prints — the same silence `request.META` was hiding, one level up.
    #
    # `ENTRYPOINT_NAMES` is deliberately not consulted here. `main` is an
    # entry point too and its arguments come off the command line, where
    # whoever supplies them already holds this process's filesystem.
    if published:
        seed = CodeRef(path=symbol.path, line=symbol.lineno,
                       symbol=symbol.name, ast_hash=symbol.ast_hash)
        for name in params:
            facts.tainted.setdefault(name, seed)
            facts.origin_rule.setdefault(name, "source.http")

    entry = match_entry(symbol.name)
    if entry is not None:
        seed = CodeRef(path=symbol.path, line=symbol.lineno,
                       symbol=symbol.name, ast_hash=symbol.ast_hash)
        # Named parameters only, when the rule names any. A package-wide rule
        # that tainted every parameter would taint the `base_url` a helper
        # receives from configuration, and call it untrusted.
        untrusted = set(entry.parameters) & params if entry.parameters else params
        for name in untrusted:
            facts.tainted[name] = seed

    def carrier(names: set[str]) -> str | None:
        """The earliest-tainted name in a set, or None.

        Same choice `is_tainted` makes and for the same reason — set order is
        randomised per process — pulled out so the caller can ask which name
        answered, and inherit the source rule recorded against it.
        """
        found = [
            (facts.tainted[name].line, name) for name in names
            if name in facts.tainted
        ]
        return min(found)[1] if found else None

    def matching_source(names: set[str]):
        """The first source rule any of these names matches. Sorted: a set's
        order would choose which rule a finding reported."""
        for name in sorted(names):
            rule = match_source(name)
            if rule is not None:
                return rule
        return None

    def is_tainted(names: set[str]) -> CodeRef | None:
        """Return where the taint came from, or None.

        The *earliest* origin when several names carry taint, and not
        whichever the set happened to yield first. Sets iterate in hash
        order, string hashing is randomised per process, and the reported
        source line therefore moved between two runs of the same audit —
        measured on Hermes: 5 findings of 417, same identities, different
        origins. A report that changes when nothing changed is a report
        nobody can diff.
        """
        held = carrier(names)
        if held is not None:
            return facts.tainted[held]
        for name in sorted(names):
            if match_source(name):
                return None  # direct source: caller assigns the ref
        return None

    # How many times each call has already been seen in this body. AST order
    # is deterministic, so the count is the same on every run — and it only
    # has to hold within one version of the body, which `ast_hash` pins.
    call_ordinal: dict[str, int] = {}

    def ref_at(child: ast.AST) -> CodeRef:
        return CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name,
                       ast_hash=symbol.ast_hash)

    def bind(targets: list[ast.AST], value: ast.AST | None, ref: CodeRef,
             extra: frozenset[str] = frozenset()) -> None:
        """Taint what an assignment binds, whatever shape the assignment has.

        `x = f()` is one way of many to bind a name, and following it alone
        made the syntax decide whether a vulnerability existed: measured on a
        file carrying the same `request.args` -> `os.system` path written
        fourteen ways, 2 sites of 14 were reported, plus one that was not
        there.
        """
        names = [name for target in targets for name in _target_names(target)]
        if not names:
            return

        # Element to element when both sides line up, so `host, port =
        # request.args.get("host"), 80` does not call the literal untrusted.
        # A starred target eats an unknown slice of the right-hand side, so
        # the arity no longer says which element goes where.
        if (len(targets) == 1
                and isinstance(targets[0], (ast.Tuple, ast.List))
                and isinstance(value, (ast.Tuple, ast.List))
                and len(targets[0].elts) == len(value.elts)
                and not any(isinstance(e, ast.Starred) for e in targets[0].elts)):
            for target, element in zip(targets[0].elts, value.elts):
                bind([target], element, ref)
            return

        refs = _referenced_names(value) if value is not None else set()
        refs |= extra

        matched = matching_source(refs)
        if matched is not None:
            origin, came_from = ref, matched.id
        else:
            held = carrier(refs)
            origin = facts.tainted[held] if held else None
            came_from = facts.origin_rule.get(held, "") if held else ""
            if origin is None and refs & params:
                # A parameter may carry anything; which rule filled it is the
                # caller's fact, and the fixed point supplies it if it can.
                origin, came_from = ref, ""

        if origin is not None:
            # Sorted: which parameter is credited decides which caller the
            # path is reported through, and a set's order would choose it.
            direct = sorted(refs & params)
            inherited = [facts.from_param[r] for r in sorted(refs)
                         if r in facts.from_param]
            root = (direct + inherited or [""])[0]
            for name in names:
                facts.tainted[name] = origin
                facts.origin_rule[name] = came_from
                if root:
                    facts.from_param[name] = root
                else:
                    facts.from_param.pop(name, None)
        elif isinstance(value, ast.Call):
            called = _called_name(value)
            if called and not is_sanitizer(called):
                for name in names:
                    facts.assigns_from_call.append(
                        (name, called.rsplit(".", 1)[-1], ref)
                    )

    # An `ast.ExceptHandler` does not name the `try` it belongs to, and the
    # block it caught is what decides what the bound name holds.
    handler_bodies: dict[int, list] = {}
    for found in ast.walk(node):
        for handler in getattr(found, "handlers", ()):
            handler_bodies[id(handler)] = getattr(found, "body", [])

    # What each name was built from, accumulated in line order. A guard reads
    # `parsed.hostname` while the sink reads `target_url` three assignments
    # later; without the chain, clearing what the test names clears nothing
    # that reaches anything. `_referenced_names` records the called name too,
    # which is how `_came_from` can later tell a `urlparse` result from any
    # other object carrying a `.host` attribute.
    derives: dict[str, frozenset[str]] = {}
    # What a name currently *is*, for the three guards that need to know.
    # Rebound on every assignment and forgotten on every mutation, so a list
    # that was all-literal and then had a request value appended stops
    # counting as an allow-list at the line where that happens.
    literal_names: set[str] = set()
    constant_names: set[str] = set()
    resolved_names: set[str] = set()
    confined_bases: set[str] = set()

    def forget(names: list[str]) -> None:
        for name in names:
            literal_names.discard(name)
            constant_names.discard(name)
            resolved_names.discard(name)
            confined_bases.discard(name)

    def note_derivation(targets: list[ast.AST], value: ast.AST | None) -> None:
        names = [name for target in targets for name in _target_names(target)]
        forget(names)
        if value is None:
            return
        if len(names) != 1:
            # Tuple unpacking gives no honest answer about which element fed
            # which name, and a wrong chain here launders the wrong value.
            return
        name = names[0]
        derives[name] = frozenset(_referenced_names(value))
        if isinstance(value, ast.Call) and (
                is_html_sanitizer(_called_name(value) or "")
                or _autoescaped_render(value)):
            # Proved for HTML and for nothing else, so it goes with the other
            # destination proofs rather than into `tainted`.
            facts.destination_safe.setdefault("html", set()).add(name)
        read = _referenced_names(value)
        if read and read <= _quoted_identifier_names(value):
            # The whole query, and not merely part of it, is quoted: a second
            # operand left outside the delimiters is the injection this is
            # supposed to notice, so it has to fail the comparison.
            facts.destination_safe.setdefault("sql", set()).add(name)
        if _all_literals(value):
            literal_names.add(name)
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            constant_names.add(name)
        elif isinstance(value, ast.BinOp) and _referenced_names(value) <= constant_names:
            constant_names.add(name)
        elif _resolves_path(value):
            resolved_names.add(name)
            if _constant_rooted_path(value):
                confined_bases.add(name)
        elif isinstance(value, ast.Name):
            # `alias = allowed` is a second handle on the same object; the
            # alias is only as trustworthy as what it points at right now.
            for pool in (literal_names, constant_names, resolved_names,
                         confined_bases):
                if value.id in pool:
                    pool.add(name)

    # Names an `if x in allowed:` block constrains, and the line each stops
    # on. Not popped from `facts.tainted`: that map is read after the walk
    # finishes, and by then a positive guard has been left behind, so a
    # clearing there would either leak past the block or be undone before
    # anyone looked. The constraint is a fact about the *site*, so it is
    # applied where the site is recorded.
    guarded_until: list[tuple[int, str]] = []
    guarded_now: set[str] = set()
    # Handles opened on a spreadsheet. `with open('report.csv') as fh` is what
    # makes `fh.write` a cell rather than a line of text.
    sheet_handles: set[str] = set()
    # Handles opened on a file whose name says it holds a secret, and where
    # that name was written.
    store_handles: dict[str, CodeRef] = {}
    # Nested callbacks that write into a name belonging to this scope:
    # callback name -> [(argument position, name it writes)]. The ordinary
    # shape of a callback in Python, and the chain used to break at the name
    # the caller reads back one line later.
    captures: dict[str, list[tuple[int, str]]] = {}

    def under_guard() -> frozenset[str]:
        return frozenset(guarded_now)

    for child in _ordered_nodes(node):
        line = getattr(child, "lineno", 0) or 0
        if guarded_until and line:
            still = []
            for end, held in guarded_until:
                if line > end:
                    guarded_now.discard(held)
                else:
                    still.append((end, held))
            guarded_until = still

        if isinstance(child, ast.Assign):
            note_derivation(child.targets, child.value)
            bind(child.targets, child.value, ref_at(child))
            # Stripping CR and LF is a real neutralisation and a narrow one:
            # it defeats header injection, whose mechanism is those two
            # characters, and nothing else — a string carrying every
            # metacharacter a shell knows survives it. Hence the `header`
            # family alone.
            #
            # The chain is usually written inside something larger,
            # `re.sub(p, '****', str(x).replace('\r','').replace('\n',''))`
            # being the ordinary shape, so what it cleaned has to be
            # everything untrusted the expression carries. Asked here rather
            # than in a helper because only here is it known what is tainted.
            if _sealed(child.value):
                facts.destination_safe.setdefault("storage", set()).update(
                    target.id for target in child.targets
                    if isinstance(target, ast.Name)
                )
            cleaned = _crlf_stripped_base(child.value)
            if cleaned is not None:
                outside = (_referenced_names(child.value)
                           - _referenced_names(cleaned))
                if not any(name in facts.tainted or match_source(name)
                           for name in outside):
                    facts.destination_safe.setdefault("header", set()).update(
                        target.id for target in child.targets
                        if isinstance(target, ast.Name)
                    )

        elif isinstance(child, ast.AnnAssign):
            if child.value is not None:
                note_derivation([child.target], child.value)
                bind([child.target], child.value, ref_at(child))

        elif isinstance(child, ast.AugAssign):
            # `command += " --now"` reads `command` too, so a constant on the
            # right must not launder what the target already carried.
            forget(list(_target_names(child.target)))
            bind([child.target], child.value, ref_at(child),
                 extra=frozenset(_target_names(child.target)))

        elif isinstance(child, ast.NamedExpr):
            bind([child.target], child.value, ref_at(child))

        elif isinstance(child, ast.If):
            # Nodes are walked in line order, so clearing here is exactly
            # "from this guard onwards". `from_param` goes too: a name left
            # linked to the parameter it came from would be re-tainted by the
            # fixed point one level up, which is the same finding wearing a
            # caller's name.
            for family, names in _destination_validated(
                    child, derives, frozenset(constant_names),
                    frozenset(confined_bases)).items():
                facts.destination_safe.setdefault(family, set()).update(names)
            for name in _validated_names(child, derives,
                                         frozenset(literal_names)):
                facts.tainted.pop(name, None)
                facts.origin_rule.pop(name, None)
                facts.from_param.pop(name, None)

            # The positive form of the same guard. Cleared only for the block
            # it opens; `guarded_until` hands the taint back after it.
            inside, ends = _body_validated(child, frozenset(literal_names))
            for name in inside:
                guarded_until.append((ends, name))
                guarded_now.add(name)

        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            declared = {name for inner in ast.walk(child)
                        if isinstance(inner, ast.Nonlocal)
                        for name in inner.names}
            if declared:
                slots = [one.arg for one in child.args.args]
                writes: list[tuple[int, str]] = []
                for inner in ast.walk(child):
                    if not isinstance(inner, ast.Assign) or len(inner.targets) != 1:
                        continue
                    target = inner.targets[0]
                    if not isinstance(target, ast.Name) or target.id not in declared:
                        continue
                    for read in _referenced_names(inner.value):
                        if read in slots:
                            writes.append((slots.index(read), target.id))
                if writes:
                    captures[child.name] = writes

        elif isinstance(child, (ast.For, ast.AsyncFor)):
            bind([child.target], child.iter, ref_at(child))

        elif isinstance(child, (ast.With, ast.AsyncWith)):
            # Bound from the `with` and not from its `withitem`s: a withitem
            # carries no `lineno`, and `_ordered_nodes` sorts on that — it
            # would land at the top of the body, ahead of the assignments
            # that really precede it, which is the one thing that walk order
            # exists to prevent.
            for item in child.items:
                if item.optional_vars is not None:
                    bind([item.optional_vars], item.context_expr, ref_at(child))
                    opened = item.context_expr
                    if isinstance(item.optional_vars, ast.Name) \
                            and isinstance(opened, ast.Call) \
                            and _called_name(opened) == "open" \
                            and opened.args \
                            and isinstance(opened.args[0], ast.Constant) \
                            and isinstance(opened.args[0].value, str) \
                            and opened.args[0].value.lower().endswith(
                                (".csv", ".tsv")):
                        sheet_handles.add(item.optional_vars.id)
                    if isinstance(item.optional_vars, ast.Name) \
                            and isinstance(opened, ast.Call) \
                            and _called_name(opened) == "open" \
                            and opened.args \
                            and isinstance(opened.args[0], ast.Constant) \
                            and isinstance(opened.args[0].value, str) \
                            and _SENSITIVE_NAME.search(opened.args[0].value):
                        store_handles[item.optional_vars.id] = ref_at(child)

        elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp,
                                ast.GeneratorExp)):
            # Same reason as `with`: `ast.comprehension` has no `lineno`, so
            # the comprehension node itself carries the binding.
            for generator in child.generators:
                bind([generator.target], generator.iter, ref_at(child))

        elif isinstance(child, ast.ExceptHandler) and child.name:
            # `except ... as host` rebinds the name to the caught exception:
            # whatever it carried before is gone, exactly as `host = "safe"`
            # would end it. What it holds instead is not nothing — the
            # exception was raised by the protected block, and carries what
            # that block was working on. `int(sys.argv[1])` fails with
            # `invalid literal for int() with base 10: '<the argument>'`.
            #
            # Read through sanitizers, and only here: a converter that
            # *rejects* its input is precisely how that input escapes, so the
            # rule that stops propagation at `int()` is the one rule that
            # cannot apply to the value it refused.
            facts.tainted.pop(child.name, None)
            protected = handler_bodies.get(id(child))
            if protected:
                raised: set[str] = set()
                for statement in protected:
                    raised |= _referenced_names(
                        statement, through_sanitizers=True
                    )
                bind([ast.Name(id=child.name, ctx=ast.Store())], None,
                     ref_at(child), extra=frozenset(raised))

        elif isinstance(child, ast.Return) and child.value is not None:
            if published and _opens_with_markup(child.value):
                facts.sink_calls.append((
                    "sink.xss", ref_at(child),
                    tuple(sorted(_referenced_names(child.value)
                                 - _html_only_names(child.value)
                                 - under_guard())),
                ))
            for rule_id, written in _header_targets(child):
                facts.sink_calls.append((
                    rule_id, ref_at(child),
                    tuple(sorted(_referenced_names(written) - under_guard())),
                ))
            refs = _referenced_names(child.value)
            matched = matching_source(refs)
            held = carrier(refs)
            if matched is not None or held is not None:
                facts.returns_taint = True
                if not facts.returns_rule:
                    facts.returns_rule = (
                        matched.id if matched is not None
                        else facts.origin_rule.get(held, "")
                    )

        elif isinstance(child, ast.Call):
            holder = _mutated_container(child)
            if holder is not None:
                forget([holder])
                # `extra` carries the holder itself, so appending never
                # launders what the list already held — the same reason
                # `AugAssign` above reads its own target.
                carried: set[str] = {holder}
                for argument in list(child.args) + [k.value for k in child.keywords]:
                    carried |= _referenced_names(argument)
                bind([ast.Name(id=holder, ctx=ast.Store())], None,
                     ref_at(child), extra=frozenset(carried))

            for rule_id, written in _header_targets(child):
                facts.sink_calls.append((
                    rule_id, ref_at(child),
                    tuple(sorted(_referenced_names(written) - under_guard())),
                ))

            # A call to one of those callbacks carries its argument into the
            # name the callback writes, here in the scope that owns it.
            for position, target in captures.get(_called_name(child) or "", ()):
                if position < len(child.args):
                    bind([ast.Name(id=target, ctx=ast.Store())],
                         child.args[position], ref_at(child))

            written_to = _called_name(child) or ""
            holder_name, _, method = written_to.rpartition(".")
            if holder_name in store_handles and method.startswith("write"):
                stored: set[str] = set()
                for argument in list(child.args) + [k.value for k in child.keywords]:
                    stored |= _referenced_names(argument)
                facts.sink_calls.append((
                    "sink.cleartext", ref_at(child),
                    tuple(sorted(stored - under_guard())),
                ))
                written = list(child.args) + [k.value for k in child.keywords]
                # A literal is what the program wrote itself — a header, a
                # separator — and a sealed value is not the secret. Anything
                # else put into this file is being kept in the clear, and the
                # filename is the program saying what it is.
                if any(not isinstance(one, ast.Constant)
                       and not _sealed(one)
                       and not (_referenced_names(one)
                                & facts.destination_safe.get("storage", set()))
                       for one in written):
                    facts.unsealed_stores.append(
                        (store_handles[holder_name], ref_at(child)))

            if holder_name in sheet_handles \
                    and method in ("write", "writerow", "writerows"):
                cells: set[str] = set()
                for argument in list(child.args) + [k.value for k in child.keywords]:
                    cells |= _referenced_names(argument)
                facts.sink_calls.append((
                    "sink.csv", ref_at(child),
                    tuple(sorted(cells - under_guard())),
                ))

            called = _called_name(child)
            if not called:
                continue
            seen_before = call_ordinal.get(called, 0)
            call_ordinal[called] = seen_before + 1
            ref = CodeRef(path=symbol.path, line=child.lineno, symbol=symbol.name,
                          ast_hash=symbol.ast_hash,
                          site=f"{called}#{seen_before}")

            rule = match_sink(called)
            if rule is not None and not _available(rule, imported):
                rule = None

            if rule is not None and rule.dangerous_args:
                considered = [
                    child.args[index]
                    for index in rule.dangerous_args
                    if index < len(child.args)
                ]
            else:
                considered = list(child.args) + [k.value for k in child.keywords]

            argument_refs: set[str] = set()
            proved: dict[str, set[str]] = {"html": set(), "sql": set()}
            for argument in considered:
                argument_refs |= _referenced_names(argument)
                proved["html"] |= _html_only_names(argument)
                proved["sql"] |= _quoted_identifier_names(argument)

            if rule is not None and not _sink_applies(rule.id, child):
                rule = None

            if rule is not None:
                # Subtracted here and not above: an escape written inside the
                # call proves what it proves for *this* destination. Removed
                # from every argument set, `HTMLResponse(html.escape(x))` on
                # one line would have cleared `os.system(x)` on the next.
                cleared: set[str] = set()
                for family in _proves_for(rule.id):
                    cleared |= proved.get(family, set())
                facts.sink_calls.append((
                    rule.id, ref,
                    tuple(sorted(argument_refs - cleared - under_guard())),
                ))
                # Sorted: this decides the insertion order of `param_sinks`,
                # the fixed point iterates it by that order, and `emit` keeps
                # the first candidate per sink — so a set's hash order was
                # choosing which origin a finding reported.
                # A parameter read straight into the sink, plus any local
                # that carries one — the second is the ordinary shape, and
                # leaving it out is what stopped a caller ever being paired
                # with this sink.
                roots = set(argument_refs & params)
                roots.update(
                    facts.from_param[name] for name in argument_refs
                    if name in facts.from_param
                )
                for name in sorted(roots):
                    facts.param_sinks.setdefault(name, []).append((rule.id, ref))
            else:
                short = called.rsplit(".", 1)[-1]
                # One argument at a time, so the slot each name was read from
                # survives into `calls_out`. Merging them into a single set —
                # what this did before — is what made a value handed to a safe
                # parameter reach every sink of the callee.
                for argument, slot in _argument_slots(child):
                    outgoing = _referenced_names(argument)
                    # Sorted, like every other set that reaches the output.
                    # Case 2 emits the first caller that feeds a given sink and
                    # dedupes the rest, so this order chose which origin a
                    # finding showed.
                    for name in sorted(outgoing):
                        facts.calls_out.append(_Handoff(short, name, ref, slot))

    _spread_destination_safe(facts, derives)
    return facts


def _spread_destination_safe(facts: "_Facts",
                             derives: Mapping[str, frozenset[str]]) -> None:
    """Carry a destination proof forward, the way taint is carried forward.

    The guard constrains the value it reads; the sink is reached through
    whatever was built from it afterwards —

        if ipaddress.ip_address(resolved).is_private: return 403
        target_url = data.replace(parsed.hostname, resolved)
        requests.get(target_url)

    — so a set holding only `data`, `parsed` and `resolved` answers nothing
    about `target_url`, and the guard buys nothing at all. Value guards do not
    need this because they *pop* from `tainted`, and every later assignment
    then reads clean names; a destination proof cannot pop, because popping
    would clear it for every other kind of sink too.

    A name joins only when **every** untrusted thing it was built from is
    already proved. `url = safe_host + request.args["path"]` keeps its taint,
    which is the case that makes the difference between a proof and a wish.
    """
    for proved in facts.destination_safe.values():
        changed = True
        while changed:
            changed = False
            for name, sources in derives.items():
                if name in proved:
                    continue
                risky = {source for source in sources if source in facts.tainted}
                if risky and risky <= proved:
                    proved.add(name)
                    changed = True


def _impact_for(rule_id: str) -> Severity:
    for rule in active().sinks:
        if rule.id == rule_id:
            return rule.impact
    return Severity.MEDIUM


def _description_for(rule_id: str) -> str:
    for rule in active().sinks:
        if rule.id == rule_id:
            return rule.description
    return ""


def find_candidates(
    root: Path, graph: CodeGraph, max_depth: int = 3
) -> list[TaintCandidate]:
    """Return every source-to-sink path the deterministic analysis can prove.

    The repository's own rules are installed for the duration of the scan, so
    a team's shell wrapper and its validators count exactly like the built-in
    ones. Scoped, so they never leak into the next analysis.
    """
    from thot.codemap.rules import load_catalog

    root = Path(root)
    with using(load_catalog(root)):
        return _find_candidates(root, graph, max_depth)


def _find_candidates(
    root: Path, graph: CodeGraph, max_depth: int
) -> list[TaintCandidate]:

    # Python only. `graph.symbols` carries the TypeScript side too, and every
    # one of those paths used to be opened and handed to `ast.parse`: measured
    # on hermes/, 1957 .ts/.tsx/.js files read for 0 successes.
    by_path: dict[str, list[Symbol]] = {}
    for symbol in graph.symbols.values():
        if symbol.kind == "function" and symbol.path.lower().endswith(PYTHON_SUFFIXES):
            by_path.setdefault(symbol.path, []).append(symbol)

    facts_by_name: dict[str, _Facts] = {}
    for relative, symbols in by_path.items():
        # Rebound each turn, so one file's bodies are the only ones alive.
        nodes = function_nodes(root / relative)
        imported = _file_gates(root / relative)
        for symbol in symbols:
            node = nodes.get(symbol.lineno)
            if node is None:
                continue
            facts_by_name[symbol.name] = _analyse_body(symbol, node, imported)

    by_short: dict[str, list[str]] = {}
    for name in facts_by_name:
        by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

    def resolve(short: str, caller: str = "") -> list[_Facts]:
        """Definitions a bare call name can mean, the caller's module first.

        Matching on the short name alone across the whole tree links any two
        functions that happen to share one. Found on Hermes, and refuted by
        the panel with the reason spelled out: `agent/command_token_source.py`
        defines `_mint(command, label)` running `subprocess.run(..., shell=
        True)`, `tests/plugins/test_chronos_verify.py` defines its own
        `_mint(priv, claims)` signing a JWT, and the test calls its own. The
        engine reported a HIGH path from attacker data to a shell.

        Python resolves the local definition, so this does too; the tree-wide
        match stays as the fallback for an imported helper, which has no
        definition in the caller's module.
        """
        names = by_short.get(short, [])
        module = caller.rsplit(".", 1)[0] if "." in caller else ""
        if module:
            local = [n for n in names if n.rsplit(".", 1)[0] == module]
            if local:
                names = local
        return [facts_by_name[n] for n in names]

    # Fixed point: propagate tainted return values and tainted parameters
    # across call edges until nothing changes, bounded by max_depth.
    for _ in range(max_depth):
        changed = False
        for facts in facts_by_name.values():
            for target, callee_short, ref in facts.assigns_from_call:
                if target in facts.tainted:
                    continue
                reached = [c for c in resolve(callee_short, facts.symbol.name)
                           if c.returns_taint]
                if reached:
                    facts.tainted[target] = ref
                    facts.origin_rule[target] = next(
                        (c.returns_rule for c in reached if c.returns_rule), ""
                    )
                    changed = True

            # Hoisted: this ran once per outgoing argument, in the hot loop of
            # the fixed point.
            own_params = set(facts.symbol.params)
            for handoff in facts.calls_out:
                if handoff.name not in own_params:
                    continue
                for callee in resolve(handoff.callee, facts.symbol.name):
                    for sinks in _sinks_reached(callee, handoff):
                        existing = facts.param_sinks.setdefault(handoff.name, [])
                        merged = facts.merged.get(handoff.name)
                        if merged is None:
                            # Seeded from the list, never empty: `_analyse_body`
                            # already put this body's own sinks there, and a
                            # self-recursive call would add them a second time.
                            merged = facts.merged[handoff.name] = set(existing)
                        for entry in sinks:
                            if entry not in merged:
                                merged.add(entry)
                                existing.append(entry)
                                changed = True
        if not changed:
            break

    candidates: list[TaintCandidate] = []
    seen: dict[tuple[str, str, int], int] = {}

    def emit(rule_id: str, source: CodeRef, sink: CodeRef,
             path: tuple[CodeRef, ...], source_rule: str = ""):
        key = (rule_id, sink.path, sink.line)
        if key in seen:
            # The same sink can be reached twice: once inside the body whose
            # parameter is tainted by assumption and names no rule, and once
            # from the caller that actually filled it. Keeping whichever came
            # first meant keeping the version that knew nothing — and case 1
            # always runs before case 2.
            held = candidates[seen[key]]
            if source_rule and not held.source_rule:
                candidates[seen[key]] = replace(
                    held, source=source, path=path, source_rule=source_rule,
                    impact=impact_for(rule_id, source_rule),
                )
            return
        seen[key] = len(candidates)
        candidates.append(
            TaintCandidate(
                rule=rule_id,
                source=source,
                sink=sink,
                path=path,
                impact=impact_for(rule_id, source_rule),
                description=_description_for(rule_id),
                source_rule=source_rule,
            )
        )

    # Case 1 — the source and the sink live in the same body.
    for facts in facts_by_name.values():
        for rule_id, ref, arg_names in facts.sink_calls:
            origin = None
            came_from = ""
            for arg in arg_names:
                if any(arg in facts.destination_safe.get(family, ())
                       for family in _proves_for(rule_id)):
                    continue
                if arg in facts.tainted:
                    origin = facts.tainted[arg]
                    came_from = facts.origin_rule.get(arg, "")
                    break
                straight = match_source(arg)
                if straight is not None:
                    origin = ref  # source read straight into the sink
                    came_from = straight.id
                    break
            if origin is not None:
                emit(rule_id, origin, ref, (origin, ref), came_from)

    # Case 2 — a caller feeds tainted data into a propagating parameter.
    for facts in facts_by_name.values():
        for handoff in facts.calls_out:
            arg, call_ref = handoff.name, handoff.ref
            origin = facts.tainted.get(arg)
            came_from = facts.origin_rule.get(arg, "")
            straight = match_source(arg)
            if origin is None and straight is not None:
                # A source handed straight to the callee, without being stored
                # first. Case 1 has always accepted the same shape into a sink
                # in its own body — "source read straight into the sink" — and
                # the omission here made `launch(sys.argv[1])` invisible while
                # `cmd = sys.argv[1]; launch(cmd)` was reported. The inline
                # form is the more common of the two.
                origin = call_ref
                came_from = straight.id
            if origin is None:
                continue
            for callee in resolve(handoff.callee, facts.symbol.name):
                for sinks in _sinks_reached(callee, handoff):
                    for rule_id, sink_ref in sinks:
                        emit(rule_id, origin, sink_ref,
                             (origin, call_ref, sink_ref), came_from)

    # Case 3 — a store kept in the clear. Last, so that when the same write
    # was also reached by a traced path, `emit` keeps the version that knows
    # where the value came from.
    for facts in facts_by_name.values():
        for opened, written in facts.unsealed_stores:
            emit("sink.cleartext", opened, written, (opened, written))

    return candidates
