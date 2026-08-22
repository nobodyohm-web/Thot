"""The ported security patterns, applied as an audit sweep.

Taint analysis proves a path and covers Python only. These 25 patterns prove
nothing but recognise shapes that are dangerous wherever they appear, in
JavaScript and YAML too. The two are complementary, and neither replaces the
other — what matters here is that the sweep stays precise enough to be worth
reading.
"""

from __future__ import annotations

import pytest

from thot.contracts import Confidence, Severity
from thot.guard.scanner import scan_text, sweep_patterns


def test_pickle_load_is_flagged():
    findings = scan_text("app.py", "import pickle\ndata = pickle.loads(blob)\n")
    assert [f.rule for f in findings] == ["pattern.pickle_deserialization"]
    assert findings[0].location.line == 2


def test_the_reminder_becomes_the_scenario():
    findings = scan_text("app.py", "import yaml\ncfg = yaml.load(raw)\n")
    assert findings
    assert "yaml.safe_load" in findings[0].failure_scenario


def test_a_javascript_pattern_is_caught():
    findings = scan_text("ui.jsx", "el.innerHTML = userInput;\n")
    assert findings
    assert findings[0].rule == "pattern.innerHTML_xss"


def test_path_filters_are_respected():
    """A Python pattern must not fire inside a JavaScript file."""
    assert scan_text("ui.js", "pickle.loads(x)\n") == []


def test_tls_verification_disabled_is_caught():
    findings = scan_text("client.py", "requests.get(url, verify=False)\n")
    assert findings
    assert findings[0].rule == "pattern.tls_verification_disabled"


def test_clean_code_produces_nothing():
    assert scan_text("app.py", "import json\ndata = json.loads(blob)\n") == []


def test_findings_are_plausible_never_confirmed():
    findings = scan_text("app.py", "eval(user_input)\n")
    assert findings
    assert all(f.confidence is Confidence.PLAUSIBLE for f in findings)


def test_severity_is_assigned_per_rule():
    critical = scan_text("app.py", "import pickle\npickle.loads(b)\n")
    assert critical[0].severity in {Severity.CRITICAL, Severity.HIGH}


def test_identity_is_stable_across_line_moves():
    first = scan_text("app.py", "import pickle\npickle.loads(b)\n")
    second = scan_text("app.py", "\n\n\nimport pickle\npickle.loads(b)\n")
    assert first[0].id == second[0].id


def test_the_same_rule_twice_in_a_file_is_reported_once():
    findings = scan_text("app.py", "pickle.loads(a)\npickle.loads(b)\n")
    assert len(findings) == 1


def test_sweep_reads_the_repository(tmp_path):
    (tmp_path / "a.py").write_text("import pickle\npickle.loads(x)\n")
    (tmp_path / "b.py").write_text("import json\njson.loads(x)\n")
    findings = sweep_patterns(tmp_path, ["a.py", "b.py"])
    assert len(findings) == 1
    assert findings[0].location.path == "a.py"


def test_an_unreadable_file_is_skipped_not_fatal(tmp_path):
    assert sweep_patterns(tmp_path, ["absent.py"]) == []


# -- literals and comments are not code --------------------------------------
# A pattern scanner that reads string literals flags every rule catalog, every
# test fixture and every piece of documentation that mentions a dangerous call.
# On Thot's own source that was 25 findings, all of them false.


def test_a_pattern_inside_a_string_literal_is_not_a_finding():
    assert scan_text("catalog.py", 'PATTERNS = ["pickle.loads", "os.system"]\n') == []


def test_a_pattern_inside_a_comment_is_not_a_finding():
    assert scan_text("a.py", "# never call pickle.loads on user data\n") == []


def test_a_pattern_inside_a_docstring_is_not_a_finding():
    assert scan_text("a.py", '"""Avoid pickle.loads here."""\n') == []


def test_real_code_is_still_caught_next_to_a_mention():
    text = 'DOC = "pickle.loads"\nimport pickle\npickle.loads(x)\n'
    findings = scan_text("a.py", text)
    assert len(findings) == 1
    assert findings[0].location.line == 3


def test_unparseable_python_still_gets_scanned():
    """A syntax error must not silently disable the sweep for that file."""
    assert scan_text("a.py", "def broken(:\npickle.loads(x)\n")


def test_non_python_files_are_unaffected():
    assert scan_text("ui.jsx", "el.innerHTML = x;\n")


# -- identity must expire when the dangerous line changes --------------------
# A pattern finding's id keys its stored verdict. Keying on the rule name alone
# made that verdict immortal: dismiss one os.system in a file and any future
# os.system in that same file inherits the dismissal.


def test_identity_changes_when_the_matching_line_changes():
    safe = scan_text("a.py", "import os\nos.system(FIXED_COMMAND)\n")
    risky = scan_text("a.py", "import os\nos.system(user_input)\n")
    assert safe and risky
    assert safe[0].id != risky[0].id


def test_identity_survives_edits_elsewhere_in_the_file():
    before = scan_text("a.py", "import os\nos.system(cmd)\n")
    after = scan_text("a.py", "import os\n\ndef helper():\n    pass\n\nos.system(cmd)\n")
    assert before[0].id == after[0].id


def test_identity_survives_reindentation():
    flat = scan_text("a.py", "import os\nos.system(cmd)\n")
    nested = scan_text("a.py", "import os\nif x:\n        os.system(cmd)\n")
    assert flat[0].id == nested[0].id


# -- the vendored Hermes cron monitor ----------------------------------------


def _monitor():
    """Hermes's cron monitor, imported from the tree this program ships."""
    import importlib.util
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    path = root / "cron" / "monitor.py"
    if not path.is_file():
        pytest.skip("cette version de Hermes n'a pas ce module")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location("hermes_cron_monitor", path)
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the module holds dataclasses, and
    # `@dataclass` resolves annotations through `sys.modules[__name__]`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_cron_monitor_refuses_an_address_only_this_host_can_reach():
    """Confirmed by the panel: SSRF with the response handed back.

    `monitor_url` is settable through an agent tool, so a prompt-injected
    model can point the fetch at the cloud metadata service — and the body
    comes back into its own prompt. The scheme check stopped `file://` and
    nothing else.
    """
    monitor = _monitor()
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/admin",
        "http://localhost/admin",
        "http://10.0.0.5/",
    ):
        assert monitor._refuse_internal_target(url), url


def test_the_cron_monitor_still_allows_a_public_address():
    monitor = _monitor()
    assert monitor._refuse_internal_target("https://example.com/status") is None


def test_a_redirect_is_checked_as_well_as_the_first_hop():
    """A host an attacker owns answers publicly, then redirects to loopback."""
    monitor = _monitor()
    opener = monitor._guarded_opener()
    handler = next(
        h for h in opener.handlers
        if type(h).__name__ == "_NoInternalRedirects"
    )
    with pytest.raises(OSError):
        handler.redirect_request(
            None, None, 302, "Found", {}, "http://127.0.0.1/secret"
        )


def _a2a_security():
    """Hermes's A2A callback guard, from the tree this program ships."""
    import importlib.util
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    path = root / "plugins" / "platforms" / "a2a" / "security.py"
    if not path.is_file():
        pytest.skip("cette version de Hermes n'a pas l'adaptateur A2A")
    spec = importlib.util.spec_from_file_location("a2a_security_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a_callback_hostname_is_resolved_before_it_is_trusted(monkeypatch):
    """The guard read the spelling of the address and never the address.

    `is_safe_callback_url` checked a prefix list and an IP literal, then let
    every hostname through with `pass  # not an IP, it's a hostname — fine`.
    The docstring promised that internal addresses were blocked; a name the
    caller controls answers 127.0.0.1 as readily as a public address.
    Confirmed by the adversarial pass on the real file, not theorised.
    """
    import socket

    security = _a2a_security()
    monkeypatch.setenv("A2A_BEARER_TOKEN", "x")  # remote mode: the risky one
    assert security.localhost_only() is False

    def resolving_to(address):
        return lambda *a, **kw: [(2, 1, 6, "", (address, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", resolving_to("127.0.0.1"))
    assert security.is_safe_callback_url("http://rebind.example/cb") is False

    monkeypatch.setattr(socket, "getaddrinfo", resolving_to("169.254.169.254"))
    assert security.is_safe_callback_url("http://metadata.example/cb") is False

    monkeypatch.setattr(socket, "getaddrinfo", resolving_to("93.184.216.34"))
    assert security.is_safe_callback_url("http://public.example/cb") is True


def test_a_name_that_does_not_resolve_is_refused(monkeypatch):
    """There is nothing to deliver to, and it is the safe direction."""
    import socket

    security = _a2a_security()
    monkeypatch.setenv("A2A_BEARER_TOKEN", "x")
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("nope")),
    )
    assert security.is_safe_callback_url("http://nowhere.invalid/cb") is False


def test_one_private_answer_among_several_is_enough_to_refuse(monkeypatch):
    """A name can carry several records; the first one is not the question."""
    import socket

    security = _a2a_security()
    monkeypatch.setenv("A2A_BEARER_TOKEN", "x")
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 0)),
                          (2, 1, 6, "", ("10.0.0.5", 0))],
    )
    assert security.is_safe_callback_url("http://mixed.example/cb") is False


def test_the_a2a_fetch_helpers_refuse_a_redirect_to_a_private_address(monkeypatch):
    """Checking the first URL only is theatre: `urlopen` follows redirects.

    Found by the adversarial pass on the code as it stood *after* the first
    fix — the guard resolved the name it was given and then let the request
    walk wherever a 302 pointed it.
    """
    import socket

    security = _a2a_security()
    monkeypatch.setenv("A2A_BEARER_TOKEN", "x")
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))]
    )
    opener = security.guarded_opener()
    handler = next(
        h for h in opener.handlers if type(h).__name__ == "_NoInternalRedirects"
    )
    with pytest.raises(OSError):
        handler.redirect_request(None, None, 302, "Found", {},
                                 "http://rebind.example/next")


def test_a2a_discover_refuses_a_model_supplied_internal_url(monkeypatch):
    """`a2a_discover` takes its URL from a tool argument, so from the model.

    The `# noqa: S310 (configured peers)` on the fetch helpers does not cover
    this path, and the body of the response is summarised back into the
    model's own context.
    """
    import importlib.util
    import socket
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    path = root / "plugins" / "platforms" / "a2a" / "tools.py"
    if not path.is_file():
        pytest.skip("cette version de Hermes n'a pas l'adaptateur A2A")

    source = path.read_text(encoding="utf-8")
    assert "if not security.is_safe_callback_url(url):" in source, (
        "a2a_discover doit valider l'URL avant de la chercher"
    )
    assert "security.guarded_opener()" in (
        (root / "plugins" / "platforms" / "a2a" / "tools.py").read_text(encoding="utf-8")
    ), "les aides HTTP doivent contrôler les redirections"


def _hermes_utils():
    import importlib.util
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    path = root / "utils.py"
    if not path.is_file():
        pytest.skip("cette version de Hermes n'a pas utils.py")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location("hermes_utils_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_shared_guard_refuses_every_way_in(monkeypatch):
    """One guard, because it was needed in four places.

    The cron monitor's URL, the A2A callback, the A2A peer fetch and the
    image plugin's source images — every one of them takes its URL from
    something a model or a peer supplies.
    """
    import socket

    utils = _hermes_utils()

    assert utils.refuse_internal_url("file:///etc/passwd")
    assert utils.refuse_internal_url("http://127.0.0.1/x")

    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(2, 1, 6, "", ("10.0.0.5", 0))]
    )
    assert utils.refuse_internal_url("http://interne.example/x")

    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("nope")),
    )
    assert utils.refuse_internal_url("http://absent.invalid/x")

    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    assert utils.refuse_internal_url("http://public.example/x") is None


def test_the_image_plugin_checks_its_model_supplied_sources():
    """`image_url` is a tool argument, so it comes from the model."""
    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    plugin = root / "plugins" / "image_gen" / "openai" / "__init__.py"
    if not plugin.is_file():
        pytest.skip("cette version de Hermes n'a pas ce plugin")

    source = plugin.read_text(encoding="utf-8")
    assert "refuse_internal_url" in source
    assert "refused image source" in source


def test_a2a_call_refuses_a_raw_internal_url_from_the_model():
    """`agent` is a tool argument, and it accepts a URL as well as a name.

    Guarding `a2a_discover` alone left the door that POSTs a message wide
    open. The panel confirmed the same two lines a second time, on the code
    as it stood after the first fix.
    """
    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    tools = root / "plugins" / "platforms" / "a2a" / "tools.py"
    if not tools.is_file():
        pytest.skip("cette version de Hermes n'a pas l'adaptateur A2A")

    source = tools.read_text(encoding="utf-8")
    resolve = source.split("def _resolve_peer")[1].split("\ndef ")[0]
    # The strict guard, not the callback one: `is_safe_callback_url` allows
    # loopback while no token is configured — right for a callback someone
    # sets up locally, wrong for a URL that arrives as a tool argument.
    # Code lines only. Three times today a test matched the comment
    # explaining a fix and failed on the explanation of its own fix; the
    # prose here names the guard it rejects, on purpose.
    code = "\n".join(
        line for line in resolve.splitlines()
        if not line.strip().startswith("#")
    )
    assert "refuse_internal_url" in code
    assert "is_safe_callback_url" not in code


def test_the_template_catalog_checks_the_address_it_was_handed():
    """"fixed https catalog" was false twice over.

    `catalog_url()` reads an environment variable, both fetchers take a `url`
    argument, and `fetch_manifest` builds its target with `urljoin` from a
    field of the catalog it just downloaded — an absolute `manifest_file`
    replaces the base entirely, so the remote server picks the next
    destination.
    """
    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    module = root / "plugins" / "memory" / "hindsight" / "templates.py"
    if not module.is_file():
        pytest.skip("cette version de Hermes n'a pas ce plugin")

    source = module.read_text(encoding="utf-8")
    getter = source.split("def _get_json")[1].split("\ndef ")[0]
    assert "refuse_internal_url" in getter, (
        "le contrôle doit être au point de passage, pas chez les appelants"
    )
    # The suppression line itself, not the file: the comment explaining the
    # fix quotes the old claim, and a test that matched prose would fail on
    # the explanation of its own fix.
    suppressions = [
        line for line in source.splitlines() if "noqa: S310" in line
    ]
    assert suppressions
    assert not any("fixed https catalog" in line for line in suppressions), (
        "la justification de la suppression était fausse"
    )


def _hermes_package(dotted: str):
    """Import a module from the vendored tree the way Hermes imports it.

    As a package, not a file: these modules use relative imports, and a
    loader that reads the file alone fails on `from . import security` —
    which is how a source-reading test ends up standing in for a real one.
    """
    import importlib
    import sys

    from thot.fusion.locate import hermes_root

    root = hermes_root()
    if root is None:
        pytest.skip("Hermes n'est pas installé ici")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        return importlib.import_module(dotted)
    except Exception as exc:  # a tree that will not import is not this test
        pytest.skip(f"{dotted} n'est pas importable ici : {exc}")


def test_a2a_refuses_a_model_supplied_internal_url_when_run(monkeypatch):
    """Run the guard rather than read it.

    The previous version of this test asserted that a function was called,
    and passed on a version that accepted `http://127.0.0.1:8080` — because
    the function it named allows loopback while no token is configured.
    """
    tools = _hermes_package("plugins.platforms.a2a.tools")

    for url in ("http://127.0.0.1:8080", "http://localhost/x",
                "http://169.254.169.254/latest/"):
        assert tools._resolve_peer(url) is None, url

    kept = tools._resolve_peer("https://example.com")
    assert kept and kept["url"] == "https://example.com"


def test_the_template_catalog_refuses_an_internal_address_when_run():
    """Second-order: the remote catalog picks the next URL through urljoin."""
    templates = _hermes_package("plugins.memory.hindsight.templates")

    with pytest.raises(ValueError) as raised:
        templates._get_json("http://127.0.0.1:9/catalog.json")
    assert "refused template catalog" in str(raised.value)


def test_the_image_plugin_refuses_an_internal_source_when_run():
    plugin = _hermes_package("plugins.image_gen.openai")

    with pytest.raises(ValueError) as raised:
        plugin._load_image_bytes("http://169.254.169.254/latest/meta-data/")
    assert "refused image source" in str(raised.value)
