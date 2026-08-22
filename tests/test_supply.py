"""What a repository depends on, and what OSV.dev knows about it.

No network here: the client is exercised through a mock transport, so the
contract is under test rather than the weather.
"""

from __future__ import annotations

import json
import textwrap

import httpx
import pytest

from thot.contracts import Confidence, Severity
from thot.supply import audit_dependencies, discover
from thot.supply.discover import NPM, PYPI, Component
from thot.supply.osv import Advisory, OsvClient, severity_from


def _write(root, name: str, text: str):
    (root / name).write_text(textwrap.dedent(text), encoding="utf-8")


# -- finding the dependencies -------------------------------------------------


def test_only_pinned_versions_are_reported(tmp_path):
    """A range is not a version; OSV cannot answer one and neither will Thot."""
    _write(tmp_path, "requirements.txt", """\
        # un commentaire
        requests==2.19.1
        flask>=2.0
        urllib3==1.24.1  # avec un commentaire en fin de ligne
        """)

    found = discover(tmp_path)
    assert [c.label() for c in found] == ["requests==2.19.1", "urllib3==1.24.1"]
    assert found[0].source == "requirements.txt"
    assert found[0].line == 2, "la ligne doit pointer sur la déclaration"


def test_a_lockfile_wins_over_the_manifest_beside_it(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\nclick==8.0.0\n")
    _write(tmp_path, "uv.lock", """\
        [[package]]
        name = "requests"
        version = "2.32.3"
        """)

    versions = {c.name: c.version for c in discover(tmp_path)}
    assert versions["requests"] == "2.32.3", "le verrou fait foi"
    assert versions["click"] == "8.0.0", "ce que le verrou ignore reste lu"


def test_npm_lockfiles_are_read_in_both_layouts(tmp_path):
    _write(tmp_path, "package-lock.json", json.dumps({
        "packages": {
            "": {"name": "projet"},
            "node_modules/lodash": {"version": "4.17.11"},
        }
    }))
    found = discover(tmp_path)
    assert [(c.name, c.version, c.ecosystem) for c in found] == \
        [("lodash", "4.17.11", NPM)]

    (tmp_path / "package-lock.json").write_text(json.dumps({
        "dependencies": {"minimist": {"version": "1.2.0"}}
    }))
    assert [c.label() for c in discover(tmp_path)] == ["minimist@1.2.0"]


def test_yarn_and_pnpm_are_understood(tmp_path):
    _write(tmp_path, "yarn.lock", """\
        lodash@^4.17.0:
          version "4.17.11"
          resolved "https://registry.yarnpkg.com/lodash"
        """)
    assert [c.label() for c in discover(tmp_path)] == ["lodash@4.17.11"]

    (tmp_path / "yarn.lock").unlink()
    _write(tmp_path, "pnpm-lock.yaml", """\
        packages:
          /lodash@4.17.11:
            resolution: {integrity: sha512-x}
        """)
    assert [c.label() for c in discover(tmp_path)] == ["lodash@4.17.11"]


def test_package_json_contributes_only_exact_pins(tmp_path):
    _write(tmp_path, "package.json", json.dumps({
        "dependencies": {"lodash": "^4.17.0", "left-pad": "1.3.0"},
    }))
    assert [c.label() for c in discover(tmp_path)] == ["left-pad@1.3.0"]


def test_pyproject_pins_are_read_and_ranges_are_not(tmp_path):
    _write(tmp_path, "pyproject.toml", """\
        [project]
        name = "x"
        dependencies = ["httpx>=0.28", "pyyaml==5.1"]
        """)
    assert [c.label() for c in discover(tmp_path)] == ["pyyaml==5.1"]


def test_a_repository_with_nothing_pinned_is_not_an_error(tmp_path):
    assert discover(tmp_path) == []
    result = audit_dependencies(tmp_path)
    assert result.checked is True
    assert result.findings == []


def test_a_broken_lockfile_costs_that_file_only(tmp_path):
    _write(tmp_path, "uv.lock", "ceci n'est pas du toml [[[")
    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")
    assert [c.label() for c in discover(tmp_path)] == ["requests==2.19.1"]


# -- asking OSV ---------------------------------------------------------------


def _client(handler):
    return OsvClient(transport=httpx.MockTransport(handler))


def _component(name="requests", version="2.19.1"):
    return Component(name, version, PYPI, "requirements.txt", 1)


def test_a_batch_query_maps_answers_back_to_their_package():
    def handler(request):
        if request.url.path.endswith("/querybatch"):
            body = json.loads(request.content)
            assert body["queries"][0]["package"]["ecosystem"] == PYPI
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "GHSA-1"}]},
                {},
            ]})
        return httpx.Response(200, json={"id": "GHSA-1", "summary": "problème"})

    first, second = _component(), _component("click", "8.0.0")
    answers = _client(handler).query([first, second])

    assert answers == {first: ["GHSA-1"]}


def test_a_lookup_that_did_not_happen_is_not_a_clean_bill_of_health(tmp_path):
    """The distinction the whole result type exists for."""
    def refuse(request):
        raise httpx.ConnectError("injoignable")

    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")
    result = audit_dependencies(tmp_path, client=_client(refuse))

    assert result.checked is False
    assert result.findings == []
    assert "injoignable" in result.error
    assert "non vérifiées" in result.summary()


def test_details_are_fetched_once_and_then_cached():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={
            "id": "GHSA-1", "summary": "un problème",
            "affected": [{"ranges": [{"events": [{"fixed": "2.20.0"}]}]}],
            "database_specific": {"severity": "HIGH"},
        })

    client = _client(handler)
    first = client.details(["GHSA-1"])
    second = client.details(["GHSA-1", "GHSA-1"])

    assert len(calls) == 1, "un avis ne change pas d'une seconde à l'autre"
    assert first["GHSA-1"].severity == "HIGH"
    assert second["GHSA-1"].fixed == ("2.20.0",)


def test_an_advisory_with_no_detail_is_still_reported():
    def refuse(request):
        raise httpx.ConnectError("injoignable")

    found = _client(refuse).details(["GHSA-inconnu"])
    assert found["GHSA-inconnu"].id == "GHSA-inconnu"


def test_a_cvss_score_becomes_a_severity_word():
    assert severity_from({"severity": [{"score": "9.8"}]}) == "CRITICAL"
    assert severity_from({"severity": [{"score": "7.1"}]}) == "HIGH"
    assert severity_from({"severity": [{"score": "1.0"}]}) == "LOW"
    assert severity_from({}) == "UNKNOWN"
    # A CVSS vector string carries no number to read; do not invent one.
    assert severity_from({"severity": [{"score": "CVSS:3.1/AV:N"}]}) == "UNKNOWN"


def test_malware_is_recognised_by_id_and_by_alias():
    assert Advisory(id="MAL-2024-1").malware is True
    assert Advisory(id="GHSA-x", aliases=("MAL-2024-1",)).malware is True
    assert Advisory(id="GHSA-x").malware is False


# -- findings ------------------------------------------------------------------


def _audit(tmp_path, *, advisory: dict, requirement="requests==2.19.1\n"):
    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [
                {"id": advisory["id"]}]}]})
        return httpx.Response(200, json=advisory)

    _write(tmp_path, "requirements.txt", requirement)
    return audit_dependencies(tmp_path, client=_client(handler))


def test_a_vulnerable_pin_becomes_a_finding_that_names_the_fix(tmp_path):
    result = _audit(tmp_path, advisory={
        "id": "GHSA-1", "summary": "Credentials leaked on redirect",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"fixed": "2.20.0"}]}]}],
    })

    assert result.checked is True
    finding = result.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.rule == "supply.pypi"
    assert finding.location.path == "requirements.txt"
    assert "Corrigé en 2.20.0" in finding.failure_scenario
    assert "Atteignabilité" in finding.failure_scenario, (
        "il faut dire ce qui n'a pas été analysé"
    )


def test_a_dependency_finding_stays_plausible_because_reach_is_unknown(tmp_path):
    finding = _audit(tmp_path, advisory={"id": "GHSA-1"}).findings[0]
    assert finding.confidence is Confidence.PLAUSIBLE


def test_malware_is_critical_and_confirmed(tmp_path):
    """`MAL-*` means the package is the payload; reachability is not the question."""
    finding = _audit(tmp_path, advisory={
        "id": "MAL-2024-1", "summary": "Paquet malveillant",
        "database_specific": {"severity": "LOW"},
    }).findings[0]

    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert "MALVEILLANT" in finding.failure_scenario


def test_bumping_the_version_expires_the_verdict(tmp_path):
    """Identity carries the pinned version, like an AST hash carries a body."""
    advisory = {"id": "GHSA-1", "database_specific": {"severity": "HIGH"}}
    before = _audit(tmp_path, advisory=advisory).findings[0]
    after = _audit(tmp_path, advisory=advisory,
                   requirement="requests==2.20.0\n").findings[0]

    assert before.id != after.id
    assert before.location.ast_hash.startswith("2.19.1")


def test_two_advisories_on_one_package_are_two_findings(tmp_path):
    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [
                {"id": "GHSA-1"}, {"id": "GHSA-2"}]}]})
        return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})

    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")
    result = audit_dependencies(tmp_path, client=_client(handler))

    assert len(result.findings) == 2
    assert len({f.id for f in result.findings}) == 2


def test_findings_come_back_worst_first(tmp_path):
    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "faible"}]},
                {"vulns": [{"id": "grave"}]},
            ]})
        identifier = request.url.path.rsplit("/", 1)[-1]
        severity = "CRITICAL" if identifier == "grave" else "LOW"
        return httpx.Response(200, json={
            "id": identifier, "database_specific": {"severity": severity}})

    _write(tmp_path, "requirements.txt", "aaa==1.0\nzzz==1.0\n")
    result = audit_dependencies(tmp_path, client=_client(handler))

    assert [f.severity for f in result.findings] == [Severity.CRITICAL, Severity.LOW]


# -- the servers you actually execute ------------------------------------------


def test_an_mcp_declaration_yields_a_package_only_when_it_is_pinned():
    from thot.supply import from_mcp_command

    pinned = from_mcp_command("s", "npx", ["-y", "@scope/pkg@1.2.3"])
    assert (pinned.name, pinned.version, pinned.ecosystem) == \
        ("@scope/pkg", "1.2.3", NPM)
    assert pinned.source == "mcp:s"

    uv = from_mcp_command("s", "/opt/bin/uvx", ["outil==2.0.1"])
    assert (uv.name, uv.version, uv.ecosystem) == ("outil", "2.0.1", PYPI)

    # An audit that invents a version is worse than one that stays quiet.
    assert from_mcp_command("s", "npx", ["-y", "@scope/pkg"]) is None
    assert from_mcp_command("s", "docker", ["run", "image"]) is None
    assert from_mcp_command("s", "npx", []) is None


def test_a_malicious_mcp_server_is_reported_and_fails_the_command(monkeypatch,
                                                                  capsys):
    from thot import cli

    monkeypatch.setattr(
        "thot.llm.claude_cli.user_mcp_definitions",
        lambda root: {"piégé": {"command": "npx", "args": ["-y", "mal@1.0.0"]}},
    )

    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "MAL-2024-9"}]}]})
        return httpx.Response(200, json={"id": "MAL-2024-9",
                                         "summary": "Paquet malveillant"})

    monkeypatch.setattr("thot.supply.OsvClient",
                        lambda **k: OsvClient(transport=httpx.MockTransport(handler)))

    code = cli.main(["mcp", "check"])
    printed = capsys.readouterr().out

    assert code == cli.EXIT_FINDINGS
    assert "MALVEILLANT" in printed
    assert "MAL-2024-9" in printed


def test_unpinned_servers_are_named_rather_than_silently_skipped(monkeypatch,
                                                                 capsys):
    from thot import cli

    monkeypatch.setattr(
        "thot.llm.claude_cli.user_mcp_definitions",
        lambda root: {"flou": {"command": "npx", "args": ["-y", "truc"]}},
    )

    assert cli.main(["mcp", "check"]) == 0
    printed = capsys.readouterr().out
    assert "flou" in printed
    assert "épingler" in printed


# --- un manifeste imbriqué compte autant que celui de la racine ------------
#
# `discover` ne lisait que `root / nom`. Mesuré sur l'arbre livré : la racine
# de Thot annonçait « 254 dépendance(s), aucune vulnérabilité connue » tandis
# que `hermes/website/`, `hermes/scripts/whatsapp-bridge/` et
# `hermes/plugins/platforms/photon/sidecar/` portaient chacun leur propre
# `package-lock.json`, jamais lu. Dans un dépôt en monorepo — la forme
# ordinaire d'un projet JavaScript — la quasi-totalité des dépendances
# échappait à l'audit, sous un rapport qui sonnait complet.


def _lock(path: Path, packages: dict) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            f"node_modules/{name}": {"version": version}
            for name, version in packages.items()
        },
    }), encoding="utf-8")


def test_a_nested_lockfile_is_discovered(tmp_path):
    from thot.supply.discover import discover

    _lock(tmp_path / "package-lock.json", {"root-dep": "1.0.0"})
    _lock(tmp_path / "apps" / "desktop" / "package-lock.json",
          {"desktop-dep": "2.0.0"})

    names = {c.name for c in discover(tmp_path)}

    assert "root-dep" in names
    assert "desktop-dep" in names, "le manifeste imbriqué a été ignoré"


def test_a_vendored_tree_is_not_walked(tmp_path):
    from thot.supply.discover import discover

    _lock(tmp_path / "package-lock.json", {"root-dep": "1.0.0"})
    _lock(tmp_path / "node_modules" / "x" / "package-lock.json",
          {"vendored-dep": "9.9.9"})
    _lock(tmp_path / ".venv" / "package-lock.json", {"venv-dep": "9.9.9"})

    names = {c.name for c in discover(tmp_path)}

    assert "vendored-dep" not in names
    assert "venv-dep" not in names


def test_an_ignored_directory_is_left_out(tmp_path):
    from thot.supply.discover import discover

    # Un nom que la liste intégrée ne couvre pas. Avec `vendor/`, ce test
    # passait sans que `.thotignore` soit lu une seule fois — la mutation qui
    # neutralise la règle restait verte.
    (tmp_path / ".thotignore").write_text("legacy/\n", encoding="utf-8")
    _lock(tmp_path / "package-lock.json", {"root-dep": "1.0.0"})
    _lock(tmp_path / "legacy" / "package-lock.json", {"legacy-dep": "9.9.9"})

    names = {c.name for c in discover(tmp_path)}

    assert "root-dep" in names
    assert "legacy-dep" not in names


def test_the_same_package_pinned_twice_is_reported_once(tmp_path):
    from thot.supply.discover import discover

    _lock(tmp_path / "package-lock.json", {"shared": "1.0.0"})
    _lock(tmp_path / "apps" / "web" / "package-lock.json", {"shared": "1.0.0"})

    assert [c.name for c in discover(tmp_path)] == ["shared"]


def test_two_versions_of_one_package_are_both_kept(tmp_path):
    from thot.supply.discover import discover

    _lock(tmp_path / "package-lock.json", {"shared": "1.0.0"})
    _lock(tmp_path / "apps" / "web" / "package-lock.json", {"shared": "2.0.0"})

    versions = sorted(c.version for c in discover(tmp_path) if c.name == "shared")
    assert versions == ["1.0.0", "2.0.0"]
