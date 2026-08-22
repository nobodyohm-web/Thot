"""Reaching Thot from a phone, and the fact that a phone can reach Thot.

Half these tests are about delivery. The other half are about the blast
radius of a bot token: what someone who steals one can make the auditor do.
"""

from __future__ import annotations

import json

import pytest

from thot.contracts import CodeRef, Confidence, Finding, Severity
from thot.gateway import config, render
from thot.gateway.base import Channel, Incoming, truncate
from thot.gateway.commands import Board, handle
from thot.gateway.platforms import Discord, Ntfy, Telegram, build


def _finding(rule="sink.os.system", severity=Severity.HIGH, line=9):
    return Finding(
        id=f"{rule}-{line}", rule=rule, severity=severity,
        confidence=Confidence.PLAUSIBLE,
        location=CodeRef(path="app/handlers.py", line=line, symbol="handle",
                         ast_hash="h"),
        failure_scenario="?host=;id — la valeur atteint os.system sans filtre",
    )


# -- configuration -----------------------------------------------------------


def test_the_config_file_holds_tokens_so_it_is_not_group_readable(isolated_home):
    config.upsert("telegram", {"token": "secret", "chat_id": "1"}, ("42",))
    path = config.config_file()

    assert path.stat().st_mode & 0o077 == 0, "0600 ou rien : ce fichier a un jeton"
    assert json.loads(path.read_text())["channels"][0]["allow"] == ["42"]


def test_the_environment_overrides_the_file_field_by_field(isolated_home, monkeypatch):
    config.upsert("telegram", {"token": "du-fichier", "chat_id": "1"})
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "de-l-environnement")

    channel = config.load()[0]
    assert channel.settings["token"] == "de-l-environnement"
    assert channel.settings["chat_id"] == "1", "le reste du fichier survit"


def test_an_allowlist_can_be_given_as_one_environment_variable(isolated_home,
                                                               monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_HOME_CHANNEL", "1")
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "alice, bob;carol")

    assert config.load()[0].allow == ("alice", "bob", "carol")


def test_a_send_only_platform_never_claims_it_can_be_commanded(isolated_home):
    """An allowlist is a permission, not a receiver.

    ntfy's `poll` returns an empty list for ever. Letting an allowlist make
    it `two_way` had `serve` announce it was listening on that channel — and
    suppress the warning that says no channel can hear anything at all.
    """
    config.upsert("ntfy", {"topic": "a"}, allow=("alice",))

    assert config.load()[0].two_way is False


def test_removing_a_channel_leaves_the_others(isolated_home):
    config.upsert("ntfy", {"topic": "a"})
    config.upsert("slack", {"webhook": "https://x"})

    assert config.remove("ntfy") is True
    assert [c.platform for c in config.load()] == ["slack"]
    assert config.remove("ntfy") is False


# -- the blast radius of a stolen token --------------------------------------


def test_a_channel_without_an_allowlist_cannot_be_commanded():
    """Hermes has an allow-all switch for development. This must not."""
    assert Channel("telegram", {"token": "t", "chat_id": "1"}).two_way is False
    assert Channel("telegram", {"token": "t"}, allow=("42",)).two_way is True


def test_the_allowlist_matches_exactly_and_never_on_emptiness():
    channel = Channel("telegram", {}, allow=("42",))

    assert channel.allows("42")
    assert not channel.allows("4")
    assert not channel.allows("")
    assert not channel.allows("420")


def test_an_unknown_verb_gets_the_help_never_an_interpretation():
    answer = handle("rm", "-rf /", board=Board())

    assert "Commande inconnue" in answer
    assert "n'exécute de code" in answer


def test_the_command_set_offers_no_way_to_run_anything():
    from thot.gateway.commands import HELP

    for forbidden in ("bash", "shell", "run_command", "write", "eval", "python"):
        assert forbidden not in HELP.lower()


def test_an_audit_can_only_target_a_registered_repository(isolated_home,
                                                          monkeypatch):
    """Otherwise a stolen token audits — and so reads — any path on the disk."""
    monkeypatch.setattr("thot.schedule.jobs.load", lambda: [])

    assert "Aucun audit programmé" in handle("audit", "/etc", board=Board())


# -- reports -----------------------------------------------------------------


def test_a_report_leads_with_the_count_then_stops_at_three():
    findings = [_finding(line=n) for n in range(1, 9)]
    text = render.report(findings, root="/home/dev/api", title="nuit")

    assert text.startswith("nuit — api")
    assert "8 finding(s)" in text
    assert text.count("sink.os.system") == 3
    assert "5 de plus" in text


def test_nothing_new_is_a_short_message_not_an_empty_one():
    assert "Rien de nouveau" in render.report([], root="/r")


def test_a_long_message_says_that_it_was_cut():
    cut = truncate("x" * 9000, 500)

    assert len(cut) <= 500
    assert "caractères de plus" in cut


def test_the_detail_of_a_finding_carries_its_scenario():
    text = render.detail(2, _finding())

    assert "app/handlers.py:9" in text
    assert "?host=;id" in text


# -- delivery ----------------------------------------------------------------


class _Response:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_a_dead_channel_costs_only_its_own_notification(monkeypatch):
    monkeypatch.setattr("httpx.post",
                        lambda *a, **k: _Response(500, text="boom"))
    delivery = Discord(webhook="https://example/hook").send("salut")

    assert delivery.ok is False
    assert "500" in delivery.detail
    assert "boom" in delivery.detail


def test_a_network_failure_is_a_sentence_not_an_exception(monkeypatch):
    import httpx

    def explode(*args, **kwargs):
        raise httpx.ConnectError("pas de route")

    monkeypatch.setattr("httpx.post", explode)
    delivery = Ntfy(topic="t").send("salut")

    assert delivery.ok is False
    assert "pas de route" in delivery.detail


def test_an_unconfigured_channel_says_what_is_missing():
    assert "token" in Telegram().send("x").detail
    assert "webhook" in Discord().send("x").detail
    assert "topic" in Ntfy().send("x").detail


def test_telegram_acknowledges_every_update_including_ignored_ones(monkeypatch):
    """An unacknowledged update is replayed forever."""
    payload = {
        "ok": True,
        "result": [
            {"update_id": 10, "message": {"text": "", "from": {"id": 1}}},
            {"update_id": 11, "message": {"text": "status",
                                          "from": {"id": 7, "username": "dev"},
                                          "chat": {"id": 99}}},
        ],
    }
    monkeypatch.setattr("httpx.get", lambda *a, **k: _Response(payload=payload))

    bot = Telegram(token="t", chat_id="1")
    messages = bot.poll()

    assert [m.text for m in messages] == ["status"]
    assert messages[0].sender == "7"
    assert messages[0].channel == "99"
    assert bot._offset == 12, "l'update vide doit être acquitté aussi"


def test_a_message_parses_into_a_verb_and_the_rest():
    assert Incoming("/audit nuit", "1").command() == ("audit", "nuit")
    assert Incoming("  STATUS  ", "1").command() == ("status", "")


def test_only_configured_channels_are_built(isolated_home):
    config.upsert("ntfy", {"topic": "t"})
    channel = config.load()[0]

    assert build(channel).configured() is True
    assert build(Channel("inconnu", {})) is None


# -- the notify plugin -------------------------------------------------------


def test_an_attended_audit_does_not_notify(monkeypatch):
    """The findings are already on screen; notifying trains you to mute."""
    from thot.plugins import discover, forget_plugins

    sent = []
    monkeypatch.setattr("thot.gateway.server.broadcast",
                        lambda text, **k: sent.append(text) or [])

    forget_plugins()
    plugin = [p for p in discover() if p.name == "gateway-notify"][0]
    plugin.callbacks["post_audit"](result=object(), root="/r")

    assert sent == []


def test_a_scheduled_audit_with_something_new_notifies(monkeypatch):
    from thot.plugins import discover, forget_plugins

    sent = []
    monkeypatch.setattr("thot.gateway.server.broadcast",
                        lambda text, **k: sent.append(text) or [])

    forget_plugins()
    plugin = [p for p in discover() if p.name == "gateway-notify"][0]
    plugin.callbacks["post_audit"](result=object(), root="/home/dev/api",
                                   new_findings=[_finding()])

    assert len(sent) == 1
    assert "Nouveau — api" in sent[0]
    assert "sink.os.system" in sent[0]


def test_a_scheduled_audit_with_nothing_new_stays_silent(monkeypatch):
    from thot.plugins import discover, forget_plugins

    sent = []
    monkeypatch.setattr("thot.gateway.server.broadcast",
                        lambda text, **k: sent.append(text) or [])

    forget_plugins()
    plugin = [p for p in discover() if p.name == "gateway-notify"][0]
    plugin.callbacks["post_audit"](result=object(), root="/r", new_findings=[])

    assert sent == []


# -- the loop ----------------------------------------------------------------


class _Fake:
    """A platform that yields a scripted message and records what it sent."""

    name = "telegram"

    def __init__(self, messages):
        self._messages = list(messages)
        self.sent = []

    def configured(self):
        return True

    def send(self, text, *, channel=""):
        from thot.gateway.base import Delivery

        self.sent.append(text)
        return Delivery(self.name, True)

    def poll(self):
        messages, self._messages = self._messages, []
        return messages


def test_an_unauthorised_sender_is_refused_before_anything_runs(isolated_home,
                                                               monkeypatch):
    from thot.gateway import server

    fake = _Fake([Incoming("audit", sender="999", sender_name="inconnu")])
    monkeypatch.setattr(server, "channels",
                        lambda: [Channel("telegram", {"token": "t"}, allow=("7",))])
    monkeypatch.setattr(server, "build", lambda channel: fake)

    ran = []
    monkeypatch.setattr("thot.gateway.commands.handle",
                        lambda *a, **k: ran.append(a) or "ne devrait pas arriver")

    assert server.serve(once=True) == 0
    assert ran == [], "une commande non autorisée ne doit jamais être exécutée"
    assert "Non autorisé" in fake.sent[0]


def test_an_authorised_sender_gets_their_answer(isolated_home, monkeypatch):
    from thot.gateway import server

    fake = _Fake([Incoming("help", sender="7", sender_name="dev")])
    monkeypatch.setattr(server, "channels",
                        lambda: [Channel("telegram", {"token": "t"}, allow=("7",))])
    monkeypatch.setattr(server, "build", lambda channel: fake)

    assert server.serve(once=True) == 0
    assert "commandes disponibles" in fake.sent[0]


def test_a_command_that_explodes_does_not_take_the_loop_down(isolated_home,
                                                             monkeypatch):
    from thot.gateway import server

    fake = _Fake([Incoming("status", sender="7")])
    monkeypatch.setattr(server, "channels",
                        lambda: [Channel("telegram", {"token": "t"}, allow=("7",))])
    monkeypatch.setattr(server, "build", lambda channel: fake)
    monkeypatch.setattr(server, "handle",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boum")))

    assert server.serve(once=True) == 0
    assert "boum" in fake.sent[0]


def test_serving_with_nothing_that_can_listen_says_so(isolated_home, monkeypatch):
    from thot.gateway import server

    monkeypatch.setattr(server, "channels",
                        lambda: [Channel("ntfy", {"topic": "t"})])
    assert server.serve(once=True) == 2

    monkeypatch.setattr(server, "channels", lambda: [])
    assert server.serve(once=True) == 2


def test_the_token_file_is_created_private_not_chmodded_afterwards(
    isolated_home, monkeypatch
):
    """0600 has to be true of the file's first byte, not of its last.

    Writing with the umask and chmod-ing next left the bot tokens and the
    SMTP password readable by every local account for the width of that
    window. Neutralising the chmod is how the test tells the two apart:
    the mode must already be right without it.
    """
    import os

    monkeypatch.setattr(os, "chmod", lambda *a, **kw: None)
    previous = os.umask(0o022)
    try:
        path = config.upsert("telegram", {"token": "secret", "chat_id": "1"})
    finally:
        os.umask(previous)

    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_the_phone_can_audit_a_whole_program_job(tmp_path, monkeypatch):
    """A job may target the fused program, whose `root` is a token.

    `Path("fusion")` is not a directory, so the one job most people register
    answered "that is not a folder" from a phone.
    """
    from thot.gateway.commands import Board, handle
    from thot.schedule.jobs import FUSION, Job
    from thot.scope.authorization import write_authorization

    first, second = tmp_path / "un", tmp_path / "deux"
    for root in (first, second):
        root.mkdir()
        (root / "app.py").write_text(
            "import os, sys\n\ndef run():\n    os.system('ls ' + sys.argv[1])\n"
        )
        write_authorization(root, owner="tester")

    monkeypatch.setattr(
        "thot.fusion.audit.parts", lambda: [("un", first), ("deux", second)]
    )
    monkeypatch.setattr(
        "thot.gateway.commands._jobs",
        lambda: [Job(name="tout", root=FUSION, deep=True)],
    )

    answer = handle("audit", "", board=Board(), author="dev")

    assert "n'est pas un dossier" not in answer
    assert "échoué" not in answer


# --- un identifiant collé avec une espace verrouille son propriétaire ------
#
# Le chemin des variables d'environnement nettoie déjà (`_split`). Le chemin
# JSON, non : `"allow": ["12345 "]` dans un `~/.thot/gateway.json` retouché à
# la main, ou un identifiant collé avec un retour à la ligne, refuse à jamais
# la personne qui vient de s'autoriser — et le message de refus lui dit
# d'ajouter l'identifiant qu'elle a déjà ajouté. L'échec est fermé, donc sûr,
# donc silencieux et indiagnosticable.


def test_a_pasted_identifier_with_spaces_still_matches(isolated_home):
    config.upsert("telegram", {"token": "t", "chat_id": "1"}, (" 12345\n",))

    channel = config.load()[0]

    assert channel.allow == ("12345",)
    assert channel.allows("12345")


def test_an_identifier_written_as_a_number_still_matches(isolated_home):
    config.upsert("telegram", {"token": "t", "chat_id": "1"}, (12345,))

    assert config.load()[0].allows("12345")


def test_a_padded_incoming_identifier_is_recognised(isolated_home):
    from thot.gateway.base import Channel

    assert Channel(platform="telegram", allow=("12345",)).allows(" 12345 ")


def test_an_empty_entry_never_authorises_anyone(isolated_home):
    from thot.gateway.base import Channel

    channel = Channel(platform="telegram", allow=("",))
    assert channel.allows("") is False
    assert channel.allows("   ") is False


def test_an_allowlist_of_nothing_is_not_a_channel_that_listens(isolated_home):
    """`two_way` reads `bool(self.allow)`, and [""] is truthy but authorises nobody.

    Announcing "à l'écoute" on a channel that will refuse every message is the
    same silence the send-only warning exists to prevent.
    """
    config.upsert("telegram", {"token": "t", "chat_id": "1"}, ("", "  "))

    assert config.load()[0].two_way is False


# --- le message poussé la nuit doit dire qu'un panel a jugé ----------------
#
# Ce que la boucle nocturne envoie est exactement le produit de la cascade :
# des confirmations et des réfutations contestées, `_is_news` ne retenant
# rien d'autre. Le message annonçait pourtant des sévérités seules — « 3
# finding(s) — 2 high · 1 medium » — sans un mot sur le fait que des agents
# avaient argumenté. C'est le seul endroit où l'utilisateur voit le travail
# du panel quand il ne regarde pas le terminal.


def _news(confidence):
    from thot.contracts import CodeRef, Confidence, Finding, Severity

    return Finding(
        id="n1", rule="sink.os.system", severity=Severity.HIGH,
        confidence=confidence,
        location=CodeRef(path="app.py", line=9, symbol="handle", ast_hash="h"),
        failure_scenario="argv atteint os.system",
    )


def test_the_pushed_message_names_the_engine_that_judged():
    from thot.contracts import Confidence
    from thot.gateway.render import report

    text = report([_news(Confidence.CONFIRMED)], root="/tmp/app",
                  title="Nouveau", engine="panel")

    assert "panel" in text
    assert "confirmé" in text


def test_a_deterministic_push_says_nothing_about_a_panel():
    from thot.contracts import Confidence
    from thot.gateway.render import report

    text = report([_news(Confidence.PLAUSIBLE)], root="/tmp/app",
                  title="Nouveau")

    assert "jugé par" not in text.lower(), text
