"""The interactive session: the thing that runs when you type `thot`.

One loop. Read a line, send it to the model with the tools, run whatever it
asks for, print what comes back. The repository briefing is built once at
startup and refreshed whenever a tool changes a file.
"""

from __future__ import annotations

import sys
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from thot import __version__, agent_tools
from thot.agent_tools import ToolContext
from thot.contracts import Confidence
from thot.llm.base import Message, Provider, ProviderError
from thot.llm.claude_cli import ClaudeCli, Events
from thot.llm.credentials import Config, build_provider, forget
from thot.recon import Recon, context_brief, sweep
from thot.ui import theme

HISTORY_PATH = Path.home() / ".thot" / "history"
MAX_TOOL_ROUNDS = 24

CLI_BRIEF = """Tu travailles sous Thot, qui a déjà cartographié ce dépôt.

Les outils `mcp__thot__code_map`, `mcp__thot__find_symbol`, `mcp__thot__callers` \
et `mcp__thot__audit` répondent depuis un index AST et un graphe d'appels \
précalculés : leurs réponses sont exhaustives et instantanées.

`mcp__thot__skills` liste des méthodes éprouvées (débogage par cause racine, \
TDD, revue de code, planification, audit). Avant toute tâche non triviale, \
consulte-les et lis celle qui s'applique avec `mcp__thot__skill`. Elles \
coûtent une lecture et évitent des allers-retours.

Utilise-les EN PREMIER pour toute question de localisation ou de structure. \
Un `grep` ou un `Read` exploratoire est presque toujours inutile ici : le graphe \
sait déjà qui appelle quoi. N'ouvre un fichier que pour en lire le contenu réel, \
jamais pour le chercher.

Réponds en français, brièvement.

Carte du dépôt :
{brief}"""

SYSTEM_PROMPT = """Tu es Thot, un assistant de développement qui travaille dans le \
terminal de l'utilisateur.

Ta particularité : tu connais déjà le dépôt. Une carte déterministe (AST, graphe \
d'appels, chemins de teinte) a été calculée avant cette conversation, et elle est \
résumée ci-dessous. Les outils `code_map`, `find_symbol`, `callers` et `audit` \
interrogent cette carte : leurs réponses sont exhaustives et ne coûtent rien. \
Utilise-les avant d'ouvrir des fichiers au hasard.

Tu disposes aussi de méthodes écrites : `skills` les liste, `skill` en lit une \
en entier. Avant une tâche non triviale — un bug tenace, une revue, un plan, \
un audit — regarde s'il en existe une et suis-la.

Règles de travail :
- Agis. Si l'utilisateur demande une modification, fais-la avec les outils plutôt \
que de décrire ce qu'il faudrait faire.
- Lis un fichier avant de le modifier.
- Après une modification qui touche du code testé, propose de lancer les tests.
- Sois bref. Le terminal n'est pas un rapport : quelques phrases, pas de résumé \
de ce que tu viens de faire ligne par ligne.
- Réponds en français.

Contexte du dépôt :
{brief}"""


class Session:
    def __init__(self, root: Path, config: Config) -> None:
        self.root = root
        self.config = config
        self.recon: Recon = sweep(root)
        self.provider: Provider | None = None
        self.claude: ClaudeCli | None = (
            ClaudeCli(root=root, model=config.model)
            if config.provider == "claude-cli"
            else None
        )
        self.messages: list[Message] = []
        self._interactive = sys.stdin.isatty()
        self._prompt = (
            PromptSession(history=self._history()) if self._interactive else None
        )

    # -- setup -----------------------------------------------------------

    @staticmethod
    def _history() -> FileHistory:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        return FileHistory(str(HISTORY_PATH))

    def _tool_context(self) -> ToolContext:
        return ToolContext(
            root=self.root,
            recon=self.recon,
            confirm=self._confirm,
            refresh=self._refresh,
        )

    def _refresh(self) -> None:
        """Recompute the map after the tools changed something on disk."""
        self.recon = sweep(self.root)

    def _system(self) -> str:
        return SYSTEM_PROMPT.format(brief=context_brief(self.recon))

    # -- display ---------------------------------------------------------

    def _model_label(self) -> str:
        """What to show in the header — as precise as currently known."""
        if self.claude is not None:
            from thot.llm.claude_cli import configured_model

            model = self.claude.active_model or self.claude.model or configured_model()
            return f"{model or 'modèle par défaut'} · ton compte Claude"
        return f"{self.config.model} · {self.config.provider}"

    def greet(self) -> None:
        theme.banner(self._model_label())
        recon = self.recon

        if recon.is_empty:
            theme.console.print(theme.field("dossier", str(self.root)))
            theme.console.print()
            theme.hint("Rien ici pour l'instant. Dis-moi ce qu'on construit.")
        else:
            theme.console.print(theme.field("dossier", str(self.root)))
            languages = " · ".join(
                f"{count} {name}" for name, count in recon.manifest.languages.items()
            )
            entries = len(recon.manifest.entrypoints)
            theme.console.print(
                theme.field("code", f"{languages} · {entries} points d'entrée")
            )
            if recon.branch:
                state = "modifié" if recon.dirty else "propre"
                theme.console.print(theme.field("git", f"{recon.branch} · {state}"))
            if recon.findings:
                counts: dict[str, int] = {}
                for finding in recon.findings:
                    key = finding.severity.value
                    counts[key] = counts.get(key, 0) + 1
                summary = " · ".join(f"{n} {k}" for k, n in counts.items())
                theme.console.print(theme.field("audit", summary))
            theme.console.print()
            theme.hint(f"Reconnaissance en {recon.elapsed:.2f} s. Prêt.")

        theme.console.print()

    @staticmethod
    def _whoami() -> str:
        import getpass

        try:
            return getpass.getuser()
        except Exception:
            return ""

    def _verdict(self, argument: str) -> None:
        """`/verdict 2 refute l'entrée est une constante`.

        Indexed on the last report rather than on a finding id: nobody types a
        sixteen-character hash, and a decision nobody makes is a decision the
        next audit asks for again.
        """
        from thot.memory import Decision, Verdict
        from thot.memory.sqlite import SqliteMemory

        parts = argument.split(maxsplit=2)
        findings = self.recon.findings
        if len(parts) < 2 or not parts[0].isdigit():
            theme.warn("Usage : /verdict <n° du finding> refute|accept|fixed <raison>")
            theme.hint("Le n° est celui de la dernière liste — `/audit` pour la revoir.")
            return None

        index = int(parts[0])
        if not 1 <= index <= len(findings):
            theme.warn(f"Il n'y a que {len(findings)} finding(s).")
            return None

        decision = Decision.parse(parts[1])
        if decision is None:
            theme.warn(f"« {parts[1]} » n'est pas une décision.")
            theme.hint("refute (faux positif) · accept (risque assumé) · fixed (corrigé)")
            return None

        reason = parts[2] if len(parts) > 2 else ""
        if not reason:
            theme.warn("Une raison est obligatoire — elle sera relue dans six mois.")
            return None

        finding = findings[index - 1]
        memory = SqliteMemory.open()
        try:
            memory.remember(Verdict.of(finding, decision, reason, self._whoami()))
        finally:
            memory.close()

        theme.ok(f"{finding.rule} à {finding.location} — {decision.value}")
        theme.hint("Retenu tant que ce code ne change pas. `thot verdicts` pour revoir.")
        theme.console.print()
        self._refresh()
        return None

    def _deep_analyse(self, findings: list) -> list:
        """Spend the model on the worst candidates, then try to refute them.

        Returns the findings untouched when no engine is reachable: a session
        that loses its audit because a CLI is missing is worse than one that
        shows the deterministic result and says why.
        """
        from thot.analysis.probe import DEFAULT_LIMIT, analyse, select_for_analysis
        from thot.engine.factory import NoEngine, build_engine

        try:
            engine = build_engine(self.root, self.config)
        except NoEngine as exc:
            theme.warn(str(exc))
            return findings

        selected = select_for_analysis(findings, DEFAULT_LIMIT)
        if not selected:
            theme.hint("Aucun candidat à analyser.")
            return findings

        label = (
            f"{len(selected)} candidat(s) — analyse puis réfutation "
            f"via {engine.capabilities.name}…"
        )
        with theme.console.status(f"   [dim]{label}[/dim]", spinner="dots"):
            analysed = analyse(self.root, findings, engine, limit=DEFAULT_LIMIT)

        confirmed = sum(1 for f in analysed if f.confidence is Confidence.CONFIRMED)
        refuted = sum(1 for f in analysed if f.confidence is Confidence.REFUTED)
        theme.ok(f"{confirmed} confirmé(s), {refuted} réfuté(s)")
        theme.console.print()
        return analysed

    def _confirm(self, action: str, detail: str) -> bool:
        theme.console.print()
        body = detail if len(detail) < 1500 else detail[:1500] + "\n…"
        theme.console.print(
            Panel(
                Syntax(body, "diff" if body.startswith(("-", "+")) else "text",
                       theme="ansi_dark", word_wrap=True),
                title=Text(action, style=theme.ACCENT),
                border_style=theme.LAPIS,
                padding=(0, 1),
            )
        )
        answer = input("   valider ? [o/N] ").strip().lower()
        theme.console.print()
        return answer in {"o", "oui", "y", "yes"}

    @staticmethod
    def _tool_line(name: str, arguments: dict) -> Text:
        hint = ""
        for key in ("path", "name", "symbol", "command", "pattern"):
            if key in arguments and arguments[key]:
                hint = str(arguments[key])
                break
        text = Text("   ")
        text.append("⟩ ", style=theme.LAPIS)
        text.append(name, style=theme.ACCENT)
        if hint:
            text.append(f"  {hint[:80]}", style=theme.INK)
        return text

    # -- the loop --------------------------------------------------------

    def run(self) -> int:
        self.greet()
        while True:
            try:
                line = self._read_line()
            except (EOFError, KeyboardInterrupt):
                theme.console.print()
                theme.hint("À bientôt.")
                return 0

            if not line:
                continue
            if line.startswith("/"):
                if self._command(line) is False:
                    return 0
                continue

            self.messages.append(Message(role="user", content=line))
            try:
                self._turn()
            except ProviderError as exc:
                theme.console.print()
                theme.error(str(exc))
                theme.console.print()
            except KeyboardInterrupt:
                theme.console.print()
                theme.hint("Interrompu.")
                theme.console.print()

    def _read_line(self) -> str:
        """Read one instruction. Falls back to plain input when piped."""
        if self._prompt is not None:
            return self._prompt.prompt(ANSI("\x1b[38;5;179m   › \x1b[0m")).strip()
        theme.console.print(f"   [{theme.ACCENT}]›[/] ", end="")
        return input().strip()

    def _turn(self) -> None:
        if self.claude is not None:
            return self._turn_via_cli()
        if self.provider is None:
            self.provider = build_provider(self.config)

        for _ in range(MAX_TOOL_ROUNDS):
            theme.console.print()
            streamed = _Streamer()
            reply = self.provider.complete(
                system=self._system(),
                messages=self.messages,
                tools=agent_tools.SPECS,
                on_text=streamed.write,
            )
            streamed.close()
            self.messages.append(reply.message)

            if not reply.message.tool_calls:
                theme.console.print()
                return

            context = self._tool_context()
            for call in reply.message.tool_calls:
                theme.console.print(self._tool_line(call.name, call.arguments))
                result = agent_tools.dispatch(context, call.name, call.arguments)
                self.messages.append(
                    Message(role="tool", content=result, tool_call_id=call.id)
                )
                if call.name in agent_tools.MUTATING:
                    context = self._tool_context()

        theme.warn("Trop d'appels d'outils enchaînés — tour interrompu.")

    def _turn_via_cli(self) -> None:
        """Delegate the turn to the official CLI, rendering its event stream.

        The CLI owns the conversation, so Thot keeps no message history in this
        mode — `--resume` on the same session id is what carries the thread.
        """
        assert self.claude is not None
        prompt = self.messages[-1].content
        streamed = _Streamer()

        theme.console.print()
        events = Events(
            on_text=streamed.write,
            on_tool=lambda name, args: self._show_tool(streamed, name, args),
            on_error=lambda message: theme.error(message),
        )
        try:
            answer = self.claude.send(
                prompt,
                brief=CLI_BRIEF.format(brief=context_brief(self.recon)),
                events=events,
            )
        finally:
            streamed.close()

        self.messages.append(Message(role="assistant", content=answer))
        self._refresh()  # the CLI may have edited files
        theme.console.print()

    def _show_tool(self, streamed: "_Streamer", name: str, arguments: dict) -> None:
        streamed.close()
        pretty = name.replace("mcp__thot__", "")
        theme.console.print(self._tool_line(pretty, arguments))

    # -- slash commands --------------------------------------------------

    def _command(self, line: str) -> bool | None:
        command, _, argument = line[1:].partition(" ")
        command = command.lower()

        if command in {"q", "quit", "exit"}:
            theme.hint("À bientôt.")
            return False

        if command in {"h", "help", "?"}:
            theme.console.print()
            for name, description in (
                ("/status", "sur quoi tu tournes, et où"),
            ("/skills", "les méthodes disponibles"),
            ("/plugins", "les extensions chargées"),
            ("/verdict", "écarter ou accepter un finding : /verdict 2 refute raison"),
            ("/audit", "relancer l'analyse et afficher les findings"),
            ("/audit deep", "faire analyser puis réfuter les candidats par le modèle"),
                ("/scan", "recalculer la carte du dépôt"),
                ("/model", "changer de modèle"),
                ("/clear", "oublier la conversation en cours"),
                ("/quit", "quitter"),
            ):
                theme.console.print(theme.field(name, description))
            theme.console.print()
            return None

        if command == "status":
            theme.console.print()
            theme.console.print(theme.field("modèle", self._model_label()))
            theme.console.print(theme.field("dossier", str(self.root)))
            if self.claude is not None:
                theme.console.print(
                    theme.field("session", self.claude.session_id[:8])
                )
                theme.console.print(
                    theme.field("écriture", "automatique (mode compte)")
                )
            else:
                theme.console.print(
                    theme.field("écriture", "sur confirmation")
                )
            theme.console.print(theme.field("outils", "carte AST + graphe d'appels"))
            from thot.plugins import discover as discover_plugins
            from thot.skills import discover as discover_skills

            plugins = discover_plugins(self.root)
            broken = sum(1 for p in plugins if not p.ok)
            suffix = f" ({broken} en erreur)" if broken else ""
            theme.console.print(
                theme.field("skills", f"{len(discover_skills(self.root))} méthodes")
            )
            theme.console.print(
                theme.field("plugins", f"{len(plugins)} chargé(s){suffix}")
            )
            if self.claude is not None:
                from thot.llm.claude_cli import user_mcp_servers

                servers = user_mcp_servers(self.root)
                theme.console.print(
                    theme.field("mcp", ", ".join(("thot",) + servers))
                )
            theme.console.print()
            theme.hint("`/model` pour changer, `thot logout` pour tout oublier.")
            theme.console.print()
            return None

        if command == "plugins":
            from thot.plugins import discover

            loaded = discover(self.root)
            theme.console.print()
            if not loaded:
                theme.hint("Aucun plugin.")
            for plugin in loaded:
                detail = plugin.error or " ".join(plugin.description.split())
                if len(detail) > 48:
                    detail = detail[:48].rsplit(" ", 1)[0] + "…"
                mark = "" if plugin.ok else "▲ "
                theme.console.print(theme.entry(plugin.name, mark + detail, width=26))
            theme.console.print()
            theme.hint("~/.thot/plugins/<nom>/ pour en ajouter un.")
            theme.console.print()
            return None

        if command == "verdict":
            return self._verdict(argument)

        if command == "skills":
            from thot.skills import discover

            available = discover(self.root)
            theme.console.print()
            if not available:
                theme.hint("Aucun skill.")
            grouped: dict[str, list] = {}
            for item in available:
                grouped.setdefault(item.category or "général", []).append(item)
            for category in sorted(grouped):
                theme.console.print(f"   [dim]{category}[/dim]")
                for item in grouped[category]:
                    detail = " ".join(item.description.split())
                    if len(detail) > 48:
                        detail = detail[:48].rsplit(" ", 1)[0] + "…"
                    theme.console.print(theme.entry(item.name, detail, width=26))
                theme.console.print()
            theme.console.print()
            theme.hint("Le modèle les lit lui-même avec l'outil `skill`.")
            theme.console.print()
            return None

        if command == "audit":
            self._refresh()
            from thot.console import print_report
            from thot.pipeline import AuditResult

            findings = self.recon.findings
            if argument.strip().lower() in {"deep", "profond", "--deep"}:
                findings = self._deep_analyse(findings)

            result = AuditResult(
                findings=findings,
                manifest=self.recon.manifest,
                elapsed=self.recon.elapsed,
            )
            print_report(result)
            theme.console.print()
            return None

        if command == "scan":
            self._refresh()
            theme.ok(
                f"{self.recon.file_count} fichiers · "
                f"{len(self.recon.symbols)} symboles · "
                f"{len(self.recon.findings)} findings"
            )
            theme.console.print()
            return None

        if command == "clear":
            self.messages.clear()
            theme.ok("Conversation oubliée.")
            theme.console.print()
            return None

        if command == "model":
            from thot.onboarding import first_run

            config = first_run()
            if config:
                from thot.llm.credentials import save_config

                save_config(config)
                self.config = config
                self.provider = None
                self.claude = (
                    ClaudeCli(root=self.root, model=config.model)
                    if config.provider == "claude-cli"
                    else None
                )
                theme.ok(f"Modèle : {config.label()}")
            theme.console.print()
            return None

        if command == "logout":
            forget()
            theme.ok("Identifiants oubliés. Relance Thot pour reconfigurer.")
            return False

        theme.warn(f"Commande inconnue : /{command} — /help pour la liste.")
        theme.console.print()
        return None


class _Streamer:
    """Writes model text as it arrives, indented like the rest of the UI."""

    def __init__(self) -> None:
        self._started = False

    def write(self, chunk: str) -> None:
        if not self._started:
            theme.console.file.write("   ")
            self._started = True
        theme.console.file.write(chunk.replace("\n", "\n   "))
        theme.console.file.flush()

    def close(self) -> None:
        if self._started:
            theme.console.file.write("\n")
            theme.console.file.flush()
            self._started = False


def start(root: Path, config: Config) -> int:
    return Session(root=root, config=config).run()
