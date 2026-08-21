"""The interactive session: the thing that runs when you type `thot`.

One loop. Read a line, send it to the model with the tools, run whatever it
asks for, print what comes back. The repository briefing is built once at
startup and refreshed whenever a tool changes a file.
"""

from __future__ import annotations

import sqlite3
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
from thot.paths import history_file
from thot.recon import Recon, context_brief, sweep
from thot.state import SessionStore
from thot import toolsets
from thot.ui import theme

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
    def __init__(self, root: Path, config: Config,
                 store: SessionStore | None = None,
                 toolset: str = "") -> None:
        self.root = root
        self.config = config
        self.toolset = (toolset or toolsets.DEFAULT).lower()
        self.recon: Recon = sweep(root)
        self.provider: Provider | None = None
        self.claude: ClaudeCli | None = (
            ClaudeCli(root=root, model=config.model,
                      denied=toolsets.denied_cli_tools(self.toolset))
            if config.provider == "claude-cli"
            else None
        )
        self.messages: list[Message] = []
        self.carry = ""  # a summary handed forward across a /compact
        self.sandbox = self._open_sandbox()
        self.kernel = None      # opened on first use: starting one costs a beat
        self.harness = self._open_harness()
        self.store, self.session_id = self._open_state(store)
        self._interactive = sys.stdin.isatty()
        self._prompt = (
            PromptSession(history=self._history()) if self._interactive else None
        )

    # -- persistent state -------------------------------------------------

    def _open_state(self, store: SessionStore | None) -> tuple[SessionStore | None, str]:
        """Open the session log. A store that will not open costs history, not the session."""
        try:
            store = store or SessionStore.open()
            session_id = store.start(self.root, model=self._model_label())
            if self.claude is not None:
                store.link_cli(session_id, self.claude.session_id)
            return store, session_id
        except (sqlite3.Error, OSError):
            return None, ""

    def _record(self, role: str, content: str, *, tool_name: str = "") -> None:
        """Write one turn down. Never let the log break the conversation."""
        if not (self.store and self.session_id and content.strip()):
            return
        try:
            self.store.append(self.session_id, role, content, tool_name=tool_name)
        except (sqlite3.Error, OSError, KeyError):
            pass

    def _close_kernel(self) -> None:
        if self.kernel is not None:
            self.kernel.stop()
            self.kernel = None

    def _close_state(self) -> None:
        """Close the session — or drop it, if nothing was ever said.

        Thot opens a session at startup so the first word is already being
        recorded. Launching it to run `/status` and quitting would otherwise
        leave an empty row in the history for every glance at the tool.
        """
        if not (self.store and self.session_id):
            return
        try:
            info = self.store.info(self.session_id)
            if info is not None and info.message_count == 0:
                self.store.forget(self.session_id)
            else:
                self.store.end(self.session_id)
        except (sqlite3.Error, OSError):
            pass

    # -- setup -----------------------------------------------------------

    @staticmethod
    def _history() -> FileHistory:
        path = history_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        return FileHistory(str(path))

    def _open_sandbox(self):
        """The configured sandbox, or the host when none is asked for.

        A misconfigured sandbox must not stop the session from opening —
        but it must not silently become the host either, so the failure is
        printed and `/sandbox` shows the truth.
        """
        from thot.sandbox import SandboxError, build_sandbox

        try:
            return build_sandbox(self.root)
        except SandboxError as exc:
            theme.warn(f"Bac à sable indisponible : {exc}")
            theme.hint("Les commandes tourneront sous ton compte.")
            return None

    def _open_harness(self):
        """What was learned about this repository, in earlier sessions."""
        from thot.harness import Harness

        try:
            return Harness.open(self.root)
        except OSError:
            return None

    def _open_kernel(self):
        """Start the Python namespace, once, on first use.

        It is given the engine so `rlm()` can delegate, the harness so a
        cell can write down what it learned, and the sandbox so the
        namespace lands inside the container when there is one.
        """
        from thot.engine.factory import NoEngine, build_engine
        from thot.kernel import Kernel, KernelError

        if self.kernel is not None and self.kernel.running:
            return self.kernel

        try:
            engine = build_engine(self.root)
        except NoEngine:
            engine = None  # rlm() will say so rather than fail obscurely

        kernel = Kernel(root=self.root, engine=engine, harness=self.harness,
                        sandbox=self.sandbox)
        try:
            kernel.start()
        except KernelError as exc:
            theme.error(str(exc))
            return None
        self.kernel = kernel
        warning = kernel.warning()
        if warning:
            theme.console.print()
            theme.warn(warning)
        return kernel

    def _tool_context(self) -> ToolContext:
        return ToolContext(
            root=self.root,
            recon=self.recon,
            confirm=self._confirm,
            refresh=self._refresh,
            sandbox=self.sandbox,
            kernel=self.kernel,
        )

    def _refresh(self) -> None:
        """Recompute the map after the tools changed something on disk."""
        self.recon = sweep(self.root)

    def _system(self) -> str:
        return SYSTEM_PROMPT.format(brief=self._brief())

    def _brief(self) -> str:
        """The repository map, and the objective if one is being pursued.

        Prime Agent's point about goals: an agent asked to keep going until
        something is true needs the "something" somewhere other than the
        conversation it is about to compact away.
        """
        blocks = []
        goal = self._goal()
        if goal is not None:
            blocks.append(goal.brief())
        if self.harness is not None:
            learned = self.harness.brief()
            if learned:
                blocks.append(learned)
        blocks.append(context_brief(self.recon))
        return "\n\n".join(blocks)

    def _goal(self):
        if self.store is None:
            return None
        try:
            return self.store.goal(self.root)
        except (sqlite3.Error, OSError):
            return None

    def _charge(self, input_tokens: int, output_tokens: int) -> None:
        """Record what the turn cost, against the session and the goal."""
        if self.store is not None and self.session_id:
            try:
                self.store.charge(self.session_id, input_tokens, output_tokens)
            except (sqlite3.Error, OSError):
                pass
        self._charge_goal(input_tokens + output_tokens)

    def _charge_goal(self, tokens: int) -> None:
        """Bill the turn, and say so the moment the budget runs out."""
        goal = self._goal()
        if goal is None or self.store is None or not goal.live:
            return
        try:
            updated = self.store.charge_goal(goal.id, tokens)
        except (sqlite3.Error, OSError):
            return
        if updated is not None and updated.status == "budget_limited" \
                and goal.status != "budget_limited":
            theme.console.print()
            theme.warn(f"Budget de l'objectif épuisé — {updated.progress()}")
            theme.hint("`/goal budget <n>` pour continuer, `/goal done` pour clore.")
            theme.console.print()

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

        self._warn_about_refused_skills()
        theme.console.print()

    def _warn_about_refused_skills(self) -> None:
        """Say out loud when this repository tried to supply a skill.

        Silently dropping it would be safe and useless: the user needs to
        know the repository they are auditing tried to write part of the
        briefing, because that is itself a finding.
        """
        from thot.skills.loader import discover_report

        refused = discover_report(self.root)[1]
        if not refused:
            return
        theme.console.print()
        theme.warn(
            f"{len(refused)} skill(s) fourni(s) par ce dépôt ont été refusés — "
            f"ils seraient passés au modèle comme instructions."
        )
        for item in refused:
            theme.console.print(theme.entry(item.name, item.summary()[:70], width=20))

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
        from thot.memory import Decision, Verdict, build_memory

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
        verdict = Verdict.of(finding, decision, reason, self._whoami())
        memory = build_memory(self.root)
        try:
            memory.remember(verdict)
        finally:
            getattr(memory, "close", lambda: None)()

        from thot.plugins import notify_verdict

        notify_verdict(verdict, self.root)
        self._record("verdict", f"{finding.rule} {finding.location} → "
                                f"{decision.value} : {reason}")

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
        kept = self._remember_refutations(analysed, engine)
        if kept:
            theme.hint(
                f"{kept} réfutation(s) mémorisée(s) — le prochain audit ne les "
                "repaiera pas."
            )
        theme.console.print()
        return analysed

    def _remember_refutations(self, findings: list, engine) -> int:
        """Write down what the refutation pass concluded.

        `recon` already reads the memory at every sweep, so without this the
        session only ever read it: minutes of model time refuting the same
        findings, thrown away the moment the session ended. `thot audit --deep`
        has always recorded them; the interactive path has to as well, or the
        two disagree about what Thot knows.
        """
        from thot.memory import build_memory
        from thot.memory.base import record_verdicts

        try:
            memory = build_memory(self.root)
        except Exception as exc:  # a memory that will not open costs nothing else
            theme.warn(f"Décisions non mémorisées : {exc}")
            return 0
        try:
            return record_verdicts(findings, memory, author=engine.capabilities.name)
        except Exception as exc:
            theme.warn(f"Décisions non mémorisées : {exc}")
            return 0
        finally:
            getattr(memory, "close", lambda: None)()

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
                self._close_kernel()
                self._close_state()
                return 0

            if not line:
                continue
            spoken = line
            if line.startswith("/"):
                outcome = self._command(line)
                if outcome is False:
                    self._close_kernel()
                    self._close_state()
                    return 0
                if not isinstance(outcome, str):
                    continue
                # A custom command expands into a prompt; what gets logged is
                # what the user typed, so the history stays readable.
                line = outcome

            self.messages.append(Message(role="user", content=line))
            self._record("user", spoken)
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
                tools=toolsets.select(agent_tools.SPECS, self.toolset),
                on_text=streamed.write,
            )
            streamed.close()
            self.messages.append(reply.message)
            self._charge(reply.usage.input_tokens, reply.usage.output_tokens)

            if not reply.message.tool_calls:
                theme.console.print()
                self._record("assistant", reply.message.content or "")
                return

            if any(call.name == "python" for call in reply.message.tool_calls):
                self._open_kernel()
            context = self._tool_context()
            allowed = set(toolsets.resolve(self.toolset))
            for call in reply.message.tool_calls:
                theme.console.print(self._tool_line(call.name, call.arguments))
                # A model can ask for a tool it was not offered, so the
                # posture holds at the dispatch and not only at the menu.
                # A name that is not a tool at all is a different mistake
                # and must keep saying so.
                if call.name in agent_tools.NAMES and call.name not in allowed:
                    result = (f"L'outil `{call.name}` est désactivé : session "
                              f"en mode {self.toolset}.")
                else:
                    result = agent_tools.dispatch(context, call.name,
                                                  call.arguments)
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
        if self.carry:
            # A compacted thread starts empty on the CLI side; the summary
            # rides in with the first question so nothing is re-derived.
            prompt = f"{self.carry}\n\n---\n\n{prompt}"
            self.carry = ""
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
                brief=CLI_BRIEF.format(brief=self._brief()),
                events=events,
            )
        finally:
            streamed.close()

        self.messages.append(Message(role="assistant", content=answer))
        self._record("assistant", answer)
        # The CLI reports one figure for the turn; attribute it to input,
        # which is where all but a rounding error of it actually goes.
        self._charge(self.claude.last_tokens, 0)
        self._refresh()  # the CLI may have edited files
        theme.console.print()

    def _show_tool(self, streamed: "_Streamer", name: str, arguments: dict) -> None:
        streamed.close()
        pretty = name.replace("mcp__thot__", "")
        theme.console.print(self._tool_line(pretty, arguments))

    # -- slash commands --------------------------------------------------

    def _command(self, line: str) -> bool | str | None:
        """Run a built-in. A string back is a custom command's expanded prompt."""
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
                ("/py", "exécuter du Python dans un noyau persistant : /py <code>"),
                ("/harness", "ce que Thot a retenu de ce dépôt"),
                ("/cost", "ce que cette session a coûté"),
                ("/context", "ce qui remplit la fenêtre de contexte"),
                ("/tools", "ce que le modèle peut faire : /tools lecture|complet|carte"),
                ("/deps", "vérifier les dépendances contre OSV.dev"),
                ("/sandbox", "où tournent les commandes : /sandbox docker|local"),
                ("/goal", "fixer un objectif suivi : /goal <texte> [--budget N]"),
                ("/mcp", "les serveurs MCP connectés, et le catalogue"),
                ("/sessions", "les sessions précédentes sur ce dépôt"),
                ("/resume", "reprendre une session : /resume <id> (défaut : la dernière)"),
                ("/search", "chercher dans tout ce que Thot a déjà dit ou trouvé"),
                ("/compact", "résumer la session et repartir avec le contexte vidé"),
                ("/export", "écrire la session en JSON : /export chemin.json"),
                ("/scan", "recalculer la carte du dépôt"),
                ("/model", "changer de modèle"),
                ("/clear", "oublier la conversation en cours"),
                ("/quit", "quitter"),
            ):
                theme.console.print(theme.field(name, description))

            from thot.commands import discover as discover_commands

            custom = discover_commands(self.root)
            if custom:
                theme.console.print()
                theme.hint("Commandes de ce dépôt et des tiennes :")
                for item in custom:
                    theme.console.print(theme.field(item.usage(), item.description))
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
            theme.console.print(
                theme.field("outils", f"{self.toolset} — "
                                      f"{toolsets.describe(self.toolset)}")
            )
            goal = self._goal()
            if goal is not None:
                theme.console.print(
                    theme.field("objectif", f"{goal.objective[:44]} · {goal.progress()}")
                )
            if self.store is not None:
                stats = self.store.stats()
                theme.console.print(
                    theme.field("journal", f"{self.session_id[:8]} · "
                                f"{stats['sessions']} sessions, "
                                f"{stats['messages']} messages, "
                                f"recherche {stats['search']}")
                )
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

        if command in {"py", "python", "noyau"}:
            return self._python(argument)

        if command in {"harness", "acquis"}:
            return self._harness_command(argument)

        if command in {"cost", "coût", "cout"}:
            return self._cost()

        if command in {"context", "contexte"}:
            return self._context()

        if command in {"tools", "outils"}:
            return self._toolset(argument)

        if command in {"deps", "dépendances", "dependances"}:
            return self._deps()

        if command in {"sandbox", "bac"}:
            return self._sandbox(argument)

        if command in {"goal", "objectif"}:
            return self._goal_command(argument)

        if command == "mcp":
            return self._mcp(argument)

        if command in {"sessions", "historique"}:
            return self._sessions(argument)

        if command in {"resume", "reprendre"}:
            return self._resume(argument)

        if command in {"search", "cherche", "rechercher"}:
            return self._search(argument)

        if command in {"compact", "compacter"}:
            return self._compact(argument)

        if command == "export":
            return self._export(argument)

        if command == "import":
            return self._import(argument)

        if command in {"forget", "oublier"}:
            return self._forget(argument)

        if command == "skills":
            from thot.skills.loader import discover_report

            available, refused = discover_report(self.root)
            query = argument.strip()
            matched = [s for s in available if s.matches(query)] if query else []

            theme.console.print()
            if not available:
                theme.hint("Aucun skill.")
            elif not query:
                # Ninety descriptions is a wall, not a list. Names by
                # category, and a hint on how to narrow it.
                grouped: dict[str, list] = {}
                for item in available:
                    grouped.setdefault(item.category or "général", []).append(item)
                for category in sorted(grouped):
                    names = ", ".join(sorted(s.name for s in grouped[category]))
                    theme.console.print(theme.entry(category, names, width=24))
                theme.console.print()
                theme.hint(f"{len(available)} méthodes · `/skills <mot>` pour "
                           f"les détails, `thot skills install <nom>` pour en "
                           f"activer une autre.")
            elif not matched:
                theme.hint(f"Rien pour « {query} ».")
                from thot.skills.loader import optional

                spare = [s.name for s in optional() if s.matches(query)]
                if spare:
                    theme.hint(f"Dans la bibliothèque optionnelle : "
                               f"{', '.join(spare[:6])}")
                    theme.hint("`thot skills install <nom>` pour l'activer.")
            else:
                for item in matched[:20]:
                    detail = " ".join(item.description.split())
                    if len(detail) > 48:
                        detail = detail[:48].rsplit(" ", 1)[0] + "…"
                    theme.console.print(theme.entry(item.name, detail, width=26))
                if len(matched) > 20:
                    theme.hint(f"… {len(matched) - 20} autres.")
            theme.console.print()
            if refused:
                theme.warn(f"{len(refused)} refusé(s) par le garde :")
                for item in refused:
                    theme.console.print(theme.entry(item.name, item.summary()[:70],
                                                    width=20))
                theme.console.print()
            theme.hint("Le modèle les lit lui-même avec l'outil `skill`. "
                       "`thot skills` en dehors de la session.")
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
            self._record_audit(findings)
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
                    ClaudeCli(root=self.root, model=config.model,
                              denied=toolsets.denied_cli_tools(self.toolset))
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

        custom = self._custom_command(command)
        if custom is not None:
            return custom.render(argument)

        theme.warn(f"Commande inconnue : /{command} — /help pour la liste.")
        theme.console.print()
        return None

    def _custom_command(self, name: str):
        from thot.commands import discover

        for command in discover(self.root):
            if command.name == name:
                return command
        return None


    def _record_audit(self, findings) -> None:
        """Write the findings into the session log so `/search` reaches them.

        A finding you half-remember from last week is worth as much as one
        found today, and only if you can get back to it.
        """
        if not (self.store and self.session_id and findings):
            return
        lines = [
            f"{f.severity.value.upper():<8} {f.rule}  "
            f"{f.location.path}:{f.location.line}"
            for f in findings[:40]
        ]
        extra = f"\n… et {len(findings) - 40} autres" if len(findings) > 40 else ""
        try:
            self.store.note(
                self.session_id,
                f"audit · {len(findings)} findings\n" + "\n".join(lines) + extra,
            )
        except (sqlite3.Error, OSError, KeyError):
            pass

    def _goal_command(self, argument: str) -> None:
        """`/goal <objectif> [--budget N]`, `/goal done`, `/goal pause`, `/goal budget N`."""
        if not self._need_store():
            return None

        words = argument.split()
        verb = words[0].lower() if words else ""
        goal = self._goal()

        if not words or verb in {"status", "état"}:
            theme.console.print()
            if goal is None:
                theme.hint("Aucun objectif en cours.")
                theme.hint("`/goal auditer le parseur jusqu'à zéro HIGH --budget 200000`")
            else:
                theme.console.print(theme.field("objectif", goal.objective))
                theme.console.print(theme.field("état", goal.status))
                theme.console.print(theme.field("coût", goal.progress()))
            theme.console.print()
            return None

        if verb in {"done", "fini", "complete"}:
            if goal is None:
                theme.hint("Aucun objectif en cours.")
            else:
                self.store.finish_goal(goal.id, "complete")
                theme.ok(f"Objectif atteint — {goal.progress()}")
                self._record("goal", f"objectif atteint : {goal.objective}")
            theme.console.print()
            return None

        if verb in {"stop", "abandon", "abandonne"}:
            if goal is not None:
                self.store.finish_goal(goal.id, "abandoned", note=" ".join(words[1:]))
                theme.ok("Objectif abandonné.")
            theme.console.print()
            return None

        if verb == "pause":
            if goal is not None:
                self.store.pause_goal(goal.id, paused=goal.status != "paused")
                theme.ok("Objectif " + ("repris." if goal.status == "paused"
                                        else "mis en pause."))
            theme.console.print()
            return None

        if verb == "budget":
            if goal is None:
                theme.warn("Aucun objectif à financer.")
            elif len(words) < 2 or not words[1].isdigit():
                theme.hint("Usage : /goal budget <jetons>")
            else:
                updated = self.store.raise_goal_budget(goal.id, int(words[1]))
                theme.ok(f"Budget porté à {updated.token_budget} jetons "
                         f"({updated.remaining} restants).")
            theme.console.print()
            return None

        objective, budget = _split_budget(argument)
        try:
            created = self.store.set_goal(self.root, objective, token_budget=budget)
        except ValueError as exc:
            theme.warn(str(exc))
            theme.console.print()
            return None

        theme.console.print()
        theme.ok(f"Objectif fixé — {created.objective}")
        if created.token_budget:
            theme.hint(f"Budget : {created.token_budget} jetons.")
        theme.hint("Il sera rappelé au modèle à chaque tour, y compris après /compact.")
        self._record("goal", f"objectif fixé : {created.objective}")
        theme.console.print()
        return None

    def _python(self, argument: str) -> None:
        """`/py <code>` — one cell in the session's kernel."""
        from thot.kernel.api import HELP

        code = argument.strip()
        if not code:
            kernel = self.kernel
            theme.console.print()
            if kernel is None or not kernel.running:
                theme.hint("Noyau fermé — il s'ouvre au premier `/py <code>`.")
            else:
                theme.console.print(theme.field("noyau", kernel.describe()))
            theme.console.print()
            theme.console.print(HELP)
            theme.console.print()
            return None

        kernel = self._open_kernel()
        if kernel is None:
            theme.console.print()
            return None

        outcome = kernel.execute(code)
        theme.console.print()
        theme.console.print(outcome.render())
        if outcome.calls:
            theme.hint(f"{len(outcome.calls)} appel(s) délégué(s) — "
                       f"{kernel.calls_made}/{kernel.max_calls} au total.")
        theme.console.print()
        self._record("python", f"{code}\n---\n{outcome.render()[:1500]}")
        self._refresh()
        return None

    def _harness_command(self, argument: str) -> None:
        """What Thot has learned about this repository, and how to add to it."""
        if self.harness is None:
            theme.warn("Aucun magasin d'acquis pour ce dépôt.")
            theme.console.print()
            return None

        verb, _, rest = argument.strip().partition(" ")
        verb = verb.lower()

        if verb in {"oublie", "forget", "rm"} and rest.strip():
            done = self.harness.forget(rest.strip())
            theme.ok("Oublié." if done else f"Aucun acquis {rest.strip()}.")
            theme.console.print()
            return None

        if verb in {"note", "retiens", "add"} and rest.strip():
            title, _, content = rest.partition(":")
            if not content.strip():
                theme.hint("Usage : /harness note <titre> : <ce qu'il faut retenir>")
                theme.console.print()
                return None
            try:
                entry = self.harness.remember(title=title, content=content,
                                              source=self._whoami())
            except ValueError as exc:
                theme.warn(str(exc))
                theme.console.print()
                return None
            theme.ok(f"Retenu ({entry.id}) — rappelé à chaque session.")
            theme.console.print()
            return None

        entries = self.harness.all()
        theme.console.print()
        if not entries:
            theme.hint("Rien de retenu sur ce dépôt.")
            theme.hint("`/harness note <titre> : <fait>` pour commencer.")
        for entry in entries:
            scope = "" if entry.scope == "local" else " ·global"
            theme.console.print(
                theme.entry(entry.id, f"{entry.title}{scope} — {entry.content[:60]}",
                            width=14)
            )
        theme.console.print()
        theme.hint("`.thot/harness.json` — versionne-le pour le partager.")
        theme.console.print()
        return None

    def _cost(self) -> None:
        if not self._need_store():
            return None
        here = self.store.usage(self.session_id)
        repo = self.store.usage_across(self.root)
        everywhere = self.store.usage_across()

        theme.console.print()
        theme.console.print(theme.field("session", here.describe()))
        theme.console.print(theme.field("ce dépôt", repo.describe()))
        theme.console.print(theme.field("en tout", everywhere.describe()))
        goal = self._goal()
        if goal is not None:
            theme.console.print(theme.field("objectif", goal.progress()))
        theme.console.print()
        theme.hint("Estimations : ce que le fournisseur a rapporté, pas une facture.")
        theme.console.print()
        return None

    def _context(self) -> None:
        """What is filling the window, worst first."""
        from thot.state import compaction, context_breakdown

        goal = self._goal()
        slices = context_breakdown(
            brief=self._brief(),
            goal=goal.brief() if goal else "",
            messages=self.messages,
        )
        total = sum(s.tokens for s in slices)

        theme.console.print()
        if not total:
            theme.hint("Contexte vide — la conversation vient de commencer.")
            theme.console.print()
            return None

        for item in slices:
            share = f"{100 * item.tokens // total:>3} %" if total else "  0 %"
            detail = f"{item.tokens:>6} jetons  {share}"
            if item.detail:
                detail += f"   {item.detail}"
            theme.console.print(theme.entry(item.label, detail, width=22))

        theme.console.print()
        proposal = compaction.plan(self.messages)
        theme.console.print(theme.field("total", f"~{total} jetons estimés"))
        theme.console.print(theme.field("compactage", proposal.describe()))
        theme.console.print()
        return None

    def _toolset(self, argument: str) -> None:
        wanted = argument.strip().lower()
        theme.console.print()
        if not wanted:
            for name, description in toolsets.DESCRIPTIONS.items():
                mark = "▸ " if name == self.toolset else "  "
                theme.console.print(theme.entry(mark + name, description,
                                                width=12))
            theme.console.print()
            return None
        try:
            toolsets.resolve(wanted)
        except KeyError as exc:
            theme.warn(str(exc))
            theme.console.print()
            return None
        self.toolset = wanted
        if self.claude is not None:
            # The posture has to reach the official CLI too, or it stops
            # meaning anything in account mode.
            self.claude.denied = toolsets.denied_cli_tools(wanted)
        theme.ok(f"{wanted} — {toolsets.describe(wanted)}")
        theme.console.print()
        return None

    def _deps(self) -> None:
        """The one audit surface that needs the network, asked for explicitly."""
        from thot.supply import audit_dependencies

        theme.console.print()
        theme.hint("Interrogation d'OSV.dev…")
        result = audit_dependencies(self.root)

        if not result.checked:
            theme.error(f"Dépendances non vérifiées : {result.error}")
            theme.hint("Rien n'est affirmé sur ces paquets.")
            theme.console.print()
            return None

        theme.ok(result.summary())
        for finding in result.findings[:12]:
            label = ("MALVEILLANT" if finding.confidence.value == "confirmed"
                     else finding.severity.value.upper())
            theme.console.print(
                theme.entry(label, f"{finding.provenance['paquet']}  "
                                   f"{finding.provenance['avis']}", width=13)
            )
        if len(result.findings) > 12:
            theme.hint(f"… {len(result.findings) - 12} de plus — `thot deps`.")
        if result.findings:
            self._record_audit(result.findings)
        theme.console.print()
        return None

    def _sandbox(self, argument: str) -> None:
        """Show or change where the model's commands run."""
        from thot.sandbox import SandboxError, build_sandbox, load_config, save_config

        wanted = argument.strip().lower()
        theme.console.print()

        if wanted:
            config = load_config()
            config["kind"] = wanted
            try:
                sandbox = build_sandbox(self.root, config=config)
            except SandboxError as exc:
                theme.error(str(exc))
                theme.hint("Rien n'a changé : les commandes continuent de "
                           "tourner là où elles tournaient.")
                theme.console.print()
                return None
            save_config(config)
            self.sandbox = sandbox
            theme.ok(f"{sandbox.name} — {sandbox.describe()}")
            theme.console.print()
            return None

        current = self.sandbox
        if current is None:
            try:
                current = build_sandbox(self.root)
            except SandboxError as exc:
                theme.error(str(exc))
                theme.console.print()
                return None
        theme.console.print(theme.field("bac à sable", current.name))
        theme.console.print(theme.field("isolation", current.describe()))
        if current.name == "local":
            theme.hint("`/sandbox docker` pour exécuter le code audité dans un "
                       "conteneur sans réseau.")
        theme.console.print()
        return None

    def _mcp(self, argument: str) -> None:
        """What is connected, and what the catalogue offers."""
        from thot.mcp import catalog, find, install, installed

        action, _, name = argument.strip().partition(" ")
        if action in {"add", "ajoute"} and name:
            server = find(name)
            if server is None:
                theme.warn(f"« {name} » n'est pas au catalogue.")
                theme.console.print()
                return None
            done, message = install(server)
            theme.console.print()
            (theme.ok if done else theme.error)(message)
            theme.console.print()
            return None

        connected = set(installed(self.root))
        entries = catalog()

        theme.console.print()
        theme.console.print(theme.field("actifs", ", ".join(sorted({"thot", *connected}))))
        theme.console.print()
        for server in entries:
            mark = "✓ " if server.name in connected else "  "
            theme.console.print(
                theme.entry(mark + server.name, server.summary(), width=26)
            )
        theme.console.print()
        theme.hint("`/mcp add <nom>` pour en connecter un.")
        theme.console.print()
        return None

    # -- session history --------------------------------------------------

    def _need_store(self) -> bool:
        if self.store is None:
            theme.warn("Le journal des sessions n'a pas pu s'ouvrir.")
            theme.console.print()
            return False
        return True

    def _sessions(self, argument: str) -> None:
        """What was worked on here before, most recent first."""
        if not self._need_store():
            return None
        everywhere = argument.strip().lower() in {"all", "tout", "--all"}
        found = self.store.sessions(None if everywhere else self.root, limit=20)

        theme.console.print()
        if not found:
            theme.hint("Aucune session enregistrée.")
            theme.console.print()
            return None

        for info in found:
            mark = "▸ " if info.id == self.session_id else "  "
            title = info.title or "(sans titre)"
            if len(title) > 46:
                title = title[:46].rsplit(" ", 1)[0] + "…"
            detail = f"{title}   {info.message_count} msg"
            if everywhere:
                detail += f" · {Path(info.root).name}"
            theme.console.print(theme.entry(mark + info.id[:8], detail, width=14))
        theme.console.print()
        theme.hint("`/resume <id>` pour en reprendre une.")
        theme.console.print()
        return None

    def _resume(self, argument: str) -> None:
        """Reopen a previous session — its transcript, and its live context."""
        if not self._need_store():
            return None

        wanted = argument.strip()
        if wanted:
            resolved = self.store.resolve(wanted)
            if resolved is None:
                theme.warn(f"Aucune session ne commence par « {wanted} ».")
                theme.console.print()
                return None
        else:
            candidates = [
                s for s in self.store.sessions(self.root, limit=5)
                if s.id != self.session_id and s.message_count
            ]
            if not candidates:
                theme.hint("Aucune session précédente sur ce dépôt.")
                theme.console.print()
                return None
            resolved = candidates[0].id

        info = self.store.info(resolved)
        if info is None:
            theme.warn("Session introuvable.")
            theme.console.print()
            return None

        turns = self.store.turns(resolved, roles=("user", "assistant", "summary"))
        self.messages = [
            Message(role="user" if turn.role != "assistant" else "assistant",
                    content=turn.content)
            for turn in turns
        ]
        # The empty session opened at startup would otherwise litter the log.
        if self.store and self.session_id and self.session_id != resolved:
            current = self.store.info(self.session_id)
            if current is not None and current.message_count == 0:
                self.store.forget(self.session_id)

        self.session_id = resolved
        self.store.reopen(resolved)

        restored = ""
        if self.claude is not None and info.cli_session_id:
            self.claude.resume(info.cli_session_id)
            restored = " · fil du CLI restauré"

        theme.console.print()
        theme.ok(f"Session {resolved[:8]} reprise — {len(turns)} messages{restored}")
        if info.title:
            theme.hint(info.title)
        theme.console.print()
        return None

    def _search(self, argument: str) -> None:
        """Find a moment again: what was said, and what was found."""
        if not self._need_store():
            return None
        query = argument.strip()
        if not query:
            theme.hint("Usage : /search <mots>")
            theme.console.print()
            return None

        hits = self.store.find(query, limit=15)
        theme.console.print()
        if not hits:
            theme.hint(f"Rien pour « {query} ».")
            theme.console.print()
            return None

        from thot.state.search import CLOSE, OPEN

        for hit in hits:
            text = Text("   ")
            text.append(f"{hit.session_id[:8]} ", style=theme.LAPIS)
            text.append(f"{hit.role:<9} ", style="dim")
            for index, chunk in enumerate(hit.snippet.replace(CLOSE, OPEN).split(OPEN)):
                clean = " ".join(chunk.split())
                if clean:
                    text.append(clean, style=theme.ACCENT if index % 2 else theme.INK)
                    text.append(" ")
            theme.console.print(text)
        theme.console.print()
        theme.hint(f"{len(hits)} résultat(s) · `/resume <id>` pour y retourner.")
        theme.console.print()
        return None

    def _compact(self, argument: str) -> None:
        """Summarise the middle, keep the beginning and the end verbatim.

        Hermes Agent's compression strategy, ported: the opening frames the
        task and the closing exchanges *are* the task, so neither is
        paraphrased. Only the middle is, and only as much of it as the
        budget requires.

        The stored session is still branched, so the whole conversation
        survives on disk: compacting costs context, never evidence.
        """
        if not self._need_store():
            return None

        from thot.state import compaction

        manual = argument.strip()
        proposal = compaction.plan(self.messages)

        if not manual and not proposal.worth_doing:
            theme.console.print()
            theme.hint(f"Rien à compacter — ~{proposal.before} jetons, "
                       f"sous le seuil.")
            theme.console.print()
            return None

        summary = manual or self._summarise(proposal)
        if not summary:
            theme.warn("Rien à résumer pour l'instant.")
            theme.console.print()
            return None

        child = self.store.branch(self.session_id, summary)
        self.session_id = child

        if manual and not proposal.worth_doing:
            kept = [Message(role="user",
                            content=f"{compaction.MARKER} :\n{summary}")]
        else:
            kept = compaction.apply(
                self.messages, proposal, summary,
                make_message=lambda role, content: Message(role=role,
                                                           content=content),
            )

        if self.claude is not None:
            # The CLI owns its own context, so compacting there means a new
            # thread; the summary and the tail ride in with the next prompt.
            self.claude.forget_thread()
            self.store.link_cli(child, self.claude.session_id)
            self.carry = self._carry_text(kept)
            self.messages = []
        else:
            self.messages = kept

        theme.console.print()
        theme.ok(f"Session compactée → {child[:8]}")
        theme.hint(proposal.describe() if proposal.worth_doing
                   else "résumé fourni à la main")
        theme.console.print()
        return None

    @staticmethod
    def _carry_text(messages) -> str:
        """What a fresh CLI thread is told about the one it replaces."""
        lines = []
        for message in messages:
            content = (message.content or "").strip()
            if content:
                lines.append(f"[{message.role}] {content}")
        return "\n\n".join(lines)

    def _summarise(self, proposal=None) -> str:
        """Summarise the span being dropped — not the whole conversation.

        Summarising everything is what made `/compact` lose the answer you
        were about to ask a follow-up question about.
        """
        from thot.state import compaction

        if proposal is not None and proposal.worth_doing:
            material = compaction.excerpt(self.messages, proposal.start,
                                          proposal.end)
        else:
            material = compaction.excerpt(self.messages, 0, len(self.messages))
        if not material.strip():
            return ""

        instruction = (
            "Résume ce passage d'une session de travail en 10 lignes maximum : "
            "ce qui a été cherché, ce qui a été trouvé, ce qui reste à faire. "
            "Pas de préambule.\n\n---\n\n" + material
        )
        try:
            if self.claude is not None:
                return self.claude.send(instruction).strip()
            if self.provider is None:
                self.provider = build_provider(self.config)
            reply = self.provider.complete(
                system="Tu résumes une session de travail.",
                messages=[Message(role="user", content=instruction)],
                tools=(),
            )
            return (reply.message.content or "").strip()
        except (ProviderError, OSError):
            asked = [m.content for m in self.messages
                     if m.role == "user" and m.content]
            return "Questions posées :\n" + "\n".join(f"- {a}" for a in asked[-10:])

    def _export(self, argument: str) -> None:
        if not self._need_store():
            return None
        from thot.state import write_export

        target = Path(argument.strip() or f"thot-session-{self.session_id[:8]}.json")
        try:
            written = write_export(self.store, self.session_id, target)
        except (OSError, KeyError) as exc:
            theme.error(str(exc))
            theme.console.print()
            return None
        theme.console.print()
        theme.ok(f"Session écrite dans {written}")
        theme.console.print()
        return None

    def _import(self, argument: str) -> None:
        if not self._need_store():
            return None
        from thot.state import read_import

        source = argument.strip()
        if not source:
            theme.hint("Usage : /import <fichier.json>")
            theme.console.print()
            return None
        try:
            created = read_import(self.store, Path(source), root=self.root)
        except (OSError, ValueError) as exc:
            theme.error(str(exc))
            theme.console.print()
            return None
        theme.console.print()
        theme.ok(f"{len(created)} session(s) importée(s) — `/resume {created[-1][:8]}`")
        theme.console.print()
        return None

    def _forget(self, argument: str) -> None:
        if not self._need_store():
            return None
        wanted = argument.strip()
        if not wanted:
            theme.hint("Usage : /forget <id>")
            theme.console.print()
            return None
        resolved = self.store.resolve(wanted)
        if resolved is None:
            theme.warn(f"Aucune session ne commence par « {wanted} ».")
            theme.console.print()
            return None
        if resolved == self.session_id:
            theme.warn("C'est la session en cours : `/clear` pour la vider.")
            theme.console.print()
            return None
        self.store.forget(resolved)
        theme.ok(f"Session {resolved[:8]} oubliée.")
        theme.console.print()
        return None


def _split_budget(argument: str) -> tuple[str, int | None]:
    """Pull `--budget N` out of the objective, wherever the user put it."""
    words = argument.split()
    budget: int | None = None
    kept: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in {"--budget", "-b"} and index + 1 < len(words) \
                and words[index + 1].isdigit():
            budget = int(words[index + 1])
            index += 2
            continue
        if word.startswith("--budget=") and word.split("=", 1)[1].isdigit():
            budget = int(word.split("=", 1)[1])
            index += 1
            continue
        kept.append(word)
        index += 1
    return " ".join(kept), budget


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


def start(root: Path, config: Config, *, toolset: str = "") -> int:
    return Session(root=root, config=config, toolset=toolset).run()
