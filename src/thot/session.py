"""The interactive session: the thing that runs when you type `thot`.

One loop. Read a line, send it to the model with the tools, run whatever it
asks for, print what comes back. The repository briefing is built once at
startup and refreshed whenever a tool changes a file.
"""

from __future__ import annotations

from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from thot import __version__, agent_tools
from thot.agent_tools import ToolContext
from thot.llm.base import Message, Provider, ProviderError
from thot.llm.credentials import Config, build_provider, forget
from thot.recon import Recon, context_brief, sweep
from thot.ui import theme

HISTORY_PATH = Path.home() / ".thot" / "history"
MAX_TOOL_ROUNDS = 24

SYSTEM_PROMPT = """Tu es Thot, un assistant de développement qui travaille dans le \
terminal de l'utilisateur.

Ta particularité : tu connais déjà le dépôt. Une carte déterministe (AST, graphe \
d'appels, chemins de teinte) a été calculée avant cette conversation, et elle est \
résumée ci-dessous. Les outils `code_map`, `find_symbol`, `callers` et `audit` \
interrogent cette carte : leurs réponses sont exhaustives et ne coûtent rien. \
Utilise-les avant d'ouvrir des fichiers au hasard.

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
        self.messages: list[Message] = []
        self._prompt = PromptSession(history=self._history())

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

    def greet(self) -> None:
        theme.banner(self.config.label())
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
                line = self._prompt.prompt(ANSI("\x1b[38;5;179m   › \x1b[0m")).strip()
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

    def _turn(self) -> None:
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
                ("/audit", "relancer l'analyse et afficher les findings"),
                ("/scan", "recalculer la carte du dépôt"),
                ("/model", "changer de modèle"),
                ("/clear", "oublier la conversation en cours"),
                ("/quit", "quitter"),
            ):
                theme.console.print(theme.field(name, description))
            theme.console.print()
            return None

        if command == "audit":
            self._refresh()
            from thot.console import print_report
            from thot.pipeline import AuditResult

            result = AuditResult(
                findings=self.recon.findings,
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


def start(root: Path, config: Config) -> int:
    return Session(root=root, config=config).run()
