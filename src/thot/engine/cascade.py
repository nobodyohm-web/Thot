"""Thot running *on* Hermes and Prime — the half of the fusion that was missing.

Both agents were reachable from Thot in two roles already: contradictors for
`thot audit --deep`, and MCP clients consuming Thot's map. Neither of those is
Thot running on them. `Config.provider` accepted `claude-cli`, `claude`,
`openai`, `local`, `custom`, and the session was a single-model loop.

Two facts decide the design.

**They are one-shot.** `hermes -z` and `prime -p` answer once and forget:
`EngineCapabilities.stateful` is False for both, and it is honest. So the
conversation has to be held by somebody, and that somebody is Thot. This is
not a workaround for a limitation — it is the persistent memory and the long
context the program claims, doing the one job only it can do. Each turn
carries the thread, the repository map and the objective; each agent brings
its own tools, its own memory and its own credentials, and Thot never holds a
token for either.

**They are good at different things.** Prime runs a kernel and executes;
Hermes sustains a line of reasoning across a long context. So the turn goes
to whoever the instruction is for, and Thot says which — a routing decision
the user cannot see is a routing decision the user cannot correct.

The rule is deliberately deterministic. Asking a model which model should
answer costs a call and a wait before any work starts, on a judgement a verb
usually settles. **The first recognised verb wins**, which is what separates
"lance les tests" from "explique comment lancer les tests" — a rule that
scanned for any action word anywhere would run the tests nobody asked to run.
When no verb is recognised the turn goes to Hermes, because an instruction
that names no action is usually somebody carrying on a conversation, and
continuity is Hermes's half.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence

from thot.engine.base import AgentTask
from thot.llm.base import Usage


class NoAgents(RuntimeError):
    """Neither agent is installed — say what to do about it."""


class _Spoken(Protocol):
    role: str
    content: str


# Verbs that ask for something to happen. French first because that is what
# the user types; the English forms are here because half of any real prompt
# about code is in English anyway.
ACTS = frozenset({
    "lance", "lancer", "relance", "exécute", "execute", "exécuter", "run",
    "teste", "tester", "test", "installe", "installer", "install",
    "corrige", "corriger", "répare", "fix", "écris", "écrire", "write",
    "crée", "créer", "create", "modifie", "modifier", "édite", "edit",
    "ajoute", "ajouter", "add", "supprime", "supprimer", "retire", "delete",
    "remove", "renomme", "renommer", "rename", "refactorise", "refactor",
    "build", "compile", "compiler", "déploie", "deploy", "applique",
    "appliquer", "apply", "migre", "migrer", "formate", "format",
    "génère", "générer", "generate", "commit", "push", "patch",
    "vérifie", "vérifier", "valide", "valider", "mesure", "mesurer",
    "bench", "profile", "profiler", "nettoie", "clean",
})

# Verbs that ask for an answer rather than an act.
THINKS = frozenset({
    "explique", "expliquer", "explain", "analyse", "analyser", "analyze",
    "compare", "comparer", "décris", "décrire", "describe", "résume",
    "résumer", "summarize", "propose", "proposer", "suggest", "conçois",
    "concevoir", "design", "évalue", "évaluer", "evaluate", "review",
    "relis", "relire", "raisonne", "réfléchis", "pense", "penses",
    "recommande", "conseille", "advise", "décide", "decide", "juge",
    "pourquoi", "why", "comment", "how", "quoi", "what", "quel", "quelle",
    "combien", "où", "where", "qui", "who", "montre", "affiche", "show",
    "liste", "list", "cherche", "trouve", "find", "lis", "read",
})

# Politeness and pronouns the verb hides behind: "peux-tu lancer…",
# "est-ce que tu peux expliquer…". Skipped rather than matched, so the verb
# that follows is the one that decides.
_SKIP = frozenset({
    "peux", "peut", "pourrais", "stp", "svp",
    "tu", "je", "on", "il", "elle", "nous", "vous", "est", "ce", "que",
    "qu", "veux", "voudrais", "merci", "please", "can", "could", "you",
    "would", "will", "let", "s", "il-te-plaît", "maintenant", "now", "et",
    "puis", "alors", "donc", "ensuite", "aussi", "bien", "juste",
    "le", "la", "les", "moi", "toi", "ça", "ca", "me", "te", "y", "en",
})

# No hyphen in the class, deliberately. `corrige-le` has to yield `corrige`,
# and `peux-tu` has to yield `peux` — glued, the first is an unknown word and
# the turn goes to the wrong agent.
_WORD = re.compile(r"[a-zà-öø-ÿ0-9_]+", re.IGNORECASE)

# What a one-shot agent can be handed. Both engines refuse a prompt past
# 100 000 characters — `execve` fails with E2BIG well before that — and a
# truncated prompt that does not say it was truncated produces a confident
# answer about half a conversation.
THREAD_BUDGET = 60_000


@dataclass
class Turn:
    """What came back, and who it came from."""

    agent: str
    why: str
    text: str = ""
    error: str | None = None
    usage: Usage = field(default_factory=Usage)

    @property
    def ok(self) -> bool:
        return self.error is None


def _both(first: Usage, second: Usage) -> Usage:
    """Two attempts, one bill. A failed call is still a call."""
    return Usage(
        input_tokens=first.input_tokens + second.input_tokens,
        output_tokens=first.output_tokens + second.output_tokens,
    )


def _cause(error: str) -> str:
    """The half of an engine error worth putting in a one-line explanation.

    Provider errors carry a request id that means nothing to the person
    reading the line; the full text stays available on the failing Turn.
    """
    head = error.split(" [")[0].strip()
    return head if len(head) <= 70 else head[:67] + "…"


def transcript(history: Sequence[_Spoken], budget: int = THREAD_BUDGET) -> str:
    """The conversation, newest-first-truncated, labelled.

    Cut from the *old* end: a one-shot agent that loses the beginning of a
    long thread can still answer the question in front of it, and one that
    loses the end cannot. The cut is announced — a transcript silently
    missing its first half is how an agent answers confidently about a
    conversation it never saw.
    """
    spoken = [
        (message.role, (message.content or "").strip())
        for message in history
        if (message.content or "").strip() and message.role in ("user", "assistant")
    ]
    lines: list[str] = []
    total = 0
    dropped = 0
    for role, content in reversed(spoken):
        who = "Utilisateur" if role == "user" else "Toi"
        block = f"{who} : {content}"
        if total + len(block) > budget and lines:
            dropped = len(spoken) - len(lines)
            break
        lines.append(block)
        total += len(block)
    lines.reverse()
    if dropped:
        lines.insert(0, f"[… {dropped} tour(s) antérieur(s) tronqué(s) …]")
    return "\n\n".join(lines)


@dataclass
class Cascade:
    """Prime executes, Hermes reasons, Thot holds the thread."""

    root: Path
    members: dict[str, Any]
    forced: str = ""          # "hermes" | "prime" | "" for automatic
    counter: int = 0

    @property
    def names(self) -> list[str]:
        return [name for name in ("hermes", "prime") if name in self.members]

    def route(self, instruction: str) -> tuple[str, str]:
        """Who takes this turn, and the sentence that explains it."""
        if not self.members:
            raise NoAgents(
                "Ni Hermes ni Prime n'est installé, et Thot est leur fusion.\n"
                "   Hermes : `uv sync` à la racine du dépôt.\n"
                "   Prime  : cd prime && npm install && npm run build"
            )

        if self.forced:
            if self.forced in self.members:
                return self.forced, f"forcé sur {self.forced}"
            raise NoAgents(f"{self.forced} n'est pas installé.")

        if len(self.members) == 1:
            only = next(iter(self.members))
            return only, f"seul {only} est installé"

        for word in _WORD.findall(instruction.lower()):
            if word in _SKIP:
                continue
            if word in ACTS:
                return "prime", f"« {word} » demande d'agir — Prime exécute"
            if word in THINKS:
                return "hermes", f"« {word} » demande une réponse — Hermes raisonne"

        return "hermes", "aucun verbe reconnu — Hermes tient le fil"

    def _stand_in(self, who: str) -> str:
        """The other agent, when routing chose this one and there is another.

        Empty when the user named an agent. `build_cascade` states the rule
        this follows: refusing beats silently running on a different agent
        than the one asked for, because the session would then attribute its
        own history to the wrong one. An automatic route carries no such
        promise — it is Thot's guess, and a guess may be revised.
        """
        if self.forced:
            return ""
        for name in self.names:
            if name != who:
                return name
        return ""

    def turn(self, instruction: str, *, history: Sequence[_Spoken] = (),
             brief: str = "", tier: str = "standard") -> Turn:
        """One exchange, on whichever agent it belongs to.

        An agent that fails hands the turn to the other one. Measured, not
        supposed: with Anthropic answering `overloaded_error`, Prime failed
        twice in a row while Hermes answered the same question correctly —
        so every `ACTS` verb died and every `THINKS` verb worked, and the
        fusion looked like one broken half. `AgentResult.error` is the
        engine reporting it could not run at all; a model that ran and
        declined comes back as text. Retrying such a failure elsewhere is
        therefore free of the usual objection, and not retrying it wastes
        the entire point of having two agents.
        """
        who, why = self.route(instruction)
        self.counter += 1

        blocks = []
        if brief:
            blocks.append(brief)
        thread = transcript(history)
        if thread:
            blocks.append("Conversation en cours :\n\n" + thread)
        context = "\n\n".join(blocks)

        task = AgentTask(
            id=f"tour-{self.counter}",
            instructions=instruction,
            context=context,
            tier=tier,
        )
        result = self.members[who].run(task)
        if result.error is None:
            return Turn(agent=who, why=why, text=result.text or "",
                        error=None, usage=result.usage)

        stand_in = self._stand_in(who)
        if not stand_in:
            return Turn(agent=who, why=why, text=result.text or "",
                        error=result.error, usage=result.usage)

        relayed = self.members[stand_in].run(task)
        spent = _both(result.usage, relayed.usage)
        if relayed.error is None:
            return Turn(
                agent=stand_in,
                why=f"{why}, mais {who} n'a pas répondu "
                    f"({_cause(result.error)}) — {stand_in} prend le tour",
                text=relayed.text or "",
                error=None,
                usage=spent,
            )
        # Both down. Reporting one of the two would send the user looking at
        # the wrong agent for a failure that is upstream of both.
        return Turn(
            agent=who, why=why, text="",
            error=f"{who} : {result.error}\n   {stand_in} : {relayed.error}",
            usage=spent,
        )
