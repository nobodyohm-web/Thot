"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from thot import __version__
from thot.contracts import Severity
from thot.schedule.jobs import SCHEDULES
from thot.analysis.probe import DEFAULT_LIMIT
from thot.errors import AuthorizationError, ThotError
from thot.gateway.config import PLATFORMS as GATEWAY_PLATFORMS

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNAUTHORIZED = 3
EXIT_ERROR = 4

# Ascending order: `--fail-on medium` also trips on high and critical.
_SEVERITY_RANK = [
    Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
]



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thot",
        description="Audit de code adossé à des preuves. Analyse déterministe : "
        "aucun appel modèle, aucun réseau.",
    )
    parser.add_argument("--version", action="version", version=f"thot {__version__}")
    parser.add_argument(
        "--tools", choices=["complet", "lecture", "carte"], default="",
        help="Ce que le modèle peut faire dans la session (défaut : complet)",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("login", help="Choisir ou changer le modèle connecté")
    subparsers.add_parser("logout", help="Oublier le modèle connecté")

    # The two other programs in this repository. REMAINDER, because their
    # command lines are theirs: parsing them here would mean maintaining a
    # second, worse copy of two CLIs that already work.
    hermes_cmd = subparsers.add_parser(
        "hermes", help="Lancer Hermes Agent (arguments transmis tels quels)"
    )
    hermes_cmd.add_argument("arguments", nargs=argparse.REMAINDER)

    prime_cmd = subparsers.add_parser(
        "prime", help="Lancer Prime Agent (arguments transmis tels quels)"
    )
    prime_cmd.add_argument("arguments", nargs=argparse.REMAINDER)

    fusion = subparsers.add_parser(
        "fusion", help="L'état des trois programmes, et leur branchement"
    )
    fusion_sub = fusion.add_subparsers(dest="action")
    fusion_sub.add_parser("status", help="Ce qui est présent, prêt, et branché")
    fusion_wire = fusion_sub.add_parser(
        "wire", help="Donner la carte de Thot à Hermes et à Prime, via MCP"
    )
    fusion_wire.add_argument(
        "--dry-run", action="store_true",
        help="Montrer les fichiers qui seraient écrits, sans rien écrire",
    )
    fusion_sub.add_parser("unwire", help="Retirer Thot des deux agents")

    fusion_config = fusion_sub.add_parser(
        "config", help="Le modèle que chacun des trois utilisera"
    )
    fusion_config.add_argument(
        "--model", metavar="ID",
        help="Dire le même modèle aux trois (ex. claude-opus-5)",
    )
    fusion_config.add_argument(
        "--provider", metavar="NOM", default="",
        help="Le fournisseur qui va avec, quand il change aussi",
    )

    fusion_memory = fusion_sub.add_parser(
        "memory", help="Ce que les trois ont retenu, en une seule vue"
    )
    fusion_memory.add_argument(
        "--sync", action="store_true",
        help="Écrire les faits de Thot dans la mémoire de Hermes et de Prime",
    )

    fusion_skills = fusion_sub.add_parser(
        "skills", help="Les méthodes des trois, et qui peut atteindre quoi"
    )
    fusion_skills.add_argument(
        "--share", action="store_true",
        help="Donner à Prime les bibliothèques de Thot et de Hermes",
    )
    fusion_skills.add_argument(
        "--unique", action="store_true",
        help="N'afficher que ce qu'un seul des trois possède",
    )

    fusion_sessions = fusion_sub.add_parser(
        "sessions", help="L'historique des trois, du plus récent au plus ancien"
    )
    fusion_sessions.add_argument(
        "path", nargs="?", help="Limiter à un dépôt (défaut : tous)"
    )
    fusion_sessions.add_argument("--limit", type=int, default=30)

    fusion_audit = fusion_sub.add_parser(
        "audit", help="Auditer les trois arbres en une passe"
    )
    fusion_audit.add_argument(
        "--deep", action="store_true",
        help="Faire argumenter puis réfuter les candidats par un agent",
    )
    fusion_audit.add_argument(
        "--engine", choices=["claude", "hermes", "prime"], default="",
        help="Quel agent argumente (défaut : celui de `thot login`)",
    )
    fusion_audit.add_argument("--budget", type=int, default=20)
    fusion_audit.add_argument("--parallel", type=int, default=4)

    schedule = subparsers.add_parser(
        "schedule", help="Auditer un dépôt automatiquement"
    )
    schedule_sub = schedule.add_subparsers(dest="action")

    sched_add = schedule_sub.add_parser("add", help="Programmer un audit")
    sched_add.add_argument("name")
    sched_add.add_argument("path", nargs="?", default=".")
    sched_add.add_argument(
        "--every", default="daily", choices=list(SCHEDULES),
        help="Fréquence (défaut : daily, 3h du matin)",
    )
    sched_add.add_argument(
        "--threshold", default=Severity.HIGH.value,
        choices=[s.value for s in Severity],
        help="Ne signaler qu'à partir de ce niveau (défaut : high)",
    )
    sched_add.add_argument(
        "--deep", action="store_true", help="Analyse assistée par le modèle"
    )

    schedule_sub.add_parser("list", help="Les audits programmés")

    sched_remove = schedule_sub.add_parser("remove", help="Déprogrammer")
    sched_remove.add_argument("name")

    sched_run = schedule_sub.add_parser(
        "run", help="Exécuter maintenant (ce que le planificateur appelle)"
    )
    sched_run.add_argument("name", nargs="?")

    deps = subparsers.add_parser(
        "deps", help="Auditer les dépendances d'un dépôt contre OSV.dev"
    )
    deps.add_argument("path", nargs="?", default=".")
    deps.add_argument("--json", action="store_true", help="Sortie JSON")
    deps.add_argument("--list", action="store_true",
                      help="Lister ce qui a été trouvé, sans interroger OSV")
    deps.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                      help="Code de sortie 1 au-dessus de ce seuil")

    sandbox_cmd = subparsers.add_parser(
        "sandbox", help="Où s'exécutent les commandes lancées par le modèle"
    )
    sandbox_sub = sandbox_cmd.add_subparsers(dest="action")
    sandbox_sub.add_parser("status", help="Le bac à sable actif, et s'il est utilisable")
    sandbox_use = sandbox_sub.add_parser("use", help="Choisir le bac à sable")
    sandbox_use.add_argument("kind", choices=["local", "docker"])
    sandbox_use.add_argument("--image", help="Image du conteneur")
    sandbox_use.add_argument("--network", action="store_true",
                             help="Laisser le réseau ouvert (déconseillé)")
    sandbox_use.add_argument("--writable", action="store_true",
                             help="Monter le dépôt en écriture (déconseillé)")
    sandbox_show = sandbox_sub.add_parser(
        "show", help="Afficher la commande docker exacte qui serait lancée"
    )
    # Not "command": that is the top-level subparser's dest, and a
    # positional of the same name silently overwrites it — the subcommand
    # then dispatches to nothing and prints the help. REMAINDER so
    # `thot sandbox show pytest -q` shows the command rather than argparse
    # claiming -q for itself.
    sandbox_show.add_argument("shell_command", nargs=argparse.REMAINDER)

    gateway = subparsers.add_parser(
        "gateway", help="Recevoir les audits ailleurs que dans ce terminal"
    )
    gw_sub = gateway.add_subparsers(dest="action")
    gw_sub.add_parser("list", help="Les canaux configurés")
    gw_add = gw_sub.add_parser("add", help="Configurer un canal")
    gw_add.add_argument("platform", choices=list(GATEWAY_PLATFORMS))
    gw_add.add_argument("setting", nargs="*",
                        help="clé=valeur (token=…, chat_id=…, webhook=…, topic=…)")
    gw_allow = gw_sub.add_parser(
        "allow", help="Autoriser un identifiant à commander par ce canal"
    )
    gw_allow.add_argument("platform", choices=list(GATEWAY_PLATFORMS))
    gw_allow.add_argument("sender", nargs="+")
    gw_test = gw_sub.add_parser("test", help="Envoyer un message d'essai")
    gw_test.add_argument("platform", nargs="?")
    gw_remove = gw_sub.add_parser("remove", help="Retirer un canal")
    gw_remove.add_argument("platform", choices=list(GATEWAY_PLATFORMS))

    serve = subparsers.add_parser(
        "serve", help="Écouter les commandes venues des canaux configurés"
    )
    serve.add_argument("--once", action="store_true",
                       help="Traiter ce qui attend, puis rendre la main")

    mcp_cmd = subparsers.add_parser(
        "mcp", help="Les serveurs MCP disponibles et connectés"
    )
    mcp_sub = mcp_cmd.add_subparsers(dest="action")
    mcp_sub.add_parser(
        "serve",
        help="Servir la carte de Thot en MCP sur stdio (lancé par un agent)",
    )
    mcp_list = mcp_sub.add_parser("list", help="Le catalogue et ce qui est connecté")
    mcp_list.add_argument("--json", action="store_true", help="Sortie JSON")
    mcp_check = mcp_sub.add_parser(
        "check", help="Vérifier tes serveurs MCP contre OSV.dev (malware, CVE)"
    )
    mcp_check.add_argument("--all", action="store_true",
                           help="Signaler aussi les vulnérabilités ordinaires")
    mcp_show = mcp_sub.add_parser("show", help="Détail d'un serveur")
    mcp_show.add_argument("name")
    mcp_add = mcp_sub.add_parser("add", help="Connecter un serveur du catalogue")
    mcp_add.add_argument("name", nargs="+")
    mcp_add.add_argument("--scope", default="user", choices=["local", "user", "project"])
    mcp_remove = mcp_sub.add_parser("remove", help="Déconnecter un serveur")
    mcp_remove.add_argument("name")
    mcp_remove.add_argument("--scope", default="user",
                            choices=["local", "user", "project"])

    skills_cmd = subparsers.add_parser(
        "skills", help="Les méthodes disponibles, et la bibliothèque optionnelle"
    )
    skills_sub = skills_cmd.add_subparsers(dest="action")
    skills_list = skills_sub.add_parser("list", help="Les méthodes chargées")
    skills_list.add_argument("query", nargs="*", help="Filtrer")
    skills_search = skills_sub.add_parser(
        "search", help="Chercher dans la bibliothèque optionnelle aussi"
    )
    skills_search.add_argument("query", nargs="+")
    skills_show = skills_sub.add_parser("show", help="Afficher une méthode en entier")
    skills_show.add_argument("name")
    skills_install = skills_sub.add_parser(
        "install", help="Activer une méthode de la bibliothèque optionnelle"
    )
    skills_install.add_argument("name", nargs="+")
    skills_remove = skills_sub.add_parser("remove", help="Désactiver une méthode")
    skills_remove.add_argument("name")
    skills_scan = skills_sub.add_parser(
        "scan", help="Analyser un skill avant de lui faire confiance"
    )
    skills_scan.add_argument("path", nargs="?", default=".",
                             help="Dossier du skill, ou dépôt à balayer")
    skills_scan.add_argument("--source", default="community",
                             choices=["builtin", "trusted", "community"])

    sessions = subparsers.add_parser(
        "sessions", help="Les sessions de travail enregistrées"
    )
    sessions.add_argument("path", nargs="?", default=".",
                          help="Limiter à un dépôt (défaut : le dossier courant)")
    sessions.add_argument("--all", action="store_true",
                          help="Toutes les sessions, tous dépôts confondus")
    sessions.add_argument("--show", metavar="ID", help="Afficher une session entière")
    sessions.add_argument("--forget", metavar="ID", help="Supprimer une session")

    search = subparsers.add_parser(
        "search", help="Chercher dans tout ce que Thot a déjà dit ou trouvé"
    )
    search.add_argument("query", nargs="+", help="Les mots à chercher")
    search.add_argument("--all", action="store_true",
                        help="Chercher hors du dépôt courant aussi")
    search.add_argument("--limit", type=int, default=20)

    export = subparsers.add_parser("export", help="Écrire une session en JSON")
    export.add_argument("session", help="Identifiant de session (préfixe accepté)")
    export.add_argument("--out", help="Fichier de sortie")
    export.add_argument("--html", action="store_true",
                        help="Écrire une page HTML autonome plutôt que du JSON")

    importer = subparsers.add_parser("import", help="Recharger une session exportée")
    importer.add_argument("file")

    verdicts = subparsers.add_parser(
        "verdicts", help="Les décisions d'audit mémorisées"
    )
    verdicts.add_argument("--forget", metavar="ID", help="Oublier une décision")
    verdicts.add_argument(
        "--path", metavar="CHEMIN", help="Filtrer sur un chemin de fichier"
    )
    verdicts.add_argument(
        "--share", metavar="ID",
        help="Publier une décision dans .thot/verdicts.json, versionné avec le code",
    )
    verdicts.add_argument(
        "--where", action="store_true",
        help="Dire d'où viennent les décisions et où elles sont écrites",
    )

    init = subparsers.add_parser(
        "init", help="Déclarer l'autorisation d'auditer un dépôt"
    )
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--owner", default="", help="Propriétaire du code")

    audit = subparsers.add_parser("audit", help="Auditer un dépôt")
    audit.add_argument("path", nargs="?", default=".")
    audit.add_argument("--deps", action="store_true",
                       help="Vérifier aussi les dépendances contre OSV.dev (réseau)")
    audit.add_argument(
        "--engine", choices=["claude", "hermes", "prime"], default="",
        help="Quel agent argumente les findings avec --deep (défaut : celui de `thot login`)",
    )
    audit.add_argument("--sandbox", choices=["local", "docker"],
                       help="Où s'exécutent les commandes de la session")
    audit.add_argument("--json", action="store_true", help="Sortie JSON")
    audit.add_argument("--markdown", action="store_true", help="Sortie Markdown")
    audit.add_argument("--html", action="store_true",
                       help="Sortie HTML autonome (un seul fichier, aucun réseau)")
    audit.add_argument("--paths", action="store_true",
                       help="Afficher le chemin de teinte complet de chaque finding")
    audit.add_argument("--out", help="Écrire le rapport dans un fichier")
    audit.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Code de sortie 1 si un finding atteint ce seuil",
    )
    audit.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="medium",
        help="Seuil d'affichage (défaut : medium)",
    )
    audit.add_argument(
        "--all", action="store_true",
        help="Tout afficher, y compris le bruit de faible sévérité",
    )
    audit.add_argument(
        "--no-store", action="store_true", help="Ne pas persister le run"
    )
    audit.add_argument(
        "--no-memory", action="store_true",
        help="Ignorer les verdicts enregistrés pour ce run",
    )
    audit.add_argument(
        "--deep", action="store_true",
        help="Analyser les candidats avec le modèle connecté, puis les réfuter",
    )
    audit.add_argument(
        "--budget", type=int, default=DEFAULT_LIMIT, metavar="N",
        help=f"Nombre de candidats analysés en --deep (défaut : {DEFAULT_LIMIT})",
    )
    audit.add_argument(
        "--parallel", type=int, default=4, metavar="N",
        help="Analyses simultanées en --deep (défaut : 4)",
    )

    return parser


def _cmd_session(path: str = ".", *, toolset: str = "") -> int:
    """`thot` with no arguments: connect if needed, then open the session."""
    from thot.onboarding import ensure_configured
    from thot.session import start
    from thot.ui import theme

    config = ensure_configured()
    if config is None:
        theme.console.print()
        theme.hint("Aucun modèle connecté. Relance `thot` quand tu veux.")
        return EXIT_USAGE
    return start(Path(path).resolve(), config, toolset=toolset)


def _cmd_login() -> int:
    from thot.llm.credentials import save_config
    from thot.onboarding import first_run
    from thot.ui import theme

    config = first_run()
    if config is None:
        return EXIT_USAGE
    save_config(config)
    theme.console.print()
    theme.ok(f"Connecté — {config.label()}")
    theme.hint("Lance `thot` pour démarrer.")
    return EXIT_OK


def _cmd_logout() -> int:
    from thot.llm.credentials import forget
    from thot.ui import theme

    forget()
    theme.ok("Identifiants oubliés.")
    return EXIT_OK


def _cmd_init(args) -> int:
    from thot.scope.authorization import write_authorization

    target = Path(args.path)
    if not target.is_dir():
        # Authorising a directory into existence is how a typo becomes a
        # mandate. The audit refuses the same path a moment later; refusing
        # it here says why, once, at the point the mistake was made.
        print(f"Ce n'est pas un dossier : {target}", file=sys.stderr)
        return EXIT_USAGE

    owner = args.owner or Path.home().name
    path = write_authorization(target, owner=owner)
    print(f"Autorisation écrite : {path}")
    print(f"Propriétaire déclaré : {owner}")
    print(f"Tu peux maintenant lancer : thot audit {args.path}")
    return EXIT_OK


def _cmd_audit(args) -> int:
    from thot.console import print_paths, print_report
    from thot.pipeline import run_audit
    from thot.report.json_report import render_json
    from thot.report.markdown_report import render_markdown
    from thot.paths import run_store
    from thot.store.db import Store

    root = Path(args.path).resolve()

    engine = None
    if getattr(args, "engine", "") and not args.deep:
        # Choosing who argues the findings, without asking anyone to argue
        # them. Silently ignoring the flag would read as if it had worked.
        print(
            f"`--engine {args.engine}` ne sert qu'avec `--deep` : sans lui, "
            "aucun agent n'est appelé.",
            file=sys.stderr,
        )
    if args.deep:
        from thot.engine.factory import NoEngine, build_engine

        try:
            engine = build_engine(
                root, max_parallel=args.parallel,
                prefer=getattr(args, "engine", ""),
            )
        except NoEngine as exc:
            print(f"Analyse assistée impossible : {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(
            f"Analyse assistée : {engine.capabilities.name}, "
            f"{args.budget} candidats max, {args.parallel} en parallèle…",
            file=sys.stderr,
        )

    store = None if args.no_store else Store.open(run_store())

    memory = None
    if not args.no_memory:
        from thot.memory import build_memory

        memory = build_memory(root)

    try:
        result = run_audit(
            root, store=store, engine=engine, budget=args.budget, memory=memory,
            dependencies=bool(getattr(args, "deps", False)),
        )
    finally:
        if store is not None:
            store.close()
        if memory is not None:
            memory.close()

    from thot.plugins import discover as _discover_plugins
    from thot.plugins import invoke_hook as _invoke_hook

    _invoke_hook(_discover_plugins(root), "post_audit", result=result, root=root)

    if result.remembered:
        print(
            f"{result.remembered} finding(s) portent une décision mémorisée.",
            file=sys.stderr,
        )

    floor = 0 if args.all else _SEVERITY_RANK.index(Severity(args.min_severity))
    kept = [
        f for f in result.findings
        if _SEVERITY_RANK.index(f.severity) >= floor
    ]
    hidden = len(result.findings) - len(kept)
    shown = replace(result, findings=kept)

    if args.json:
        rendered = render_json(
            shown.findings, shown.manifest, shown.elapsed, hidden=hidden
        )
    elif args.markdown:
        rendered = render_markdown(
            shown.findings, shown.manifest, shown.elapsed, hidden=hidden
        )
    elif args.html:
        from thot.report.html_report import audit_page

        rendered = audit_page(shown, root=str(root)).html
    else:
        rendered = None

    if rendered is not None:
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
            print(f"Rapport écrit : {args.out}")
        else:
            print(rendered)
    else:
        print_report(shown, hidden=hidden)
        if args.paths:
            print_paths(shown)

    if args.fail_on:
        threshold = _SEVERITY_RANK.index(Severity(args.fail_on))
        for finding in result.findings:  # the floor never hides a CI failure
            if _SEVERITY_RANK.index(finding.severity) >= threshold:
                return EXIT_FINDINGS
    return EXIT_OK


def _cmd_schedule(args) -> int:
    from thot.schedule import install, jobs

    action = getattr(args, "action", None)

    if action == "add":
        root = Path(args.path).resolve()
        job = jobs.Job(
            name=args.name, root=str(root), schedule=args.every,
            threshold=args.threshold, deep=args.deep,
        )
        try:
            jobs.add(job)
        except ValueError as exc:
            print(f"Impossible : {exc}", file=sys.stderr)
            return EXIT_USAGE

        written, next_step = install.install(job)
        print(f"« {job.name} » programmé : {root}, {job.schedule}, seuil {job.threshold}")
        if written:
            print(f"Fichier écrit : {written}")
        print(f"\nPour l'activer :\n  {next_step}")
        print(f"\nPour l'annuler plus tard :\n  {install.uninstall_hint(job)}")
        return EXIT_OK

    if action == "remove":
        removed = jobs.remove(args.name)
        print("Déprogrammé." if removed else f"Aucun audit nommé « {args.name} ».")
        if removed:
            print(install.uninstall_hint(jobs.Job(name=args.name, root="")))
        return EXIT_OK if removed else EXIT_USAGE

    if action == "run":
        return _run_scheduled(args.name)

    programmed = jobs.load()
    if not programmed:
        print("Aucun audit programmé.")
        print("  thot schedule add nuit ~/mon-projet --every daily")
        return EXIT_OK
    for job in programmed:
        flag = " --deep" if job.deep else ""
        print(f"{job.name:<14} {job.schedule:<8} seuil {job.threshold:<8} {job.root}{flag}")
    return EXIT_OK


def _run_scheduled(name: str | None) -> int:
    """Execute due jobs and print only what is new. Silence is the success case."""
    from thot import logs
    from thot.memory import build_memory
    from thot.paths import run_store
    from thot.schedule import jobs
    from thot.schedule.runner import run_job
    from thot.store.db import Store

    logs.setup(mode="cron")
    logger = logs.get("schedule")

    selected = [j for j in jobs.load() if name is None or j.name == name]
    if not selected:
        print(f"Aucun audit nommé « {name} ».", file=sys.stderr)
        return EXIT_USAGE

    store = Store.open(run_store())
    found_something = False
    try:
        for job in selected:
            # Per job, not per run: each repository may carry its own
            # committed verdicts, and they are not interchangeable.
            memory = build_memory(job.root)
            try:
                fresh, total = run_job(job, store=store, memory=memory)
            finally:
                getattr(memory, "close", lambda: None)()
            logger.info("%s : %d nouveau(x) sur %d — %s",
                        job.name, len(fresh), total, job.root)
            if not fresh:
                continue
            found_something = True
            print(f"[{job.name}] {len(fresh)} nouveau(x) sur {total} — {job.root}")
            for finding in fresh:
                print(f"  {finding.severity.value.upper():<8} {finding.rule}  {finding.location}")
    finally:
        store.close()

    return EXIT_FINDINGS if found_something else EXIT_OK


def _cmd_verdicts(args) -> int:
    from thot.memory import build_memory

    root = Path.cwd().resolve()
    memory = build_memory(root)
    try:
        if args.where:
            described = getattr(memory, "describe", lambda: memory.name)()
            print(f"Chaîne : {described}")
            print(f"Local  : {home_hint()}")
            print(f"Dépôt  : {repo_verdicts(root)}")
            for layer in getattr(memory, "layers", []):
                # A remote layer that is quietly doing nothing is the whole
                # reason this flag exists.
                if not hasattr(layer, "last_error"):
                    continue
                reachable = layer.is_available()
                state = "joignable" if reachable else (layer.last_error or "muet")
                print(f"Distant: {layer.name} — {state}")
            return EXIT_OK

        if args.share:
            return _share_verdict(memory, args.share, root)

        if args.forget:
            removed = memory.forget(args.forget)
            print("Oublié." if removed else f"Aucune décision pour {args.forget}.")
            return EXIT_OK if removed else EXIT_USAGE

        stored = memory.all_verdicts()
        if args.path:
            stored = [v for v in stored if args.path in v.path]
        if not stored:
            print("Aucune décision mémorisée.")
            print("Les réfutations de `thot audit --deep` s'enregistrent ici.")
            return EXIT_OK

        known = _last_audited_ids(root)
        dormant = (
            0 if known is None
            else sum(1 for v in stored if v.finding_id not in known)
        )
        header = f"{len(stored)} décision(s)"
        if dormant:
            header += f" · {dormant} sans finding correspondant"
        print(header + "\n")

        for verdict in stored:
            where = f"{verdict.path}:{verdict.symbol}" if verdict.symbol else verdict.path
            author = f" · {verdict.author}" if verdict.author else ""
            # Not "expired": the last stored run is the only thing consulted,
            # and it may predate the code. What can be said is what is said.
            stale = (
                "  [absent du dernier audit]"
                if known is not None and verdict.finding_id not in known
                else ""
            )
            print(f"{verdict.finding_id}  {verdict.decision.value:<9} {where}{author}{stale}")
            if verdict.reason:
                print(f"{' ' * 18}{verdict.reason[:90]}")
        if dormant:
            print()
            print("Un verdict expire quand le code qu'il visait change : le finding")
            print("prend une nouvelle identité et la décision cesse de s'appliquer.")
            print("`thot verdicts --forget <id>` pour retirer celles qui ont fait leur temps.")
        return EXIT_OK
    finally:
        getattr(memory, "close", lambda: None)()


def _last_audited_ids(root: Path) -> set[str] | None:
    """The finding ids of the last stored audit here — None when there is none.

    A verdict outlives the finding that produced it: change the code and the
    finding takes a new identity, leaving the old decision pointing at
    nothing. Listing the two kinds identically made a memory of six decisions
    look like six live ones. None, not an empty set: never having audited
    this repository is not the same as having audited it and found nothing.
    """
    from thot.paths import run_store
    from thot.store.db import Store

    try:
        store = Store.open(run_store())
    except Exception:
        return None
    try:
        known = store.previous_finding_ids(str(root))
    except Exception:
        return None
    finally:
        store.close()
    return known or None


def home_hint() -> str:
    from thot.paths import memory_db

    return str(memory_db())


def repo_verdicts(root) -> str:
    from thot.memory import repo_path

    path = repo_path(root)
    return f"{path} ({'présent' if path.is_file() else 'absent'})"


def _share_verdict(memory, finding_id: str, root) -> int:
    """Promote a local decision into the file the team reviews.

    Deliberately a separate act. `/verdict` writes locally, because a tool
    that edits a committed file on every keystroke produces pull-request
    diffs nobody asked for. Publishing is a decision of its own.
    """
    from thot.memory import JsonMemory

    verdict = memory.recall(finding_id)
    if verdict is None:
        print(f"Aucune décision pour {finding_id}.", file=sys.stderr)
        return EXIT_USAGE

    shared = JsonMemory.for_repo(root)
    if not shared.is_available():
        print(f"Impossible d'écrire dans {repo_verdicts(root)}.", file=sys.stderr)
        return EXIT_USAGE
    shared.remember(verdict)
    print(f"{verdict.rule} à {verdict.path} — {verdict.decision.value}")
    print(f"Publié dans {shared.path}. Commite-le pour le partager.")
    return EXIT_OK


def _mcp_check(everything: bool) -> int:
    """Ask OSV whether the MCP servers you run are known-malicious.

    This is Hermes Agent's original use of OSV, ported: an MCP server is a
    package that gets executed on your machine, and `MAL-*` advisories are
    the ones that matter before it runs for the first time.
    """
    from thot.llm.claude_cli import user_mcp_definitions
    from thot.supply import OsvClient, from_mcp_command

    definitions = user_mcp_definitions(Path.cwd().resolve())
    if not definitions:
        print("Aucun serveur MCP configuré.")
        return EXIT_OK

    components, unpinned = [], []
    for name, entry in sorted(definitions.items()):
        component = from_mcp_command(name, entry.get("command", ""),
                                     entry.get("args") or [])
        (components.append(component) if component else unpinned.append(name))

    if not components:
        print(f"{len(definitions)} serveur(s), aucun ne fixe une version "
              f"vérifiable : {', '.join(unpinned)}.")
        print("Un serveur non épinglé ne peut pas être audité — c'est en soi "
              "une raison de l'épingler.")
        return EXIT_OK

    client = OsvClient()
    try:
        hits = client.query(components)
        if not hits and client.last_error:
            print(f"OSV.dev injoignable : {client.last_error}", file=sys.stderr)
            return EXIT_USAGE
        advisories = client.details([i for ids in hits.values() for i in ids])
    finally:
        client.close()

    dangerous = False
    for component in components:
        found = [advisories[i] for i in hits.get(component, [])
                 if i in advisories]
        malware = [a for a in found if a.malware]
        if malware:
            dangerous = True
            print(f"MALVEILLANT  {component.source[4:]:<22} {component.label()}")
            for advisory in malware:
                print(f"             {advisory.id} {advisory.summary[:90]}")
        elif found and everything:
            print(f"{len(found)} avis      {component.source[4:]:<22} "
                  f"{component.label()}")
        elif not found:
            print(f"propre       {component.source[4:]:<22} {component.label()}")

    if unpinned:
        print(f"\nNon épinglés, donc non vérifiés : {', '.join(unpinned)}")
    return EXIT_FINDINGS if dangerous else EXIT_OK


def _cmd_deps(args) -> int:
    """Audit a repository's pinned dependencies against OSV.dev."""
    from thot.contracts import Severity
    from thot.supply import audit_dependencies, discover

    root = Path(args.path).resolve()

    if args.list:
        components = discover(root)
        for component in components:
            print(f"{component.ecosystem:<6} {component.label():<40} "
                  f"{component.source}")
        print(f"\n{len(components)} dépendance(s) épinglée(s).")
        return EXIT_OK

    result = audit_dependencies(root)

    if args.json:
        from thot.report.json_report import render_json
        from thot.pipeline import AuditResult
        from thot.scope.detect import detect_scope

        print(render_json(AuditResult(findings=result.findings,
                                      manifest=detect_scope(root), elapsed=0.0)))
        return EXIT_OK

    if not result.checked:
        print(f"Dépendances non vérifiées : {result.error}", file=sys.stderr)
        print("OSV.dev est injoignable. Rien n'est affirmé sur ces paquets.",
              file=sys.stderr)
        return EXIT_USAGE

    print(result.summary())
    if not result.findings:
        return EXIT_OK

    print()
    for finding in result.findings:
        mark = "MALVEILLANT" if finding.confidence.value == "confirmed" else \
            finding.severity.value.upper()
        print(f"{mark:<11} {finding.provenance['paquet']:<34} "
              f"{finding.provenance['avis']}")
        print(f"{'':11} {finding.failure_scenario[:150]}")

    if args.fail_on:
        floor = _SEVERITY_RANK.index(Severity(args.fail_on))
        worst = max(_SEVERITY_RANK.index(f.severity) for f in result.findings)
        if worst >= floor:
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_sandbox(args) -> int:
    """Show or choose where model-run commands execute."""
    from thot.sandbox import SandboxError, build_sandbox, load_config, save_config
    from thot.sandbox.docker import DEFAULT_IMAGE, DockerSandbox

    action = getattr(args, "action", None) or "status"
    root = Path.cwd().resolve()
    config = load_config()

    if action == "use":
        config["kind"] = args.kind
        if args.image:
            config["image"] = args.image
        config["network"] = bool(args.network)
        config["writable"] = bool(args.writable)
        path = save_config(config)
        print(f"Bac à sable : {args.kind} → {path}")
        if args.kind == "docker":
            usable, reason = DockerSandbox(root=root).available()
            if not usable:
                print(f"Attention : {reason}", file=sys.stderr)
        if args.network:
            print("Le réseau reste ouvert : le code audité peut sortir.")
        return EXIT_OK

    if action == "show":
        sandbox = DockerSandbox(
            root=root, image=str(config.get("image") or DEFAULT_IMAGE),
            network=bool(config.get("network", False)),
            writable=bool(config.get("writable", False)),
        )
        print(sandbox.preview(" ".join(args.shell_command)))
        return EXIT_OK

    try:
        sandbox = build_sandbox(root, config=config)
    except SandboxError as exc:
        print(f"Bac à sable indisponible : {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"{sandbox.name} — {sandbox.describe()}")
    if sandbox.name == "local":
        print("`thot sandbox use docker` pour exécuter le code audité "
              "dans un conteneur sans réseau.")
    return EXIT_OK


def _cmd_gateway(args) -> int:
    """Configure where audits are delivered, and who may answer back."""
    from thot.gateway import config
    from thot.gateway.platforms import build

    action = getattr(args, "action", None) or "list"

    if action == "add":
        settings = {}
        for pair in args.setting:
            key, _, value = pair.partition("=")
            if not value:
                print(f"Attendu clé=valeur, reçu « {pair} ».", file=sys.stderr)
                return EXIT_USAGE
            settings[key.strip()] = value.strip()
        existing = next((c for c in config.load()
                         if c.platform == args.platform), None)
        merged = {**(existing.settings if existing else {}), **settings}
        path = config.upsert(args.platform, merged,
                             existing.allow if existing else ())
        print(f"{args.platform} configuré → {path}")
        if args.platform == "telegram" and not (existing and existing.allow):
            print("Pour commander depuis Telegram : "
                  "`thot gateway allow telegram <ton-id>`.")
        return 0

    if action == "allow":
        existing = next((c for c in config.load()
                         if c.platform == args.platform), None)
        if existing is None:
            print(f"{args.platform} n'est pas configuré.", file=sys.stderr)
            return EXIT_USAGE
        allow = tuple(dict.fromkeys([*existing.allow, *args.sender]))
        config.upsert(args.platform, existing.settings, allow)
        print(f"{args.platform} : {len(allow)} identifiant(s) autorisé(s).")
        return 0

    if action == "remove":
        if config.remove(args.platform):
            print(f"{args.platform} retiré.")
            return 0
        print(f"{args.platform} n'était pas configuré.", file=sys.stderr)
        return EXIT_USAGE

    if action == "test":
        from thot.gateway.server import broadcast

        only = (args.platform,) if args.platform else ()
        results = broadcast("Thot — message d'essai.", only=only)
        if not results:
            print("Aucun canal configuré.", file=sys.stderr)
            return EXIT_USAGE
        for delivery in results:
            mark = "✓" if delivery.ok else "✗"
            print(f"{mark} {delivery.platform} {delivery.detail}".rstrip())
        return 0 if all(d.ok for d in results) else EXIT_USAGE

    configured = config.load()
    if not configured:
        print("Aucun canal configuré.")
        print("`thot gateway add ntfy topic=<le-tien>` pour commencer.")
        return 0
    for channel in configured:
        platform = build(channel)
        ready = "prêt" if platform and platform.configured() else "incomplet"
        way = f"deux sens ({len(channel.allow)} autorisé(s))" \
            if channel.two_way else "sortant seulement"
        print(f"{channel.platform:<10} {ready:<10} {way}")
    return 0


def _cmd_mcp_serve() -> int:
    """Speak MCP on stdio until the agent that started us closes it.

    A subcommand rather than `python -m thot.mcp_server`, because Hermes
    refuses a plugin whose command is an absolute path — a plugin must not be
    able to point at an arbitrary binary. A bare `thot` on PATH satisfies
    that, and survives the virtualenv moving.
    """
    from thot.mcp_server import serve

    return serve()


def _cmd_serve(args) -> int:
    from thot import logs
    from thot.gateway.server import serve

    logs.setup(mode="gateway")

    try:
        return serve(once=args.once)
    except KeyboardInterrupt:
        print()
        return 0


def _cmd_mcp(args) -> int:
    """Browse the catalogue, and hand installation to the official CLI."""
    from thot.mcp import as_json, catalog, find, install, installed, remove

    action = getattr(args, "action", None) or "list"

    if action == "add":
        for name in args.name:
            server = find(name)
            if server is None:
                print(f"« {name} » n'est pas au catalogue.", file=sys.stderr)
                return EXIT_USAGE
            done, message = install(server, scope=args.scope)
            print(message, file=sys.stdout if done else sys.stderr)
            if not done:
                return EXIT_USAGE
        return 0

    if action == "remove":
        done, message = remove(args.name, scope=args.scope)
        print(message, file=sys.stdout if done else sys.stderr)
        return 0 if done else EXIT_USAGE

    if action == "check":
        return _mcp_check(bool(args.all))

    if action == "show":
        server = find(args.name)
        if server is None:
            print(f"« {args.name} » n'est pas au catalogue.", file=sys.stderr)
            return EXIT_USAGE
        print(f"{server.name} — {server.description}")
        print(f"transport : {server.transport}   auth : {server.auth}")
        if server.url:
            print(f"url       : {server.url}")
        if server.source:
            print(f"source    : {server.source}")
        print(f"connexion : {' '.join(server.add_command())}")
        return 0

    entries = catalog()
    if getattr(args, "json", False):
        print(as_json(entries))
        return 0

    connected = set(installed())
    for server in entries:
        mark = "✓" if server.name in connected else " "
        print(f"{mark} {server.name:<16} {server.auth:<8} {server.summary()}")

    extra = sorted(connected - {s.name for s in entries})
    if extra:
        print("\nHors catalogue, déjà connectés : " + ", ".join(extra))
    print(f"\n{len(connected & {s.name for s in entries})}/{len(entries)} "
          f"connecté(s) · `thot mcp add <nom>`")
    return 0


def _cmd_skills(args) -> int:
    """Browse the library, and move an optional skill into the loaded set."""
    from thot.skills.loader import discover, install, optional, uninstall

    action = getattr(args, "action", None) or "list"
    root = Path.cwd().resolve()

    if action == "install":
        for name in args.name:
            try:
                target = install(name)
            except KeyError:
                print(f"« {name} » n'est pas dans la bibliothèque optionnelle.",
                      file=sys.stderr)
                return EXIT_USAGE
            print(f"{target.name} activé → {target}")
        return 0

    if action == "remove":
        if uninstall(args.name):
            print(f"{args.name} désactivé.")
            return 0
        print(f"« {args.name} » n'est pas une méthode installée par toi.",
              file=sys.stderr)
        return EXIT_USAGE

    if action == "scan":
        from thot.guard.skill_guard import (
            format_scan_report,
            scan_skill,
            should_allow_install,
        )

        target = Path(args.path).resolve()
        candidates = (
            [target] if (target / "SKILL.md").is_file()
            else sorted(p.parent for p in target.rglob("SKILL.md"))
        )
        if not candidates:
            print(f"Aucun SKILL.md sous {target}.", file=sys.stderr)
            return EXIT_USAGE

        worst = 0
        for folder in candidates:
            result = scan_skill(folder, source=args.source)
            allowed, reason = should_allow_install(result)
            print(f"{result.verdict:<10} {folder.name:<32} {reason}")
            if result.findings:
                print(format_scan_report(result))
            worst = max(worst, 0 if allowed else 1)
        return 0 if worst == 0 else EXIT_USAGE

    if action == "show":
        for item in discover(root):
            if item.name == args.name:
                print(f"# {item.name}\n\n{item.description}\n")
                print(item.body)
                return 0
        print(f"Méthode inconnue : {args.name}", file=sys.stderr)
        return EXIT_USAGE

    query = " ".join(getattr(args, "query", []) or [])
    loaded = discover(root)
    shown = [s for s in loaded if not query or s.matches(query)]

    for item in shown:
        label = f"{item.category}/{item.name}" if item.category else item.name
        print(f"{label:<52} {' '.join(item.description.split())[:64]}")
    print(f"\n{len(shown)}/{len(loaded)} méthode(s) chargée(s).")

    if action == "search" or not shown:
        spare = [s for s in optional() if not query or s.matches(query)]
        installed = {s.name for s in loaded}
        spare = [s for s in spare if s.name not in installed]
        if spare:
            print(f"\nBibliothèque optionnelle ({len(spare)}) — "
                  f"`thot skills install <nom>` :")
            for item in spare[:40]:
                label = f"{item.category}/{item.name}" if item.category else item.name
                print(f"  {label:<50} {' '.join(item.description.split())[:60]}")
    return 0


def _cmd_sessions(args) -> int:
    """List, show, or delete recorded sessions."""
    from thot.state import SessionStore

    store = SessionStore.open()
    try:
        if args.forget:
            resolved = store.resolve(args.forget)
            if resolved is None:
                print(f"Aucune session « {args.forget} ».", file=sys.stderr)
                return EXIT_USAGE
            store.forget(resolved)
            print(f"Session {resolved[:8]} supprimée.")
            return 0

        if args.show:
            resolved = store.resolve(args.show)
            if resolved is None:
                print(f"Aucune session « {args.show} ».", file=sys.stderr)
                return EXIT_USAGE
            info = store.info(resolved)
            print(f"{info.id}  {info.title or '(sans titre)'}")
            print(f"{info.root}  ·  {info.started_at}")
            print()
            for turn in store.turns(resolved):
                print(f"— {turn.role} —")
                print(turn.content)
                print()
            return 0

        root = None if args.all else str(Path(args.path).resolve())
        found = store.sessions(root, limit=50)
        if not found:
            print("Aucune session enregistrée.")
            return 0
        for info in found:
            title = info.title or "(sans titre)"
            marker = " " if info.ended_at else "*"
            print(f"{marker}{info.id[:8]}  {info.message_count:>4} msg  "
                  f"{info.started_at[:16]}  {title[:60]}")
        return 0
    finally:
        store.close()


def _cmd_search(args) -> int:
    """Search every session, or just this repository's."""
    from thot.state import SessionStore
    from thot.state.search import CLOSE, OPEN

    store = SessionStore.open()
    try:
        root = None if args.all else str(Path.cwd().resolve())
        hits = store.find(" ".join(args.query), root=root, limit=args.limit)
        if not hits and not args.all:
            hits = store.find(" ".join(args.query), limit=args.limit)
        if not hits:
            print("Aucun résultat.")
            return 0
        for hit in hits:
            text = hit.snippet.replace(OPEN, "\033[1m").replace(CLOSE, "\033[0m")
            print(f"{hit.session_id[:8]}  {hit.role:<9} {' '.join(text.split())}")
        return 0
    finally:
        store.close()


def _cmd_export(args) -> int:
    from thot.state import SessionStore, write_export

    store = SessionStore.open()
    try:
        resolved = store.resolve(args.session)
        if resolved is None:
            print(f"Aucune session « {args.session} ».", file=sys.stderr)
            return EXIT_USAGE

        if args.html:
            from thot.report.html_report import session_page

            target = Path(args.out or f"thot-session-{resolved[:8]}.html")
            page = session_page(store.info(resolved), store.turns(resolved))
            print(page.write(target))
            return 0

        target = Path(args.out or f"thot-session-{resolved[:8]}.json")
        print(write_export(store, resolved, target))
        return 0
    finally:
        store.close()


def _cmd_import(args) -> int:
    from thot.state import SessionStore, read_import

    store = SessionStore.open()
    try:
        created = read_import(store, Path(args.file))
        print(f"{len(created)} session(s) importée(s) : "
              + ", ".join(i[:8] for i in created))
        return 0
    except (OSError, ValueError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        store.close()


# Handed over before argparse sees them. `thot hermes --version` must reach
# Hermes, and argparse has no way to express "everything after this word is
# somebody else's grammar" — REMAINDER still lets the leading `--version` be
# claimed as Thot's own.
PASSTHROUGH = ("hermes", "prime")


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in PASSTHROUGH:
        return _cmd_run_part(raw[0], raw[1:])

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    if not args.command:
        return _cmd_session(toolset=getattr(args, "tools", ""))

    try:
        if args.command == "login":
            return _cmd_login()
        if args.command == "logout":
            return _cmd_logout()
        if args.command == "init":
            return _cmd_init(args)
        if args.command == "schedule":
            return _cmd_schedule(args)
        if args.command == "verdicts":
            return _cmd_verdicts(args)
        if args.command == "deps":
            return _cmd_deps(args)
        if args.command == "sandbox":
            return _cmd_sandbox(args)
        if args.command == "gateway":
            return _cmd_gateway(args)
        if args.command == "serve":
            return _cmd_serve(args)
        if args.command == "mcp":
            if getattr(args, "action", None) == "serve":
                return _cmd_mcp_serve()
            return _cmd_mcp(args)
        if args.command == "skills":
            return _cmd_skills(args)
        if args.command == "sessions":
            return _cmd_sessions(args)
        if args.command == "search":
            return _cmd_search(args)
        if args.command == "export":
            return _cmd_export(args)
        if args.command == "import":
            return _cmd_import(args)
        if args.command == "audit":
            return _cmd_audit(args)
        if args.command == "hermes":
            return _cmd_run_part("hermes", args.arguments)
        if args.command == "prime":
            return _cmd_run_part("prime", args.arguments)
        if args.command == "fusion":
            return _cmd_fusion(args)
    except AuthorizationError as exc:
        print(f"Refus : {exc}", file=sys.stderr)
        return EXIT_UNAUTHORIZED
    except ThotError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE

    parser.print_help()
    return EXIT_USAGE


def _cmd_run_part(name: str, arguments: list[str]) -> int:
    """Hand the terminal to Hermes or Prime."""
    from thot.fusion import run as fusion_run

    launcher = fusion_run.run_hermes if name == "hermes" else fusion_run.run_prime
    try:
        return launcher(list(arguments or []))
    except fusion_run.NotAvailable as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR


def _cmd_fusion(args) -> int:
    from thot.fusion import locate, wiring

    action = getattr(args, "action", None) or "status"

    if action == "status":
        for part in locate.parts():
            print(part.line())
        print()
        # Being installed and being reachable from the agents are different
        # facts, and a status that showed only the first would be the more
        # flattering half of the truth.
        steps = wiring.plan()
        wired = [step for step in steps if not step.changes]
        print(f"Carte de Thot branchée : {len(wired)}/{len(steps)} fichiers")
        for step in steps:
            print(f"   {step.line()}")
        if len(wired) != len(steps):
            print()
            print("`thot fusion wire` pour donner la carte aux deux agents.")

        from thot.engine.factory import available_engines

        usable = available_engines()
        print()
        # The reverse direction: the map goes out to the agents, and the
        # agents come back as engines that argue findings.
        print(f"Moteurs pour `--deep` : {', '.join(usable) if usable else 'aucun'}")
        if usable:
            print(f"   thot audit . --deep --engine {usable[-1]}")

        from thot.fusion import config as fusion_config
        from thot.fusion import memory as fusion_memory

        print()
        disagreement = fusion_config.divergence()
        print(f"Modèle : {disagreement or 'le même pour les trois'}")
        try:
            shared = len(fusion_memory.merged(Path.cwd()))
        except Exception:
            shared = 0
        print(f"Mémoire partagée : {shared} note(s) — `thot fusion memory`")
        return EXIT_OK

    if action == "wire":
        if getattr(args, "dry_run", False):
            for step in wiring.plan():
                print(step.line())
            return EXIT_OK
        steps = wiring.wire()
        changed = [step for step in steps if step.changes]
        for step in steps:
            print(step.line())
        if changed:
            print()
            print("Hermes et Prime voient maintenant `code_map`, `find_symbol`,")
            print("`callers`, `audit`, `skills` et `skill` — sans appel modèle.")
            print("Redémarre-les pour que le serveur soit chargé.")
        return EXIT_OK

    if action == "config":
        from thot.fusion import config as fusion_config

        model = getattr(args, "model", None)
        if model:
            for applied in fusion_config.apply(model, getattr(args, "provider", "")):
                print(applied.line())
            print()

        for choice in fusion_config.read_all():
            print(choice.line())
        disagreement = fusion_config.divergence()
        if disagreement:
            print()
            print(disagreement)
            print("`thot fusion config --model <id>` pour n'en avoir qu'un.")
        return EXIT_OK

    if action == "memory":
        from thot.fusion import memory as fusion_memory

        if getattr(args, "sync", False):
            for written in fusion_memory.project(Path.cwd()):
                print(written.line())
            print()

        notes = fusion_memory.merged(Path.cwd())
        ignored = fusion_memory.skipped()
        if not notes:
            print("Rien en mémoire, dans aucun des trois.")
        for note in notes:
            print(f"  {note.line()}")
        if ignored:
            print()
            # Said, not swallowed: Thot cannot tell an unfilled form from a
            # terse note with certainty, so the number is on screen.
            print(f"{ignored} entrée(s) écartée(s) : gabarit non rempli.")
        return EXIT_OK

    if action == "audit":
        from thot.fusion import audit as fusion_audit

        if getattr(args, "deep", False):
            print("Analyse assistée sur les trois arbres…", file=sys.stderr)
        done = fusion_audit.audit_all(
            deep=getattr(args, "deep", False),
            engine_name=getattr(args, "engine", ""),
            budget=args.budget, parallel=args.parallel,
        )
        for part in done:
            print(part.line())
        print()
        print(fusion_audit.summary(done))
        highest = max(
            (f.severity for part in done if part.ok for f in part.result.findings),
            default=None,
        )
        from thot.contracts import Severity

        if highest in (Severity.CRITICAL, Severity.HIGH):
            return EXIT_FINDINGS
        return EXIT_OK

    if action == "skills":
        from thot.fusion import skills as fusion_skills

        if getattr(args, "share", False):
            for step in fusion_skills.share():
                print(step.line())
            print()

        for library in fusion_skills.libraries():
            print(library.line())
        print()

        entries = fusion_skills.catalogue()
        shared = sum(1 for entry in entries if entry.shared)
        print(f"{len(entries)} méthodes distinctes · {shared} vues par plusieurs")

        if getattr(args, "unique", False):
            for entry in entries:
                if not entry.shared:
                    print(f"   {entry.line()}")
        else:
            for program in ("thot", "hermes", "prime"):
                only = fusion_skills.only_in(program)
                if only:
                    print(f"   seulement {program:<7} {len(only):>3} — "
                          f"{', '.join(only[:4])}"
                          + (" …" if len(only) > 4 else ""))

        blocked = fusion_skills.not_portable()
        if blocked:
            # Catalogued, never loaded: they call Prime's own kernel API,
            # which Thot does not provide. Saying so beats a silent gap.
            print()
            print(f"{len(blocked)} méthode(s) de Prime restent chez Prime : "
                  "elles appellent son noyau, pas celui de Thot.")
        return EXIT_OK

    if action == "sessions":
        from thot.fusion import sessions as fusion_sessions

        root = Path(args.path).resolve() if getattr(args, "path", None) else None
        found = fusion_sessions.merged(root, limit=args.limit)
        if not found:
            print("Aucune session, dans aucun des trois.")
            return EXIT_OK
        for session in found:
            print(f"  {session.line()}")
        counts: dict[str, int] = {}
        for session in found:
            counts[session.source] = counts.get(session.source, 0) + 1
        print()
        print(" · ".join(f"{n} {name}" for name, n in sorted(counts.items())))
        return EXIT_OK

    if action == "unwire":
        removed = wiring.unwire()
        for step in removed:
            print(step.line())
        if not removed:
            print("Thot n'était branché nulle part.")
        return EXIT_OK

    print(f"Action inconnue : {action}", file=sys.stderr)
    return EXIT_USAGE


def run() -> None:
    """The console entry point. Bootstrap before anything prints."""
    from thot import bootstrap

    bootstrap.apply()
    sys.exit(main())
