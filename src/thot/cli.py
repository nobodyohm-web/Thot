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
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("login", help="Choisir ou changer le modèle connecté")
    subparsers.add_parser("logout", help="Oublier le modèle connecté")

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

    importer = subparsers.add_parser("import", help="Recharger une session exportée")
    importer.add_argument("file")

    verdicts = subparsers.add_parser(
        "verdicts", help="Les décisions d'audit mémorisées"
    )
    verdicts.add_argument("--forget", metavar="ID", help="Oublier une décision")
    verdicts.add_argument(
        "--path", metavar="CHEMIN", help="Filtrer sur un chemin de fichier"
    )

    init = subparsers.add_parser(
        "init", help="Déclarer l'autorisation d'auditer un dépôt"
    )
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--owner", default="", help="Propriétaire du code")

    audit = subparsers.add_parser("audit", help="Auditer un dépôt")
    audit.add_argument("path", nargs="?", default=".")
    audit.add_argument("--json", action="store_true", help="Sortie JSON")
    audit.add_argument("--markdown", action="store_true", help="Sortie Markdown")
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


def _cmd_session(path: str = ".") -> int:
    """`thot` with no arguments: connect if needed, then open the session."""
    from thot.onboarding import ensure_configured
    from thot.session import start
    from thot.ui import theme

    config = ensure_configured()
    if config is None:
        theme.console.print()
        theme.hint("Aucun modèle connecté. Relance `thot` quand tu veux.")
        return EXIT_USAGE
    return start(Path(path).resolve(), config)


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

    owner = args.owner or Path.home().name
    path = write_authorization(Path(args.path), owner=owner)
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
    if args.deep:
        from thot.engine.factory import NoEngine, build_engine

        try:
            engine = build_engine(root, max_parallel=args.parallel)
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
        from thot.memory.sqlite import SqliteMemory

        memory = SqliteMemory.open()

    try:
        result = run_audit(
            root, store=store, engine=engine, budget=args.budget, memory=memory
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
    from thot.memory.sqlite import SqliteMemory
    from thot.paths import run_store
    from thot.schedule import jobs
    from thot.schedule.runner import run_job
    from thot.store.db import Store

    selected = [j for j in jobs.load() if name is None or j.name == name]
    if not selected:
        print(f"Aucun audit nommé « {name} ».", file=sys.stderr)
        return EXIT_USAGE

    store = Store.open(run_store())
    memory = SqliteMemory.open()
    found_something = False
    try:
        for job in selected:
            fresh, total = run_job(job, store=store, memory=memory)
            if not fresh:
                continue
            found_something = True
            print(f"[{job.name}] {len(fresh)} nouveau(x) sur {total} — {job.root}")
            for finding in fresh:
                print(f"  {finding.severity.value.upper():<8} {finding.rule}  {finding.location}")
    finally:
        store.close()
        memory.close()

    return EXIT_FINDINGS if found_something else EXIT_OK


def _cmd_verdicts(args) -> int:
    from thot.memory.sqlite import SqliteMemory

    memory = SqliteMemory.open()
    try:
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

        print(f"{len(stored)} décision(s)\n")
        for verdict in stored:
            where = f"{verdict.path}:{verdict.symbol}" if verdict.symbol else verdict.path
            author = f" · {verdict.author}" if verdict.author else ""
            print(f"{verdict.finding_id}  {verdict.decision.value:<9} {where}{author}")
            if verdict.reason:
                print(f"{' ' * 18}{verdict.reason[:90]}")
        return EXIT_OK
    finally:
        memory.close()


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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    if not args.command:
        return _cmd_session()

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
    except AuthorizationError as exc:
        print(f"Refus : {exc}", file=sys.stderr)
        return EXIT_UNAUTHORIZED
    except ThotError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE

    parser.print_help()
    return EXIT_USAGE


def run() -> None:
    sys.exit(main())
