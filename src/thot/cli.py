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

DEFAULT_STORE = Path.home() / ".thot" / "store.db"


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

    store = None if args.no_store else Store.open(DEFAULT_STORE)

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
    from thot.schedule import jobs
    from thot.schedule.runner import run_job
    from thot.store.db import Store

    selected = [j for j in jobs.load() if name is None or j.name == name]
    if not selected:
        print(f"Aucun audit nommé « {name} ».", file=sys.stderr)
        return EXIT_USAGE

    store = Store.open(DEFAULT_STORE)
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
