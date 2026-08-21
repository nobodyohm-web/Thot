"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from thot import __version__
from thot.contracts import Severity
from thot.errors import AuthorizationError, ThotError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNAUTHORIZED = 3

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
        "--no-store", action="store_true", help="Ne pas persister le run"
    )

    return parser


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
    store = None if args.no_store else Store.open(DEFAULT_STORE)

    try:
        result = run_audit(root, store=store)
    finally:
        if store is not None:
            store.close()

    if args.json:
        rendered = render_json(result.findings, result.manifest, result.elapsed)
    elif args.markdown:
        rendered = render_markdown(result.findings, result.manifest, result.elapsed)
    else:
        rendered = None

    if rendered is not None:
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
            print(f"Rapport écrit : {args.out}")
        else:
            print(rendered)
    else:
        print_report(result)
        if args.paths:
            print_paths(result)

    if args.fail_on:
        threshold = _SEVERITY_RANK.index(Severity(args.fail_on))
        for finding in result.findings:
            if _SEVERITY_RANK.index(finding.severity) >= threshold:
                return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    try:
        if args.command == "init":
            return _cmd_init(args)
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
