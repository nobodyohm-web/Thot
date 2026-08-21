"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

from thot import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thot",
        description="Audit de code adossé à des preuves.",
    )
    parser.add_argument(
        "--version", action="version", version=f"thot {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command")

    audit = subparsers.add_parser("audit", help="Auditer un dépôt")
    audit.add_argument("path", nargs="?", default=".", help="Racine du dépôt")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if not args.command:
        parser.print_help()
        return 2
    return 0


def run() -> None:
    sys.exit(main())
