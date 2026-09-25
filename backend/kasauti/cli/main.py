"""``kasauti`` command-line interface (PLAN §4.2).

M0 ships the commands that work today. ``kasauti audit`` arrives with the M1 walking skeleton
and ``kasauti verify`` with the transparency log in M5; they are not stubbed here, because a
command that pretends to work is worse than one that doesn't exist yet.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from kasauti import __version__
from kasauti.packs.loader import PackError, load_framework_pack, load_ruleset, load_vendor_pack


def _validate_packs(root: Path) -> int:
    failures = 0
    checked = 0
    for vendor_dir in sorted((root / "vendors").glob("*/")):
        checked += 1
        failures += _report(
            f"vendor pack {vendor_dir.name}", lambda d=vendor_dir: load_vendor_pack(d)
        )
    for fw_dir in sorted((root / "frameworks").glob("*/")):
        checked += 1
        failures += _report(
            f"framework pack {fw_dir.name}", lambda d=fw_dir: load_framework_pack(d)
        )
    checked += 1
    failures += _report(
        "rules + derivations", lambda: load_ruleset(root / "rules", root / "derivations")
    )
    print(f"{checked - failures}/{checked} pack groups valid")
    return 1 if failures else 0


def _report(label: str, load: object) -> int:
    try:
        load()  # type: ignore[operator]
    except PackError as err:
        print(f"FAIL {label}")
        for problem in err.problems:
            print(f"  - {problem}")
        return 1
    print(f"ok   {label}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kasauti",
        description="Kasauti (कसौटी): multi-vendor network security compliance auditor",
    )
    parser.add_argument("--version", action="version", version=f"kasauti {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    packs = sub.add_parser("packs", help="work with content packs")
    packs_sub = packs.add_subparsers(dest="packs_command", required=True)
    validate = packs_sub.add_parser("validate", help="schema-check every pack under a directory")
    validate.add_argument("root", type=Path, nargs="?", default=Path("packs"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Windows consoles default to cp1252; the product name and reports contain Devanagari.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    if args.command == "packs" and args.packs_command == "validate":
        return _validate_packs(args.root)
    return 2  # pragma: no cover - argparse enforces the choices above


if __name__ == "__main__":
    sys.exit(main())
