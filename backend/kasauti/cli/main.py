"""``kasauti`` command-line interface (PLAN §4.2).

Commands that work today: ``audit`` (M1) and ``packs validate`` (M0). ``kasauti verify`` arrives
with the transparency log in M5; it is not stubbed, because a command that pretends to work is
worse than one that doesn't exist yet.

Exit codes: 0 done; 1 the input or packs couldn't be used (message on stderr); 2 bad usage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from kasauti import __version__
from kasauti.audit import AuditError, AuditResult, audit, load_kb
from kasauti.ingest.read import IngestError, read_file
from kasauti.packs.loader import PackError, load_framework_pack, load_ruleset, load_vendor_pack
from kasauti.rules.model import Status

FRAMEWORK_ALIASES = {"nist": "nist_800_53r5", "nist_800_53r5": "nist_800_53r5"}


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


def _audit(args: argparse.Namespace) -> int:
    try:
        kb = load_kb(args.packs)
        artifact = read_file(args.config)
        result = audit(
            artifact,
            kb,
            vendor=args.vendor,
            frameworks=tuple(dict.fromkeys(FRAMEWORK_ALIASES[f] for f in args.framework)),
        )
    except (IngestError, AuditError) as err:
        print(f"kasauti: {err}", file=sys.stderr)
        return 1
    except PackError as err:
        print("kasauti: the knowledge base is invalid:", file=sys.stderr)
        for problem in err.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.config.name.rsplit(".", 1)[0]
    json_path = args.out / f"{stem}.kasauti.json"
    # LF on every OS, so the bytes (and their hash) match across machines.
    json_path.write_bytes(result.canonical_json().encode("utf-8"))
    written = [json_path]
    if not args.no_pdf:
        from kasauti.report.pdf import render_pdf  # noqa: PLC0415 - ReportLab only when needed

        pdf_path = args.out / f"{stem}.kasauti.pdf"
        rules = {r.id: r for r in kb.ruleset.rules}
        pdf_path.write_bytes(render_pdf(result, rules, generated=_report_date(args.date)))
        written.append(pdf_path)
    _print_summary(result, written)
    return 0


def _report_date(given: str | None) -> str:
    """``--date``, else ``SOURCE_DATE_EPOCH`` (reproducible builds), else today."""
    if given:
        return dt.date.fromisoformat(given).isoformat()
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return dt.datetime.fromtimestamp(int(epoch), tz=dt.UTC).date().isoformat()
    return dt.date.today().isoformat()


def _print_summary(result: AuditResult, written: Sequence[Path]) -> None:
    host = result.identity["hostname"].value or result.input.file
    print(f"{host}  ({result.kb.vendor_pack}, chosen by {result.detection.chosen_by})")
    for sc in result.scores:
        comp = "n/a" if sc.compliance_pct is None else f"{sc.compliance_pct:.1f}%"
        cov = "n/a" if sc.coverage_pct is None else f"{sc.coverage_pct:.1f}%"
        print(
            f"  {sc.title}: compliance {comp}, coverage {cov} "
            f"({sc.passed} pass, {sc.failed} fail, {sc.review} review, {sc.not_applicable} n/a)"
        )
    for rule in result.rules:
        if rule.status in (Status.FAIL, Status.REVIEW):
            print(f"  {rule.status.value:<6} {rule.severity.value:<8} {rule.rule_id}: {rule.title}")
    a = result.assurance
    print(f"  understood {a.understood}/{a.statements} statements; audit {result.audit_id}")
    for warning in result.warnings:
        print(f"  warning: {warning}")
    for path in written:
        print(f"  wrote {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kasauti",
        description="Kasauti (कसौटी): multi-vendor network security compliance auditor",
    )
    parser.add_argument("--version", action="version", version=f"kasauti {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    aud = sub.add_parser("audit", help="audit one configuration file")
    aud.add_argument("config", type=Path, help="configuration file (e.g. router.cfg)")
    aud.add_argument(
        "--framework",
        action="append",
        choices=sorted(FRAMEWORK_ALIASES),
        default=None,
        help="framework to score against (repeatable; default: nist)",
    )
    aud.add_argument("--vendor", help="vendor pack id, if fingerprinting can't tell")
    aud.add_argument("--packs", type=Path, default=Path("packs"), help="knowledge base root")
    aud.add_argument("--out", type=Path, default=Path(), help="where to write the report")
    aud.add_argument("--date", help="report date YYYY-MM-DD (default: today)")
    aud.add_argument("--no-pdf", action="store_true", help="write the JSON result only")

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
    if args.command == "audit":
        args.framework = args.framework or ["nist"]
        return _audit(args)
    if args.command == "packs" and args.packs_command == "validate":
        return _validate_packs(args.root)
    return 2  # pragma: no cover - argparse enforces the choices above


if __name__ == "__main__":
    sys.exit(main())
