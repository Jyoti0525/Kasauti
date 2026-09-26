"""``kasauti`` command-line interface (PLAN §4.2).

Commands that work today: ``audit`` (M1), ``packs validate`` (M0), ``serve`` (M2.01, the web
API on the loopback interface, with its pool of job workers from M2.03) and ``db upgrade`` /
``db status`` (M2.02; ``audit`` never needs a database). ``kasauti verify`` arrives
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
from typing import TYPE_CHECKING

from kasauti import __version__
from kasauti.audit import AuditError, AuditResult, audit, load_kb
from kasauti.ingest.read import IngestError, read_file
from kasauti.packs.loader import PackError, load_framework_pack, load_ruleset, load_vendor_pack
from kasauti.rules.model import Status

if TYPE_CHECKING:
    from sqlalchemy import URL

FRAMEWORK_ALIASES = {"nist": "nist_800_53r5", "nist_800_53r5": "nist_800_53r5"}
LOOPBACK_NAMES = ("127.0.0.1", "localhost")
DATA_DIR_ENV = "KASAUTI_DATA_DIR"
MAX_WORKERS = 32


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


def _serve(args: argparse.Namespace) -> int:
    """Run the web API on the loopback interface. Any other address is refused until accounts,
    MFA and TLS exist (TODO M5.B, PLAN §17): the API would hand configurations to the LAN."""
    if args.host not in LOOPBACK_NAMES:
        print(
            f"kasauti: serve listens on the loopback interface only (127.0.0.1), not {args.host}. "
            "Serving to the network needs accounts, MFA and TLS, which arrive in M5.",
            file=sys.stderr,
        )
        return 2
    from kasauti.api.app import Settings, create_app  # noqa: PLC0415 - web stack only here
    from kasauti.db import SchemaError  # noqa: PLC0415

    try:
        url = _database(args.data_dir)
        if url.drivername.startswith("sqlite"):
            _migrate(url)  # one user, one file: keep it current. PostgreSQL is the DBA's call.
        app = create_app(Settings(packs=args.packs, database=url, workers=args.workers))
    except PackError as err:
        print("kasauti: the knowledge base is invalid:", file=sys.stderr)
        for problem in err.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    except (_DatabaseError, SchemaError) as err:
        print(f"kasauti: {err}", file=sys.stderr)
        return 1
    import uvicorn  # noqa: PLC0415

    print(f"kasauti {__version__}: http://127.0.0.1:{args.port}/api/health (loopback only)")
    uvicorn.run(
        app,
        host="127.0.0.1",  # never a name: `localhost` may also resolve to other addresses
        port=args.port,
        server_header=False,
        proxy_headers=False,
        log_level="info",
    )
    return 0


class _DatabaseError(Exception):
    """A database that can't be used, described without its password."""


def _database(data_dir: Path) -> URL:
    from kasauti.db import DatabaseConfigError, database_url  # noqa: PLC0415

    try:
        return database_url(data_dir)
    except DatabaseConfigError as err:
        raise _DatabaseError(str(err)) from None


def _migrate(url: URL) -> tuple[str | None, str]:
    """Upgrade ``url`` to the newest schema; the revisions before and after."""
    from sqlalchemy.exc import SQLAlchemyError  # noqa: PLC0415

    from kasauti.db import create_engine, current_revision, redacted, upgrade  # noqa: PLC0415

    engine = create_engine(url)
    try:
        before = current_revision(engine)
        upgrade(engine)
        return before, current_revision(engine) or "none"
    except SQLAlchemyError as err:
        raise _DatabaseError(f"can't use the database {redacted(url)} ({_cause(err)})") from None
    finally:
        engine.dispose()


def _db(args: argparse.Namespace) -> int:
    from sqlalchemy.exc import SQLAlchemyError  # noqa: PLC0415

    from kasauti.db import (  # noqa: PLC0415
        create_engine,
        current_revision,
        exists,
        head_revision,
        redacted,
    )

    try:
        url = _database(args.data_dir)
        if args.db_command == "upgrade":
            before, after = _migrate(url)
            change = "already current" if before == after else f"{before or 'empty'} -> {after}"
            print(f"{redacted(url)}: schema {after} ({change})")
            return 0
        if not exists(url):  # status mustn't create the file it reports on
            print(f"{redacted(url)}: no database yet; `kasauti db upgrade` creates it")
            return 1
        engine = create_engine(url)
        try:
            current = current_revision(engine)
        except SQLAlchemyError as err:
            problem = f"can't read the database {redacted(url)} ({_cause(err)})"
            raise _DatabaseError(problem) from None
        finally:
            engine.dispose()
    except _DatabaseError as err:
        print(f"kasauti: {err}", file=sys.stderr)
        return 1
    head = head_revision()
    print(f"{redacted(url)}: schema {current or 'none'}, this version needs {head}")
    # Non-zero when behind, so scripts and health checks can act on it.
    return 0 if current == head else 1


def _cause(err: Exception) -> str:
    """The driver error's kind, e.g. ``OperationalError``. Not its text: that may echo the
    URL, and so the password."""
    orig = getattr(err, "orig", None)
    return type(orig if orig is not None else err).__name__


def _data_dir() -> Path:
    return Path(os.environ.get(DATA_DIR_ENV) or "var")


def _port(text: str) -> int:
    port = int(text)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{port} is not a TCP port")
    return port


def _workers(text: str) -> int:
    workers = int(text)
    if not 0 <= workers <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"{workers} isn't between 0 and {MAX_WORKERS}")
    return workers


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

    srv = sub.add_parser("serve", help="run the web API on this machine (loopback only)")
    srv.add_argument("--host", default="127.0.0.1", help="127.0.0.1 or localhost (the default)")
    srv.add_argument("--port", type=_port, default=8000, help="TCP port (default: 8000)")
    srv.add_argument("--packs", type=Path, default=Path("packs"), help="knowledge base root")
    data_help = (
        f"where the SQLite database lives (default: ${DATA_DIR_ENV} or ./var); "
        "PostgreSQL is set with $KASAUTI_DATABASE_URL instead"
    )
    srv.add_argument("--data-dir", type=Path, default=None, help=data_help)
    srv.add_argument(
        "--workers",
        type=_workers,
        default=None,
        help="processes running background jobs (default: 2, or 1 below 4 CPUs; 0 for none)",
    )

    db = sub.add_parser("db", help="the database's schema")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    for name, text in (
        ("upgrade", "migrate the database to this version's schema"),
        ("status", "show the database's schema (exit 1 if it needs an upgrade)"),
    ):
        cmd = db_sub.add_parser(name, help=text)
        cmd.add_argument("--data-dir", type=Path, default=None, help=data_help)

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
    if getattr(args, "data_dir", False) is None:
        args.data_dir = _data_dir()
    if args.command == "serve" and args.workers is None:
        from kasauti.jobs import default_workers  # noqa: PLC0415

        args.workers = default_workers()
    if args.command == "audit":
        args.framework = args.framework or ["nist"]
        return _audit(args)
    if args.command == "serve":
        return _serve(args)
    if args.command == "db":
        return _db(args)
    if args.command == "packs" and args.packs_command == "validate":
        return _validate_packs(args.root)
    return 2  # pragma: no cover - argparse enforces the choices above


if __name__ == "__main__":
    sys.exit(main())
