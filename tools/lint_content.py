"""Content gates run in CI (PLAN §12.2, §12.4; docs/TODO.md M0.08, M2.46, M2.57).

Rule quality gate. Beyond what the schema already enforces, every rule must *explicitly*
state its ``on_absent`` and ``on_unknown`` semantics and its ``fix_intent``, and must ship at
least one passing and one failing fixture that exists on disk. Each fixture is then audited:
a ``pass`` fixture must make the rule PASS and a ``fail`` fixture must make it FAIL, so a
fixture can't silently stop testing what it claims to. The fixture's first path component is
the vendor pack (``cisco_ios_xe/weak.cfg``).
(Per-seed-vendor fixture completeness is added in M2.46 once more seed packs exist.)

Crosswalk lint. No rule may cite a control ID that isn't in an imported official catalog;
every crosswalk entry must name an existing rule and existing controls.

Usage: ``uv run python tools/lint_content.py [--packs packs] [--fixtures datasets/authored]``
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from kasauti.audit import AuditError, audit, load_kb
from kasauti.ingest.read import IngestError, read_file
from kasauti.packs.loader import FrameworkPack, PackError, load_framework_pack, load_ruleset

NIST = "nist_800_53r5"
EXPLICIT_KEYS = ("on_absent", "on_unknown", "fix_intent")


def rule_quality(packs: Path, fixtures: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted((packs / "rules").glob("*.yaml")):
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in raw.get("rules", []):
            rid = rule.get("id", "?")
            problems += [
                f"{path.name}: {rid}: `{key}` must be stated explicitly (§12.2)"
                for key in EXPLICIT_KEYS
                if key not in rule
            ]
            fx = rule.get("fixtures") or {}
            for kind in ("pass", "fail"):
                files = fx.get(kind) or []
                if not files:
                    problems.append(f"{path.name}: {rid}: needs at least one `{kind}` fixture")
                problems += [
                    f"{path.name}: {rid}: fixture {f} not found under {fixtures}"
                    for f in files
                    if not (fixtures / f).is_file()
                ]
    return problems


def fixture_verdicts(packs: Path, fixtures: Path) -> list[str]:
    """Audit every fixture once and check each rule's verdict on it."""
    try:
        kb = load_kb(packs)
    except PackError as err:
        return [f"knowledge base: {p}" for p in err.problems]
    statuses: dict[str, dict[str, str]] = {}
    problems: list[str] = []
    for rule in kb.ruleset.rules:
        for want, files in (("PASS", rule.fixtures.pass_), ("FAIL", rule.fixtures.fail)):
            for rel in files:
                path = fixtures / rel
                if not path.is_file():
                    continue  # reported by rule_quality
                if rel not in statuses:
                    try:
                        result = audit(read_file(path), kb, vendor=rel.split("/", 1)[0])
                    except (IngestError, AuditError) as err:
                        problems.append(f"fixture {rel}: {err}")
                        statuses[rel] = {}
                        continue
                    statuses[rel] = {r.rule_id: r.status.value for r in result.rules}
                got = statuses[rel].get(rule.id)
                if got is not None and got != want:
                    problems.append(f"{rule.id}: {want.lower()} fixture {rel} gives {got}")
    return problems


def crosswalk_lint(packs: Path) -> list[str]:
    problems: list[str] = []
    try:
        ruleset = load_ruleset(packs / "rules", packs / "derivations")
    except PackError as err:
        return [f"rules: {p}" for p in err.problems]
    frameworks: dict[str, FrameworkPack] = {}
    for fw_dir in sorted((packs / "frameworks").glob("*/")):
        try:
            fw = load_framework_pack(fw_dir)
        except PackError as err:
            problems += [f"{fw_dir.name}: {p}" for p in err.problems]
            continue
        frameworks[fw.catalog.framework] = fw

    rule_ids = {r.id for r in ruleset.rules}
    nist = frameworks.get(NIST)
    nist_ids = {c.id for c in nist.catalog.controls} if nist else set()
    for rule in ruleset.rules:
        cited = rule.refs.nist_800_53r5
        if cited and nist is None:
            problems.append(
                f"{rule.id}: cites NIST controls but no {NIST} catalog is imported "
                "(run tools/import_oscal.py)"
            )
        problems += [
            f"{rule.id}: {cid} is not in the official NIST SP 800-53 r5 catalog"
            for cid in cited
            if nist is not None and cid not in nist_ids
        ]

    for name, fw in frameworks.items():
        if fw.crosswalk is None:
            continue
        ids = {c.id for c in fw.catalog.controls}
        for entry in fw.crosswalk.entries:
            if entry.rule not in rule_ids:
                problems.append(f"{name} crosswalk: unknown rule {entry.rule}")
            problems += [
                f"{name} crosswalk: {entry.rule} -> {cid} is not in the {name} catalog"
                for cid in entry.controls
                if cid not in ids
            ]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--packs", type=Path, default=Path("packs"))
    parser.add_argument("--fixtures", type=Path, default=Path("datasets/authored"))
    args = parser.parse_args(argv)
    problems = (
        rule_quality(args.packs, args.fixtures)
        + crosswalk_lint(args.packs)
        + fixture_verdicts(args.packs, args.fixtures)
    )
    for p in problems:
        print(f"FAIL {p}")
    print("content gates: " + ("FAILED" if problems else "passed"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
