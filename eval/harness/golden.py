"""Golden regression, E1 (PLAN §21.1, §21.3; TODO M1.16, M1.17).

A case is a directory ``datasets/golden/<case>/`` holding:

* ``case.yaml``: the input (a path under ``datasets/`` plus its SHA-256), optionally the vendor
  pack, and ``expected_statuses``: the verdict for every rule, **labelled by hand from the
  dataset's documented weaknesses, never copied from the engine**;
* ``expected.json``: the engine's full audit result, reviewed by hand when it changes.

Two checks with different jobs:

1. **Ground truth.** Each rule's status must equal the hand label. A rule reported PASS whose
   label is FAIL or REVIEW is a *false PASS*, the one error a security audit can't make, and
   is reported separately (target: zero, §21.3).
2. **Snapshot.** The result must be byte-identical to ``expected.json``. Any change to facts,
   evidence or wording shows up as a diff to review. ``--update`` rewrites snapshots (only);
   the hand labels are never rewritten by tooling.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from harness.metrics import Ratio, false_pass_rate
from kasauti.audit import KnowledgeBase, audit, load_kb
from kasauti.ingest.read import decode

REPO = Path(__file__).resolve().parents[2]
DATASETS = REPO / "datasets"
GOLDEN = DATASETS / "golden"
PACKS = REPO / "packs"
VERDICTS = frozenset({"PASS", "FAIL", "REVIEW", "N/A"})


@dataclass(frozen=True)
class Case:
    name: str
    root: Path
    input: Path
    input_sha256: str
    vendor: str | None
    frameworks: tuple[str, ...]
    expected: dict[str, str]


@dataclass
class CaseResult:
    case: str
    mismatches: list[str] = field(default_factory=list)
    false_passes: list[str] = field(default_factory=list)
    snapshot_diff: str = ""
    expected: list[str] = field(default_factory=list)
    actual: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.mismatches or self.false_passes or self.snapshot_diff)


def cases(root: Path = GOLDEN) -> list[Path]:
    return sorted(p for p in root.glob("*/") if (p / "case.yaml").is_file())


def load_case(case_dir: Path) -> Case:
    raw: dict[str, Any] = yaml.safe_load((case_dir / "case.yaml").read_text(encoding="utf-8"))
    expected = {str(k): str(v) for k, v in raw["expected_statuses"].items()}
    bad = {k: v for k, v in expected.items() if v not in VERDICTS}
    if bad:
        raise ValueError(f"{case_dir.name}: unknown verdicts {bad}")
    return Case(
        name=case_dir.name,
        root=case_dir,
        input=DATASETS / raw["input"],
        input_sha256=raw["input_sha256"],
        vendor=raw.get("vendor"),
        frameworks=tuple(raw.get("frameworks", ["nist_800_53r5"])),
        expected=expected,
    )


def result_json(case: Case, kb: KnowledgeBase) -> str:
    data = case.input.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != case.input_sha256:
        raise ValueError(f"{case.name}: input changed (sha256 {digest}); re-label the case")
    artifact = decode(data, case.input.name)
    return audit(artifact, kb, vendor=case.vendor, frameworks=case.frameworks).canonical_json()


def run_case(case_dir: Path, kb: KnowledgeBase | None = None) -> CaseResult:
    case = load_case(case_dir)
    kb = kb or load_kb(PACKS)
    text = result_json(case, kb)
    statuses = {r["rule_id"]: r["status"] for r in json.loads(text)["rules"]}
    out = CaseResult(case.name)
    for rule_id in sorted(set(case.expected) | set(statuses)):
        want = case.expected.get(rule_id)
        got = statuses.get(rule_id)
        if want is None:
            out.mismatches.append(f"{rule_id}: no hand label (engine says {got}); label it")
            continue
        out.expected.append(want)
        out.actual.append(got or "missing")
        if got != want:
            out.mismatches.append(f"{rule_id}: expected {want}, got {got}")
            if got == "PASS":
                out.false_passes.append(rule_id)

    snapshot = case_dir / "expected.json"
    stored = snapshot.read_text(encoding="utf-8") if snapshot.exists() else ""
    if stored != text:
        diff = difflib.unified_diff(
            stored.splitlines(), text.splitlines(), "expected.json", "actual", lineterm="", n=2
        )
        out.snapshot_diff = "\n".join(list(diff)[:200]) or "(snapshot missing)"
    return out


def update_snapshot(case_dir: Path, kb: KnowledgeBase | None = None) -> bool:
    """Rewrite ``expected.json``. Returns True if it changed. Hand labels are not touched."""
    case = load_case(case_dir)
    text = result_json(case, kb or load_kb(PACKS))
    snapshot = case_dir / "expected.json"
    changed = not snapshot.exists() or snapshot.read_text(encoding="utf-8") != text
    snapshot.write_text(text, encoding="utf-8", newline="\n")
    return changed


def false_pass_ratio(results: list[CaseResult]) -> Ratio:
    expected = [e for r in results for e in r.expected]
    actual = [a for r in results for a in r.actual]
    return false_pass_rate(expected, actual)
