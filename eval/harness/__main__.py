"""Evaluation harness entry point.

``uv run python -m harness status``            which evaluation datasets are populated
``uv run python -m harness golden``            run every E1 golden case (ground truth + snapshot)
``uv run python -m harness golden --update``   rewrite snapshots after reviewing the change
``uv run python -m harness lovo``              Studio suggestions on vendors held out (-> reports)
``uv run python -m harness teach``             teach Huawei one approval at a time (-> reports)
"""

from __future__ import annotations

import sys
from pathlib import Path

from harness import golden, lovo, teach
from harness.datasets import DATASETS
from kasauti.audit import load_kb

USAGE = "usage: python -m harness status | golden [--update] | lovo | teach"
REPORTS = Path(__file__).resolve().parents[1] / "reports"


def _status() -> int:
    print(f"{'id':<4} {'dataset':<13} {'files':>5}  populated in")
    for ds in DATASETS:
        print(f"{ds.id:<4} {ds.name:<13} {len(ds.files()):>5}  {ds.milestone}")
    return 0


def _golden(update: bool) -> int:
    kb = load_kb(golden.PACKS)
    if update:
        for case_dir in golden.cases():
            changed = golden.update_snapshot(case_dir, kb)
            print(f"{'updated' if changed else 'unchanged':<9} {case_dir.name}")
        print("review the diff (git diff datasets/golden) before committing")
        return 0
    results = [golden.run_case(c, kb) for c in golden.cases()]
    for r in results:
        print(f"{'ok  ' if r.ok else 'FAIL'} {r.case}")
        for line in r.mismatches:
            print(f"     {line}")
        if r.snapshot_diff:
            print("     snapshot differs:\n" + r.snapshot_diff)
    ratio = golden.false_pass_ratio(results)
    print(f"false PASS rate: {ratio}  (target 0)")
    return 0 if all(r.ok for r in results) else 1


def _lovo() -> int:
    return _write("lovo.md", lovo.markdown(lovo.run(), lovo.huawei()))


def _teach() -> int:
    return _write("huawei_teach.md", teach.markdown(*teach.run()))


def _write(name: str, text: str) -> int:
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / name).write_text(text, encoding="utf-8")
    print(text)
    return 0


def main(argv: list[str]) -> int:
    match argv:
        case ["lovo"]:
            return _lovo()
        case ["teach"]:
            return _teach()
        case ["status"]:
            return _status()
        case ["golden"]:
            return _golden(update=False)
        case ["golden", "--update"]:
            return _golden(update=True)
    print(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
