"""Golden regression and the zero-false-PASS gate (PLAN §21.1, §21.3; TODO M1.16, M1.17).

Each case in ``datasets/golden/<case>/`` carries hand-labelled verdicts and a reviewed snapshot;
see ``eval/harness/golden.py``. CI runs these with ``pytest -m golden``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness import golden
from kasauti.audit import KnowledgeBase, load_kb

CASES = golden.cases()


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(golden.PACKS)


def test_there_are_golden_cases() -> None:
    assert len(CASES) >= 2


@pytest.mark.golden
@pytest.mark.parametrize("case_dir", CASES, ids=[c.name for c in CASES])
def test_zero_false_pass(case_dir: Path, kb: KnowledgeBase) -> None:
    """The gate that must never be relaxed: no rule may PASS where the ground truth says it
    fails or needs review."""
    result = golden.run_case(case_dir, kb)
    assert not result.false_passes, f"FALSE PASS on {result.false_passes}"


@pytest.mark.golden
@pytest.mark.parametrize("case_dir", CASES, ids=[c.name for c in CASES])
def test_verdicts_match_ground_truth(case_dir: Path, kb: KnowledgeBase) -> None:
    result = golden.run_case(case_dir, kb)
    assert not result.mismatches, "\n".join(result.mismatches)


@pytest.mark.golden
@pytest.mark.parametrize("case_dir", CASES, ids=[c.name for c in CASES])
def test_snapshot_is_byte_identical(case_dir: Path, kb: KnowledgeBase) -> None:
    result = golden.run_case(case_dir, kb)
    assert not result.snapshot_diff, (
        "audit output changed; review it, then run `uv run python -m harness golden --update` "
        "from eval/\n" + result.snapshot_diff
    )
