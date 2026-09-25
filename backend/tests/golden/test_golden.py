"""Golden regression (PLAN §21.1 E1, TODO M1.16).

Each case in ``datasets/golden/<case>/`` holds an input config and the hand-verified expected
SBM snapshot and verdicts. The audit must reproduce them byte for byte. The first case lands
with the M1 walking skeleton; until then this collects nothing and CI stays green honestly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parents[3] / "datasets" / "golden"
CASES = sorted(p for p in GOLDEN.glob("*/") if (p / "case.yaml").exists())


@pytest.mark.golden
@pytest.mark.parametrize("case_dir", CASES, ids=[c.name for c in CASES])
def test_golden_case(case_dir: Path) -> None:  # pragma: no cover - first case arrives in M1.16
    from kasauti.pipeline import run_golden_case  # noqa: PLC0415

    run_golden_case(case_dir)
