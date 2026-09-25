import json
from pathlib import Path

import pytest

from harness.datasets import DATASETS, by_id
from harness.metrics import (
    FixOutcome,
    Ratio,
    coverage,
    detection,
    false_pass_rate,
    fix_success,
    recall_at_k,
)
from harness.report import write_report


def test_false_pass_counts_only_cases_that_should_not_pass() -> None:
    r = false_pass_rate(["PASS", "FAIL", "REVIEW", "FAIL"], ["PASS", "PASS", "REVIEW", "FAIL"])
    assert (r.num, r.den) == (1, 3)


def test_zero_over_zero_is_not_a_percentage() -> None:
    assert Ratio(0, 0).value is None
    assert str(Ratio(0, 0)) == "0/0 (n/a)"
    assert str(Ratio(1, 4)) == "1/4 (25.0%)"


def test_detection_precision_recall() -> None:
    pr = detection({"a", "b", "c"}, {"b", "c", "d", "e"})
    assert (pr.precision.num, pr.precision.den) == (2, 4)
    assert (pr.recall.num, pr.recall.den) == (2, 3)


def test_coverage_and_recall_at_k() -> None:
    assert coverage({"l1", "l2", "x"}, {"l1", "l2", "l3"}) == Ratio(2, 3)
    ranked = [["a", "b"], ["c", "d"], ["e", "f"]]
    assert recall_at_k(ranked, ["b", "c", "z"], k=1) == Ratio(1, 3)
    assert recall_at_k(ranked, ["b", "c", "z"], k=2) == Ratio(2, 3)
    with pytest.raises(ValueError, match="k must be"):
        recall_at_k(ranked, ["a", "b", "c"], k=0)


def test_fix_success_requires_zero_regressions() -> None:
    outcomes = [FixOutcome("1", True, 0), FixOutcome("2", True, 1), FixOutcome("3", False, 0)]
    assert fix_success(outcomes) == Ratio(1, 3)


def test_datasets_registry() -> None:
    assert [d.id for d in DATASETS] == ["E1", "E2", "E3", "E4", "E5"]
    assert by_id("E3").milestone == "M4.23"


def test_report_written(tmp_path: Path) -> None:
    md = write_report(tmp_path, "run-1", "Smoke", {"false_pass": Ratio(0, 12)})
    assert "0/12 (0.0%)" in md.read_text(encoding="utf-8")
    data = json.loads((tmp_path / "run-1" / "report.json").read_text(encoding="utf-8"))
    assert data["metrics"]["false_pass"] == {"num": 0, "den": 12, "value": 0.0}
