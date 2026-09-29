"""The Studio's suggestions on vendors it has never seen must not get worse (PLAN §10.5 eval
gate, §21.3; TODO M3.16). Numbers: eval/reports/lovo.md, from `python -m harness lovo`."""

import os

import pytest

from harness import lovo, teach
from kasauti.semantic.embed import shared


@pytest.fixture(scope="module")
def results() -> lovo.Results:
    if shared() is None:
        if os.environ.get("KASAUTI_REQUIRE_MODEL"):
            pytest.fail("the embedding model isn't installed: run `kasauti models fetch`")
        pytest.skip("the embedding model isn't installed (`kasauti models fetch`)")
    return lovo.run()


def test_fused_suggestions_beat_the_lexicon_on_every_count(results: lovo.Results) -> None:
    fused, lexicon = results.scores["fused"]["all"], results.scores["lexicon"]["all"]
    assert fused.n == lexicon.n >= 90
    assert fused.r1 >= 0.70 > lexicon.r1
    assert fused.precision >= 0.95 > lexicon.precision
    (n, fused_false), (_, lexicon_false) = (
        results.false_offers["fused"],
        results.false_offers["lexicon"],
    )
    assert fused_false <= lexicon_false
    assert fused_false / n <= 0.17


def test_huawei_held_out_is_read_right(results: lovo.Results) -> None:
    rows = lovo.huawei()
    fused = next(r for r in rows if r.method == "fused")
    assert fused.with_meaning >= 27
    assert fused.right_first == fused.with_meaning
    assert fused.false_offers <= 1
    # The committed report is what the code measures (eval/reports/lovo.md).
    assert lovo.REPORT.read_text(encoding="utf-8") == lovo.markdown(results, rows)


def test_huawei_is_taught_with_the_suggestions_the_studio_makes(results: lovo.Results) -> None:
    """Every line the catalogue can express, taught by accepting the top suggestion (TODO
    M3.28; eval/reports/huawei_teach.md)."""
    steps, skipped = teach.run()
    assert not skipped
    assert len(steps) - 1 >= 23
    assert all(s.suggested for s in steps[1:])
    assert steps[-1].judged >= 11
    assert teach.REPORT.read_text(encoding="utf-8") == teach.markdown(steps, skipped)
