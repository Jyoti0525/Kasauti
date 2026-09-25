"""Evaluation metrics (PLAN §21.3).

Every metric returns a :class:`Ratio` (numerator and denominator), never a bare percentage, so
a report can't show "100%" for 0/0. We publish the numbers we get, including misses (P4).
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Ratio:
    num: int
    den: int

    @property
    def value(self) -> float | None:
        return None if self.den == 0 else self.num / self.den

    def __str__(self) -> str:
        v = self.value
        return f"{self.num}/{self.den} (n/a)" if v is None else f"{self.num}/{self.den} ({v:.1%})"


# A verdict, not a password (hence the S105/B105 suppressions).
PASS = "PASS"  # noqa: S105  # nosec B105


def false_pass_rate(expected: Sequence[str], actual: Sequence[str]) -> Ratio:
    """Share of cases that should *not* pass but were reported PASS. Target: 0 (§21.3).

    This is the metric that matters most in a security audit: a false PASS tells an operator
    a weakness isn't there.
    """
    _same_length(expected, actual)
    should_not_pass = [a for e, a in zip(expected, actual, strict=True) if e != PASS]
    return Ratio(sum(a == PASS for a in should_not_pass), len(should_not_pass))


@dataclass(frozen=True, slots=True)
class PrecisionRecall:
    precision: Ratio
    recall: Ratio


def detection(expected_violations: Collection[str], detected: Collection[str]) -> PrecisionRecall:
    """Precision/recall of violation detection on E3 (mutation set). Items are case ids."""
    exp, got = set(expected_violations), set(detected)
    hit = len(exp & got)
    return PrecisionRecall(precision=Ratio(hit, len(got)), recall=Ratio(hit, len(exp)))


def coverage(understood: Collection[str], relevant: Collection[str]) -> Ratio:
    """Share of security-relevant statements that an approved mapping understood."""
    rel = set(relevant)
    return Ratio(len(rel & set(understood)), len(rel))


def recall_at_k(ranked: Sequence[Sequence[str]], gold: Sequence[str], k: int) -> Ratio:
    """Suggestion quality on E2: the correct attribute is among the top-k suggestions."""
    if k < 1:
        raise ValueError("k must be >= 1")
    _same_length(ranked, gold)
    return Ratio(sum(g in r[:k] for r, g in zip(ranked, gold, strict=True)), len(gold))


@dataclass(frozen=True, slots=True)
class FixOutcome:
    """One E4 case: did the fix flip its target FAIL -> PASS without regressing anything?"""

    case_id: str
    target_flipped: bool
    regressions: int


def fix_success(outcomes: Sequence[FixOutcome]) -> Ratio:
    ok = sum(o.target_flipped and o.regressions == 0 for o in outcomes)
    return Ratio(ok, len(outcomes))


def _same_length(a: Sequence[object], b: Sequence[object]) -> None:
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)}")
