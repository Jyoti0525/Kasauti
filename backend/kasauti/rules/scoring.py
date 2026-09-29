"""Statuses and scoring (PLAN §12.6; TODO M1.12). Always two numbers.

* A rule's status on a device is its worst finding: FAIL > REVIEW > PASS > N/A.
* **Compliance %** = PASS / (PASS + FAIL) over applicable rules.
* **Coverage %** = (PASS + FAIL) / applicable rules: how much could actually be judged.
* A framework control rolls up from the rules mapped to it: all PASS -> satisfied; some FAIL
  and some PASS -> partially satisfied; all judged ones FAIL -> not satisfied; otherwise
  undetermined (REVIEW) or not applicable. A STIG rule is one requirement, open or not, so any
  FAIL leaves it not satisfied (``atomic``).
* How far a rule decides a control (``Coverage``) bounds what its verdict proves: a rule that
  checks only part of a control can fail it but never satisfy it alone; one stricter than the
  control can satisfy it but never fail it alone. The framework's two numbers count the same
  way, so a STIG's Coverage % shows how much of it the checks really settle.

Nobody should read "100 % compliant" without seeing "on 10 % coverage".
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from kasauti.rules.model import Finding, Rule, Status

_RANK = {Status.FAIL: 3, Status.REVIEW: 2, Status.PASS: 1, Status.NOT_APPLICABLE: 0}

NIST = "nist_800_53r5"
FRAMEWORKS = {
    NIST: "NIST SP 800-53 Rev. 5",
    "disa_stig": "DISA STIG",
    "iso_27001_2022": "ISO/IEC 27001:2022",
}


def rule_status(findings: Iterable[Finding]) -> Status:
    worst = Status.NOT_APPLICABLE
    for f in findings:
        if _RANK[f.status] > _RANK[worst]:
            worst = f.status
    return worst


def rule_statuses(rules: Sequence[Rule], findings: Sequence[Finding]) -> dict[str, Status]:
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)
    return {r.id: rule_status(by_rule.get(r.id, ())) for r in rules}


@dataclass(frozen=True, slots=True)
class Score:
    passed: int
    failed: int
    review: int
    not_applicable: int

    @property
    def applicable(self) -> int:
        return self.passed + self.failed + self.review

    @property
    def compliance_pct(self) -> float | None:
        judged = self.passed + self.failed
        return None if judged == 0 else round(100.0 * self.passed / judged, 1)

    @property
    def coverage_pct(self) -> float | None:
        if self.applicable == 0:
            return None
        return round(100.0 * (self.passed + self.failed) / self.applicable, 1)


def score(statuses: Iterable[Status]) -> Score:
    counts = dict.fromkeys(Status, 0)
    for s in statuses:
        counts[s] += 1
    return Score(
        counts[Status.PASS],
        counts[Status.FAIL],
        counts[Status.REVIEW],
        counts[Status.NOT_APPLICABLE],
    )


class Coverage(StrEnum):
    FULL = "full"
    PART = "part"
    STRICTER = "stricter"


@dataclass(frozen=True, slots=True)
class Cited:
    """A control a rule is mapped to, and how much of it the rule decides."""

    control: str
    covers: Coverage = Coverage.FULL


def nist_citations(rules: Sequence[Rule]) -> dict[str, tuple[Cited, ...]]:
    """NIST, the hub: each rule's own anchors, each decided in full."""
    return {r.id: tuple(Cited(c) for c in r.refs.nist_800_53r5) for r in rules}


def framework_score(statuses: dict[str, Status], cited: dict[str, tuple[Cited, ...]]) -> Score:
    """Over the rules mapped to at least one of the framework's controls. A verdict counts only
    as far as it decides them: a PASS on a rule that checks only part of every control it maps to
    is left for review, and so is a FAIL on a rule stricter than all of them. Coverage then shows
    how much of the framework the checks really settle."""
    return score(
        _as_evidence(statuses[rule], controls) for rule, controls in cited.items() if controls
    )


def _as_evidence(status: Status, controls: tuple[Cited, ...]) -> Status:
    if status is Status.PASS and all(c.covers is Coverage.PART for c in controls):
        return Status.REVIEW
    if status is Status.FAIL and all(c.covers is Coverage.STRICTER for c in controls):
        return Status.REVIEW
    return status


class ControlStatus(StrEnum):
    SATISFIED = "satisfied"
    PARTIALLY_SATISFIED = "partially satisfied"
    NOT_SATISFIED = "not satisfied"
    UNDETERMINED = "undetermined"
    NOT_APPLICABLE = "not applicable"


@dataclass(frozen=True, slots=True)
class Rolled:
    status: ControlStatus
    rules: tuple[str, ...]
    partial: bool
    """Undetermined because the passing rules check only part of the control."""


def control_matrix(
    cited: dict[str, tuple[Cited, ...]],
    statuses: dict[str, Status],
    *,
    order: Callable[[str], Any],
    atomic: bool = False,
) -> dict[str, Rolled]:
    """Control id -> its roll-up and the rules behind it, in ``order``."""
    by_control: dict[str, list[tuple[str, Coverage]]] = defaultdict(list)
    for rule, controls in cited.items():
        for c in controls:
            by_control[c.control].append((rule, c.covers))
    out: dict[str, Rolled] = {}
    for control in sorted(by_control, key=order):
        pairs = sorted(by_control[control])
        status, partial = _roll_up([(statuses[r], cov) for r, cov in pairs], atomic=atomic)
        out[control] = Rolled(status, tuple(dict.fromkeys(r for r, _ in pairs)), partial)
    return out


def nist_controls(
    rules: Sequence[Rule], statuses: dict[str, Status]
) -> dict[str, tuple[ControlStatus, tuple[str, ...]]]:
    """NIST control id -> (roll-up status, the rules behind it), in control order."""
    rolled = control_matrix(nist_citations(rules), statuses, order=control_sort_key)
    return {c: (r.status, r.rules) for c, r in rolled.items()}


def _roll_up(
    verdicts: list[tuple[Status, Coverage]], *, atomic: bool
) -> tuple[ControlStatus, bool]:
    breaks = [s for s, cov in verdicts if s is Status.FAIL and cov is not Coverage.STRICTER]
    passes = [s for s, _ in verdicts if s is Status.PASS]
    if breaks:
        partly = bool(passes) and not atomic
        return (ControlStatus.PARTIALLY_SATISFIED if partly else ControlStatus.NOT_SATISFIED), False
    if any(s is Status.REVIEW or s is Status.FAIL for s, _ in verdicts):
        return ControlStatus.UNDETERMINED, False
    if any(s is Status.PASS and cov is not Coverage.PART for s, cov in verdicts):
        return ControlStatus.SATISFIED, False
    if passes:
        return ControlStatus.UNDETERMINED, True
    return ControlStatus.NOT_APPLICABLE, False


def control_sort_key(control: str) -> tuple[str, int, int]:
    """``AC-2`` < ``AC-2(1)`` < ``AC-17``."""
    family, _, rest = control.partition("-")
    number, _, enh = rest.partition("(")
    return (family, int(number or 0), int(enh.rstrip(")") or 0))
