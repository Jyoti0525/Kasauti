"""Statuses and scoring (PLAN §12.6; TODO M1.12). Always two numbers.

* A rule's status on a device is its worst finding: FAIL > REVIEW > PASS > N/A.
* **Compliance %** = PASS / (PASS + FAIL) over applicable rules.
* **Coverage %** = (PASS + FAIL) / applicable rules: how much could actually be judged.
* A NIST control rolls up from the rules that cite it: all PASS -> satisfied; some FAIL and
  some PASS -> partially satisfied; all judged ones FAIL -> not satisfied; otherwise
  undetermined (REVIEW) or not applicable.

Nobody should read "100 % compliant" without seeing "on 10 % coverage".
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from kasauti.rules.model import Finding, Rule, Status

_RANK = {Status.FAIL: 3, Status.REVIEW: 2, Status.PASS: 1, Status.NOT_APPLICABLE: 0}

NIST = "nist_800_53r5"
FRAMEWORKS = {NIST: "NIST SP 800-53 Rev. 5"}


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


def in_framework(rule: Rule, framework: str) -> bool:
    if framework == NIST:
        return bool(rule.refs.nist_800_53r5)
    raise KeyError(f"framework {framework!r} lands with its pack (TODO M2.57-M2.60)")


def framework_score(rules: Sequence[Rule], statuses: dict[str, Status], framework: str) -> Score:
    return score(statuses[r.id] for r in rules if in_framework(r, framework))


class ControlStatus(StrEnum):
    SATISFIED = "satisfied"
    PARTIALLY_SATISFIED = "partially satisfied"
    NOT_SATISFIED = "not satisfied"
    UNDETERMINED = "undetermined"
    NOT_APPLICABLE = "not applicable"


def nist_controls(
    rules: Sequence[Rule], statuses: dict[str, Status]
) -> dict[str, tuple[ControlStatus, tuple[str, ...]]]:
    """Control id -> (roll-up status, the rules behind it), in control order."""
    by_control: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        for control in r.refs.nist_800_53r5:
            by_control[control].append(r.id)
    out: dict[str, tuple[ControlStatus, tuple[str, ...]]] = {}
    for control in sorted(by_control, key=control_sort_key):
        ids = tuple(sorted(by_control[control]))
        out[control] = (_roll_up([statuses[i] for i in ids]), ids)
    return out


def _roll_up(statuses: list[Status]) -> ControlStatus:
    judged = [s for s in statuses if s in (Status.PASS, Status.FAIL)]
    if Status.FAIL in judged:
        return (
            ControlStatus.PARTIALLY_SATISFIED
            if Status.PASS in judged
            else ControlStatus.NOT_SATISFIED
        )
    if Status.REVIEW in statuses:
        return ControlStatus.UNDETERMINED
    if judged:
        return ControlStatus.SATISFIED
    return ControlStatus.NOT_APPLICABLE


def control_sort_key(control: str) -> tuple[str, int, int]:
    """``AC-2`` < ``AC-2(1)`` < ``AC-17``."""
    family, _, rest = control.partition("-")
    number, _, enh = rest.partition("(")
    return (family, int(number or 0), int(enh.rstrip(")") or 0))
