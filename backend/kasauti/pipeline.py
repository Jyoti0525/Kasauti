"""The pipeline core's ports (PLAN §4.1, §4.2).

The core is pure: each stage takes values and returns values, with no file, network or clock
access. The web API, CLI and worker processes are adapters that do the I/O and call these
stages. That is what makes audits reproducible (same input + same KB version + same rule-set
version -> byte-identical results, §3.1) and lets one core serve both ``kasauti audit`` and the
server.

::

    raw text ─► ShapeParser ─► ConfigTree ─► Mapper ─► SBM (+ unmapped statements)
            ─► Evaluator ─► findings ─► Remediator ─► fixes ─► Reporter
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from kasauti.packs.loader import RuleSet, VendorPack
from kasauti.rules.model import Finding
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.shape.model import ConfigTree, Statement


@dataclass(frozen=True)
class Artifact:
    """One ingested file after validation and hashing (the ingest adapter builds it)."""

    name: str
    text: str
    sha256: str
    kind: str
    """``config`` or a companion kind such as ``show_version`` (§5.1)."""


@dataclass(frozen=True)
class MappingResult:
    sbm: SecurityBaselineModel
    unmapped: tuple[Statement, ...]
    """Security-relevant statements no approved mapping understood -> Training Studio."""


@dataclass(frozen=True)
class Coverage:
    """Compliance % and Coverage % are always reported together (§12.6)."""

    passed: int
    failed: int
    applicable: int

    @property
    def compliance_pct(self) -> float | None:
        judged = self.passed + self.failed
        return None if judged == 0 else 100.0 * self.passed / judged

    @property
    def coverage_pct(self) -> float | None:
        return (
            None if self.applicable == 0 else 100.0 * (self.passed + self.failed) / self.applicable
        )


class ShapeParser(Protocol):
    def __call__(self, artifact: Artifact) -> ConfigTree: ...


class Mapper(Protocol):
    def __call__(
        self, tree: ConfigTree, pack: VendorPack, companions: Sequence[ConfigTree]
    ) -> MappingResult: ...


class Evaluator(Protocol):
    def __call__(self, sbm: SecurityBaselineModel, rules: RuleSet) -> tuple[Finding, ...]: ...
