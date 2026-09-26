"""The pipeline core's ports (PLAN §4.1, §4.2).

The core is pure: each stage takes values and returns values, with no file, network or clock
access. The web API, CLI and worker processes are adapters that do the I/O and call these
stages. That is what makes audits reproducible (same input + same KB version + same rule-set
version -> byte-identical results, §3.1) and lets one core serve both ``kasauti audit`` and the
server.

::

    raw text ─► ShapeParser ─► ConfigTree ─► Mapper ─► SBM (+ unmapped statements)
            ─► Evaluator ─► findings ─► Remediator ─► fixes ─► Reporter

The concrete stages: :func:`kasauti.shape.parse.parse_text`,
:func:`kasauti.mapping.engine.apply_mappings`, :func:`kasauti.rules.engine.evaluate_rules`,
orchestrated for one device by :func:`kasauti.audit.audit`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from kasauti.ingest.model import Artifact
from kasauti.mapping.engine import MappingResult
from kasauti.packs.loader import RuleSet, VendorPack
from kasauti.rules.model import Finding
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.shape.model import ConfigTree

__all__ = ["Artifact", "Evaluator", "Mapper", "MappingResult", "ShapeParser"]


class ShapeParser(Protocol):
    def __call__(self, artifact: Artifact) -> ConfigTree: ...


class Mapper(Protocol):
    def __call__(
        self, tree: ConfigTree, pack: VendorPack, companions: Sequence[ConfigTree]
    ) -> MappingResult: ...


class Evaluator(Protocol):
    def __call__(self, sbm: SecurityBaselineModel, rules: RuleSet) -> tuple[Finding, ...]: ...
