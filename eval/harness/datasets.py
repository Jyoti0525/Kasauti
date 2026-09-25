"""The evaluation datasets E1–E5 (PLAN §21.1)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class Dataset:
    id: str
    name: str
    contents: str
    purpose: str
    path: Path
    milestone: str
    """When the dataset is first populated (docs/TODO.md)."""

    def files(self) -> list[Path]:
        if not self.path.exists():
            return []
        return sorted(p for p in self.path.rglob("*") if p.is_file() and p.name != ".gitkeep")


DATASETS: tuple[Dataset, ...] = (
    Dataset(
        "E1",
        "Golden set",
        "Authored + Batfish configs with hand-verified SBM snapshots and verdicts",
        "Correctness, regression gate",
        REPO / "datasets" / "golden",
        "M1.16",
    ),
    Dataset(
        "E2",
        "Mapping set",
        "400-600 labelled (statement -> attribute) pairs across seeds + Huawei",
        "Suggestion quality; model selection",
        REPO / "datasets" / "mapping_pairs",
        "M3.10",
    ),
    Dataset(
        "E3",
        "Mutation set",
        "Hardened configs x catalogued violation operators (per vendor)",
        "Detection precision/recall",
        REPO / "datasets" / "mutations",
        "M4.23",
    ),
    Dataset(
        "E4",
        "Fix set",
        "Every E3 violation",
        "Fix success rate (re-audit verified)",
        REPO / "datasets" / "mutations",
        "M4.24",
    ),
    Dataset(
        "E5",
        "Policy set",
        "Synthetic rulesets with planted shadowing/redundancy/correlation + real examples",
        "Policy-analysis precision/recall",
        REPO / "datasets" / "policy",
        "M4.25",
    ),
)


def by_id(dataset_id: str) -> Dataset:
    for ds in DATASETS:
        if ds.id == dataset_id:
            return ds
    raise KeyError(dataset_id)
