"""Vendor/OS fingerprinting from each pack's ``detect.yaml`` (PLAN §7; TODO M2.18).

Every signature that matches adds its weight once. The best pack wins if it reaches its
``min_score`` and no other pack ties with it; otherwise the operator must choose (the CLI's
``--vendor``), because auditing a config against the wrong vendor's mappings would produce
confident nonsense.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from kasauti.ingest.mask import mask_secrets
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import Signature
from kasauti.rules import regex
from kasauti.sbm.facts import Evidence
from kasauti.shape.model import ConfigTree
from kasauti.shape.parse import parse_text
from kasauti.shape.tokens import split_lines


@dataclass(frozen=True, slots=True)
class Detection:
    pack_id: str
    score: float
    min_score: float
    matched: tuple[tuple[str, int], ...]
    """(signature id, 1-based line) for every signature that matched."""

    @property
    def confident(self) -> bool:
        return self.score >= self.min_score


def score_pack(text: str, pack: VendorPack, tree: ConfigTree | None = None) -> Detection:
    lines = split_lines(text)
    matched: list[tuple[str, int]] = []
    for sig in pack.detect.signatures:
        line = _match(sig, text, lines, tree)
        if line is not None:
            matched.append((sig.id, line))
    weights = {s.id: s.weight for s in pack.detect.signatures}
    total = round(sum(weights[sid] for sid, _ in matched), 6)
    return Detection(pack.manifest.id, total, pack.detect.min_score, tuple(matched))


def detect_vendor(text: str, packs: Sequence[VendorPack]) -> list[Detection]:
    """All packs, best first (ties broken by pack id, so the order is deterministic)."""
    trees: dict[str, ConfigTree] = {}
    out: list[Detection] = []
    for pack in packs:
        family = pack.manifest.shape_family
        if family not in trees:
            trees[family] = parse_text(text, source_file="detect", family=family)
        out.append(score_pack(text, pack, trees[family]))
    return sorted(out, key=lambda d: (-d.score, d.pack_id))


def choose(detections: Sequence[Detection]) -> Detection | None:
    """The single confident winner, or None if nothing is confident or the top two tie."""
    if not detections or not detections[0].confident:
        return None
    if len(detections) > 1 and detections[1].score == detections[0].score:
        return None
    return detections[0]


def detection_evidence(detection: Detection, text: str, source_file: str) -> tuple[Evidence, ...]:
    lines = split_lines(text)
    return tuple(
        Evidence(
            file=source_file,
            line_start=line,
            line_end=line,
            raw=mask_secrets(lines[line - 1].strip()),
        )
        for line in sorted({ln for _, ln in detection.matched})
    )


def _match(sig: Signature, text: str, lines: list[str], tree: ConfigTree | None) -> int | None:
    match sig.kind:
        case "contains":
            pos = text.find(sig.pattern)
            return None if pos < 0 else text.count("\n", 0, pos) + 1
        case "line_prefix":
            return next(
                (i for i, ln in enumerate(lines, 1) if ln.lstrip().startswith(sig.pattern)), None
            )
        case "regex":
            return next((i for i, ln in enumerate(lines, 1) if regex.search(sig.pattern, ln)), None)
        case "json_key" | "xml_path":
            return _structured(sig.pattern, tree)


def _structured(pattern: str, tree: ConfigTree | None) -> int | None:
    """``DEVICE_METADATA.localhost`` or ``devices/entry/deviceconfig``: a run of element/key
    names, matched against each statement's path followed by its first token."""
    if tree is None:
        return None
    want = tuple(p for p in pattern.replace("/", ".").split(".") if p)
    for stmt in tree.statements:
        names = (*(block.split(" ", 1)[0] for block in stmt.path), stmt.tokens[0])
        for i in range(len(names) - len(want) + 1):
            if names[i : i + len(want)] == want:
                return stmt.line_start
    return None
