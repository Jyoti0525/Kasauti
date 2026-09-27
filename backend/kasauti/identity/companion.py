"""Companion files: command outputs that come with a configuration (PLAN §5.1, §7; TODO M2.05).

A running configuration rarely holds a device's serial number or hardware; ``show version``,
``show inventory``, ``show chassis hardware`` and their kin do. They are the second source of
identity in PLAN §7's order, after live facts and before the configuration itself.

Everything vendor-specific is pack data (R-08): each pack's ``identity.yaml`` says how to
recognise each output it reads (signatures scored like the vendor fingerprint), which fields it
holds (mapping-language patterns or RE2 regexes) and how its hardware components are listed
(RE2 records). Not TextFSM templates: TextFSM runs Python's backtracking ``re`` over the
device output, and every expression that meets untrusted text here is RE2 (linear time).

A companion is parsed as flat text, one statement per line, so the same patterns that read a
configuration read it; its evidence points at its own file and line.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from kasauti.identity.detect import Detection, choose, score
from kasauti.ingest.mask import mask_secrets
from kasauti.ingest.model import Artifact
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import CompanionKind
from kasauti.rules import regex
from kasauti.shape.model import ConfigTree, ShapeFamily
from kasauti.shape.parse import parse_text
from kasauti.shape.tokens import joined_lines

COMMANDS: dict[str, str] = {
    "show_version": "`show version`",
    "show_inventory": "`show inventory`",
    "get_system_status": "`get system status`",
    "show_system_info": "`show system info`",
    "show_chassis_hardware": "`show chassis hardware`",
    "display_version": "`display version`",
    "display_esn": "`display esn`",
}
"""How each companion kind is named to the user: the command that prints it."""


@dataclass(frozen=True, slots=True)
class Companion:
    """A companion output recognised for one pack, parsed and ready to read."""

    name: str
    sha256: str
    kind: CompanionKind
    text: str
    tree: ConfigTree
    detection: Detection


@dataclass(frozen=True, slots=True)
class Component:
    """One hardware component a companion lists (R-07a)."""

    name: str
    serial: str
    description: str | None
    part: str | None
    version: str | None
    file: str
    line: int
    kind: CompanionKind


def recognise(text: str, pack: VendorPack) -> Detection | None:
    """Which of ``pack``'s companion outputs ``text`` is (the detection's ``pack_id`` holds
    the kind), or None: nothing reaches its threshold, or two kinds tie."""
    joined = joined_lines(text)
    found = sorted(
        (score(text, spec, kind, joined=joined) for kind, spec in pack.identity.companions.items()),
        key=lambda d: (-d.score, d.pack_id),
    )
    return choose(found)


def classify(text: str, packs: Sequence[VendorPack]) -> tuple[VendorPack, Detection] | None:
    """Which pack's companion output ``text`` is, across ``packs``: the single best, or None
    if nothing is confident or two packs tie."""
    best: list[tuple[VendorPack, Detection]] = []
    for pack in packs:
        found = recognise(text, pack)
        if found is not None:
            best.append((pack, found))
    best.sort(key=lambda pd: (-pd[1].score, pd[0].manifest.id))
    if not best or (len(best) > 1 and best[1][1].score == best[0][1].score):
        return None
    return best[0]


def read(artifact: Artifact, detection: Detection) -> Companion:
    kind: CompanionKind = detection.pack_id  # type: ignore[assignment]
    tree = parse_text(
        artifact.text, source_file=artifact.name, family=ShapeFamily.FLAT, sha256=artifact.sha256
    )
    return Companion(artifact.name, artifact.sha256, kind, artifact.text, tree, detection)


def components(companions: Sequence[Companion], pack: VendorPack) -> tuple[Component, ...]:
    """Every hardware component the companions list, by the pack's ``inventory`` records, in
    file and line order. Text is masked like all evidence; a component with no serial is
    left out (fan trays, empty slots)."""
    out: list[Component] = []
    for companion in companions:
        for record in pack.identity.inventory:
            if record.source != companion.kind:
                continue
            for start, groups in regex.records(record.record, companion.text):
                serial = groups.get("serial", "").strip()
                if not serial or serial in record.not_serials:
                    continue
                out.append(
                    Component(
                        name=_clean(groups.get("name")) or "",
                        serial=serial,
                        description=_clean(groups.get("description")),
                        part=_clean(groups.get("part")),
                        version=_clean(groups.get("version")),
                        file=companion.name,
                        line=companion.text.count("\n", 0, start) + 1,
                        kind=companion.kind,
                    )
                )
    return tuple(sorted(out, key=lambda c: (c.file, c.line)))


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = mask_secrets(" ".join(value.split()))
    return value or None


__all__ = ["COMMANDS", "Companion", "Component", "classify", "components", "read", "recognise"]
