"""Vendor/OS fingerprinting from each pack's ``detect.yaml`` (PLAN §7; TODO M2.18).

Every signature that matches adds its weight once. The best pack wins if it reaches its
``min_score`` and no other pack ties with it; otherwise the operator must choose (the CLI's
``--vendor``), because auditing a config against the wrong vendor's mappings would produce
confident nonsense. A pack's ``excludes`` rule it out whatever it scores: they name another OS
it isn't written for, whose own pack isn't installed to outscore it (NX-OS against IOS XE).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from kasauti.ingest.mask import mask_secrets
from kasauti.mapping.setform import absolute_view
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import DetectSpec, Exclusion, InputWarning, Signature
from kasauti.rules import regex
from kasauti.sbm.facts import Evidence
from kasauti.shape.model import ConfigTree
from kasauti.shape.parse import parse_text
from kasauti.shape.tokens import joined_lines, split_lines

_STRUCTURED = frozenset({"json_key", "xml_path"})
"""Signature kinds matched against the parsed tree rather than the text."""


@dataclass(frozen=True, slots=True)
class Detection:
    pack_id: str
    score: float
    min_score: float
    matched: tuple[tuple[str, int], ...]
    """(signature id, 1-based line) for every signature that matched."""
    excluded: tuple[tuple[str, int, str], ...] = ()
    """(exclusion id, 1-based line, message) for every ``excludes`` pattern that matched."""

    @property
    def confident(self) -> bool:
        return self.score >= self.min_score and not self.excluded

    def exclusion_note(self) -> str | None:
        """Why the pack is ruled out: the first exclusion that matched, with its line (NX-OS
        can match two, which say the same thing)."""
        if not self.excluded:
            return None
        _, line, message = self.excluded[0]
        return f"{message} (line {line})"


def score_pack(text: str, pack: VendorPack, tree: ConfigTree | None = None) -> Detection:
    found = score(text, pack.detect, pack.manifest.id, tree)
    return _from_the_top(found, text, pack, tree)


def _from_the_top(
    found: Detection, text: str, pack: VendorPack, tree: ConfigTree | None
) -> Detection:
    """A pack that takes CLI commands also scores the file as it reads from the top of the
    hierarchy: ``set host-name R1`` under an ``[edit system]`` banner is ``set system
    host-name R1``, and the pack's signatures are written for that. Line numbers are the
    file's own, line for line; the better score counts."""
    view = absolute_view(text, pack)
    if view is None:
        return found
    seen = score(view, pack.detect, pack.manifest.id, tree)
    return seen if seen.score > found.score else found


def score(
    text: str,
    spec: DetectSpec,
    name: str,
    tree: ConfigTree | None = None,
    joined: str | None = None,
) -> Detection:
    """How well ``text`` matches ``spec``'s signatures: a vendor's fingerprint, or a companion
    output's (``identity.yaml``). ``joined`` is :func:`joined_lines` of ``text``, if the
    caller already has it."""
    joined = joined_lines(text) if joined is None else joined
    matched: list[tuple[str, int]] = []
    for sig in spec.signatures:
        line = _match(sig, joined, tree)
        if line is not None:
            matched.append((sig.id, line))
    weights = {s.id: s.weight for s in spec.signatures}
    total = round(sum(weights[sid] for sid, _ in matched), 6)
    excluded = []
    for ex in spec.excludes:
        line = _match(ex, joined, tree)
        if line is not None:
            excluded.append((ex.id, line, ex.message))
    return Detection(name, total, spec.min_score, tuple(matched), tuple(excluded))


def detect_vendor(text: str, packs: Sequence[VendorPack]) -> list[Detection]:
    """All packs, best first (ties broken by pack id, so the order is deterministic); packs
    ruled out by their ``excludes`` come last.

    A pack's shape family is parsed only if one of its signatures reads structure: a parse is
    most of what an audit costs in time and memory, and text signatures don't need one."""
    trees: dict[str, ConfigTree] = {}
    out: list[Detection] = []
    joined = joined_lines(text)
    for pack in packs:
        tree = None
        kinds = [s.kind for s in pack.detect.signatures] + [e.kind for e in pack.detect.excludes]
        if any(kind in _STRUCTURED for kind in kinds):
            family = pack.manifest.shape_family
            if family not in trees:
                trees[family] = parse_text(text, source_file="detect", family=family)
            tree = trees[family]
        found = score(text, pack.detect, pack.manifest.id, tree, joined)
        out.append(_from_the_top(found, text, pack, tree))
    return sorted(out, key=lambda d: (bool(d.excluded), -d.score, d.pack_id))


def choose(detections: Sequence[Detection]) -> Detection | None:
    """The single confident winner, or None if nothing is confident or the top two tie. A pack
    ruled out by its ``excludes`` is never a winner, and so never ties with one."""
    if not detections or not detections[0].confident:
        return None
    rivals = [d for d in detections[1:] if not d.excluded]
    if rivals and rivals[0].score == detections[0].score:
        return None
    return detections[0]


def input_warnings(text: str, pack: VendorPack, tree: ConfigTree | None = None) -> list[str]:
    """The pack's ``warnings`` whose pattern matches, each with the line that matched."""
    joined = joined_lines(text)
    out = []
    for warning in pack.detect.warnings:
        line = _match(warning, joined, tree)
        if line is not None:
            out.append(f"{warning.message} (line {line})")
    return out


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


def _match(
    sig: Signature | InputWarning | Exclusion, joined: str, tree: ConfigTree | None
) -> int | None:
    """The 1-based line ``sig`` first matches in ``joined`` (the text, every line break made
    ``\\n``), or None. Each kind is one pass over the text: a loop that called RE2 once per
    line spent 48 s on a file of a million blank lines (M2.07 review)."""
    match sig.kind:
        case "contains":
            pos = joined.find(sig.pattern)
            return None if pos < 0 else joined.count("\n", 0, pos) + 1
        case "line_prefix":
            return _line_prefix(joined, sig.pattern)
        case "regex":
            found = regex.first_line(sig.pattern, joined)
            return None if found is None else found[0]
        case "json_key" | "xml_path":
            return _structured(sig.pattern, tree)


def _line_prefix(joined: str, prefix: str) -> int | None:
    """The first line that starts with ``prefix`` after leading whitespace. Candidates are
    found by ``str.find``; a line whose candidate isn't at its start is skipped whole, so no
    line is looked at twice."""
    pos = 0
    while (at := joined.find(prefix, pos)) >= 0:
        start = joined.rfind("\n", 0, at) + 1
        if joined[start:at].isspace() or start == at:
            return joined.count("\n", 0, at) + 1
        pos = joined.find("\n", at)
        if pos < 0:
            return None
        pos += 1
    return None


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
