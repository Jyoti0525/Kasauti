"""Device identity (PLAN §7, R-07a; TODO M1.04, M2.19-M2.20).

Sources in priority order: (1) live facts, (2) companion show outputs, (3) configuration
headers and markers, (4) manual entry. (3) came with M1 and (2) with M2.05, both read by the
pack's ``identity.yaml``; the others slot into the same function as they land. The order is
PLAN §7's, whatever order a pack lists its sources in: a companion's ``17.09.04a`` is more
exact than a configuration's ``version 17.9``. Each field records its source, and a field no
source supplied is *stated* as missing, with what to upload to fill it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from kasauti.identity.companion import COMMANDS, Companion
from kasauti.identity.detect import Detection, detection_evidence
from kasauti.ingest.mask import mask_secrets
from kasauti.mapping.match import match_tokens, tokenize_path
from kasauti.mapping.model import parse_pattern
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import IdentityField, IdentitySource
from kasauti.rules import regex
from kasauti.sbm.entities import Device
from kasauti.sbm.facts import Evidence, Fact
from kasauti.shape.model import ConfigTree
from kasauti.shape.tokens import split_lines

FIELDS: tuple[IdentityField, ...] = (
    "hostname",
    "vendor",
    "os_version",
    "model",
    "serial",
    "hardware",
)
_LABELS = {
    "hostname": "Hostname",
    "vendor": "Vendor",
    "os_version": "OS version",
    "model": "Model",
    "serial": "Serial",
    "hardware": "Hardware",
}


@dataclass(frozen=True, slots=True)
class Identity:
    device: Device
    sources: dict[str, str]
    """Field -> where it came from, e.g. ``config line 10``."""
    missing: dict[str, str]
    """Field -> the sentence the report prints instead of a blank."""
    lines: frozenset[int] = frozenset()
    """Config lines identity read (``hostname``, ``version``): understood, even though no
    mapping reads them."""


def resolve_identity(
    tree: ConfigTree,
    pack: VendorPack,
    detection: Detection | None,
    text: str,
    companions: Sequence[Companion] = (),
) -> Identity:
    facts: dict[str, Fact[str]] = {}
    sources: dict[str, str] = {}
    lines: set[int] = set()

    if detection is not None and detection.matched:
        fingerprint = detection_evidence(detection, text, tree.source_file)
        facts["vendor"] = Fact.explicit(pack.manifest.vendor, *fingerprint)
        facts["os_family"] = Fact.explicit(pack.manifest.os_family, *fingerprint)
        sources["vendor"] = f"fingerprint ({len(detection.matched)} signatures)"

    for field in FIELDS:
        if field in facts:
            continue
        declared = pack.identity.fields.get(field, ())
        found = _first_companion(companions, declared)
        if found is not None:
            value, ev, kind = found
            facts[field] = Fact.explicit(value, ev)
            sources[field] = f"{COMMANDS[kind]} ({ev.file} line {ev.line_start})"
            continue
        for source in declared:
            if source.source != "config":
                continue
            found_config = _read(tree, text, source)
            if found_config is not None:
                value, ev = found_config
                facts[field] = Fact.explicit(value, ev)
                sources[field] = f"config line {ev.line_start}"
                lines.add(ev.line_start)
                break

    missing = {field: _missing_text(field, pack) for field in FIELDS if field not in facts}
    return Identity(Device(**facts), sources, missing, frozenset(lines))  # type: ignore[arg-type]


def companion_value(
    companion: Companion, pack: VendorPack, field: IdentityField
) -> tuple[str, Evidence] | None:
    """What ``companion`` alone says ``field`` is (to check it belongs to this device)."""
    found = _first_companion((companion,), pack.identity.fields.get(field, ()))
    return None if found is None else found[:2]


def _first_companion(
    companions: Sequence[Companion], declared: Sequence[IdentitySource]
) -> tuple[str, Evidence, str] | None:
    for source in declared:
        for companion in companions:
            if companion.kind == source.source:
                found = _read(companion.tree, companion.text, source)
                if found is not None:
                    return (*found, companion.kind)
    return None


def _read(tree: ConfigTree, text: str, source: IdentitySource) -> tuple[str, Evidence] | None:
    if source.regex is not None:
        return _from_raw_lines(tree.source_file, text, source.regex)
    return _from_config(tree, source)


def _from_raw_lines(file: str, text: str, pattern: str) -> tuple[str, Evidence] | None:
    for lineno, line in enumerate(split_lines(text), start=1):
        value = regex.group(pattern, line, "value")
        if value:
            ev = Evidence(
                file=file, line_start=lineno, line_end=lineno, raw=mask_secrets(line.strip())
            )
            return value, ev
    return None


def _from_config(tree: ConfigTree, source: IdentitySource) -> tuple[str, Evidence] | None:
    if source.pattern is None:  # pragma: no cover - the caller routes regex sources elsewhere
        return None
    pattern = parse_pattern(source.pattern)
    context = tuple(parse_pattern(c) for c in source.context)
    for stmt in tree.statements:
        if not _in_context(tokenize_path(stmt.path), context):
            continue
        caps = match_tokens(pattern, stmt.tokens)
        if caps is not None and "value" in caps:
            ev = Evidence(
                file=tree.source_file,
                line_start=stmt.line_start,
                line_end=stmt.line_end,
                raw=mask_secrets(stmt.text),
            )
            value = caps["value"]
            return (" ".join(value) if isinstance(value, tuple) else str(value)), ev
    return None


def _in_context(path: tuple[tuple[str, ...], ...], context: tuple[tuple[object, ...], ...]) -> bool:
    """Same rule as mappings: suffix match of the block path; empty context = top level."""
    if not context:
        return not path
    if len(path) < len(context):
        return False
    return all(
        match_tokens(p, block) is not None  # type: ignore[arg-type]
        for p, block in zip(context, path[-len(context) :], strict=True)
    )


def _missing_text(field: str, pack: VendorPack) -> str:
    companions = [
        COMMANDS[s.source]
        for s in pack.identity.fields.get(field, ())  # type: ignore[call-overload]
        if s.source in COMMANDS
    ]
    hint = f"; upload {' or '.join(dict.fromkeys(companions))} to populate" if companions else ""
    return f"{_LABELS[field]}: not present in supplied artefacts{hint}"
