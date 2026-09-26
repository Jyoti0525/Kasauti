"""Device identity (PLAN §7, R-07a; TODO M1.04, M2.19-M2.20).

Sources in priority order: (1) live facts, (2) companion show outputs, (3) configuration
headers and markers, (4) manual entry. M1 implements (3) from the pack's ``identity.yaml``;
the others slot into the same function as they land. Each field records its source, and a
field no source supplied is *stated* as missing, with what to upload to fill it.
"""

from __future__ import annotations

from dataclasses import dataclass

from kasauti.identity.detect import Detection, detection_evidence
from kasauti.ingest.mask import mask_secrets
from kasauti.mapping.match import match_tokens, tokenize_path
from kasauti.mapping.model import parse_pattern
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import IdentityField, IdentitySource
from kasauti.sbm.entities import Device
from kasauti.sbm.facts import Evidence, Fact
from kasauti.shape.model import ConfigTree

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
_COMPANION_NAMES = {
    "show_version": "`show version`",
    "show_inventory": "`show inventory`",
    "get_system_status": "`get system status`",
    "show_system_info": "`show system info`",
    "show_chassis_hardware": "`show chassis hardware`",
    "display_version": "`display version`",
    "display_esn": "`display esn`",
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
    tree: ConfigTree, pack: VendorPack, detection: Detection | None, text: str
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
        for source in pack.identity.fields.get(field, ()):
            if source.source != "config":
                continue  # companion outputs: TODO M2.05/M2.19
            found = _from_config(tree, source)
            if found is not None:
                value, ev = found
                facts[field] = Fact.explicit(value, ev)
                sources[field] = f"config line {ev.line_start}"
                lines.add(ev.line_start)
                break

    missing = {field: _missing_text(field, pack) for field in FIELDS if field not in facts}
    return Identity(Device(**facts), sources, missing, frozenset(lines))  # type: ignore[arg-type]


def _from_config(tree: ConfigTree, source: IdentitySource) -> tuple[str, Evidence] | None:
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
        _COMPANION_NAMES[s.source]
        for s in pack.identity.fields.get(field, ())  # type: ignore[call-overload]
        if s.source in _COMPANION_NAMES
    ]
    hint = f"; upload {' or '.join(dict.fromkeys(companions))} to populate" if companions else ""
    return f"{_LABELS[field]}: not present in supplied artefacts{hint}"
