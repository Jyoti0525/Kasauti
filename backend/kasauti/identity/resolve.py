"""Device identity (PLAN §7, R-07a; TODO M1.04, M2.19-M2.20).

Sources in priority order: (1) live facts, (2) companion show outputs, (3) configuration
headers and markers, (4) manual entry. (3) came with M1 and (2) with M2.05, both read by the
pack's ``identity.yaml``, and (4) with M2.19 (:mod:`kasauti.identity.manual`): a field typed by
hand fills only what no file did, and stays out of the device's facts. The order is
PLAN §7's, whatever order a pack lists its sources in: a companion's ``17.09.04a`` is more
exact than a configuration's ``version 17.9``. Each field records its source, and a field no
source supplied is *stated* as missing, with what to upload to fill it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from kasauti.identity.companion import COMMANDS, Companion
from kasauti.identity.detect import Detection, detection_evidence
from kasauti.identity.manual import SOURCE as ENTERED_SOURCE
from kasauti.ingest.mask import mask_secrets
from kasauti.mapping.match import match_tokens, tokenize_path
from kasauti.mapping.model import parse_pattern
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import IdentityField, IdentitySource
from kasauti.rules import regex
from kasauti.sbm.entities import Device
from kasauti.sbm.facts import Evidence, Fact
from kasauti.shape.model import ConfigTree, Statement
from kasauti.shape.structured import RECORD
from kasauti.shape.tokens import joined_lines, unquote

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
    entered: dict[str, str] = dataclass_field(default_factory=dict)
    """Field -> the value typed by hand, for a field no file supplied. Not in ``device``: its
    facts are what the files show, with the lines that show it."""
    disagreements: tuple[str, ...] = ()
    """A value typed by hand that the files contradict, said in a sentence; the files win."""

    def value(self, name: str) -> str | None:
        """What the report shows for ``name``: the files' value, else the one typed by hand."""
        fact: Fact[str] = getattr(self.device, name)
        return fact.value if fact.value is not None else self.entered.get(name)


def resolve_identity(
    tree: ConfigTree,
    pack: VendorPack,
    detection: Detection | None,
    text: str,
    companions: Sequence[Companion] = (),
    *,
    entered: Mapping[str, str] | None = None,
) -> Identity:
    """``entered``: fields typed by hand, already checked
    (:func:`kasauti.identity.manual.clean_entered`)."""
    facts: dict[str, Fact[str]] = {}
    sources: dict[str, str] = {}
    lines: set[int] = set()
    conflicts: dict[str, str] = {}

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
        conflict = _conflict(tree, text, field, declared)
        if conflict is not None:
            conflicts[field] = conflict
            continue
        for source in declared:
            found_config = _read(tree, text, source) if source.source == "config" else None
            if found_config is not None:
                value, ev = found_config
                facts[field] = Fact.explicit(value, ev)
                sources[field] = f"config line {ev.line_start}"
                lines.add(ev.line_start)
                break

    by_hand: dict[str, str] = {}
    disagreements: list[str] = []
    for name, value in (entered or {}).items():
        found_fact = facts.get(name)
        if found_fact is None:
            by_hand[name] = value
            sources[name] = ENTERED_SOURCE
        elif found_fact.value != value:
            disagreements.append(
                f"{_LABELS[name]} entered by hand ({value!r}) differs from {sources[name]} "
                f"({found_fact.value!r}); the value in the files is used"
            )
    missing: dict[str, str] = {
        f: conflicts.get(f) or _missing_text(f, pack)
        for f in FIELDS
        if f not in facts and f not in by_hand
    }
    return Identity(
        Device(**facts),  # type: ignore[arg-type]
        sources,
        missing,
        frozenset(lines),
        by_hand,
        tuple(disagreements),
    )


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
    return next(_all(tree, text, source), None)


def _all(tree: ConfigTree, text: str, source: IdentitySource) -> Iterator[tuple[str, Evidence]]:
    if source.regex is not None:
        return _raw_values(tree.source_file, text, source.regex)
    if source.field is not None:
        return _fields(tree, source)
    return _from_config(tree, source)


def _conflict(
    tree: ConfigTree, text: str, field: str, declared: Sequence[IdentitySource]
) -> str | None:
    """Why no value is taken, if the ``all_agree`` sources find more than one."""
    values = sorted(
        {
            value
            for source in declared
            if source.source == "config" and source.all_agree
            for value, _ in _all(tree, text, source)
        }
    )
    if len(values) < 2:
        return None
    shown = ", ".join(values[:3]) + (", …" if len(values) > 3 else "")
    return (
        f"{_LABELS[field]}: the file names {len(values)} different values ({shown}), so it "
        "isn't one device's; none is taken"
    )


def _fields(tree: ConfigTree, source: IdentitySource) -> Iterator[tuple[str, Evidence]]:
    """``field``'s value in each record (``@ key value key value …``) in ``context``."""
    context = tuple(parse_pattern(c) for c in source.context)
    for stmt in tree.statements:
        tokens = stmt.tokens
        if not tokens or tokens[0] != RECORD:
            continue
        if not _in_context(tokenize_path(stmt.path), context):
            continue
        for key, value in zip(tokens[1::2], tokens[2::2], strict=False):
            if unquote(key) == source.field:
                yield unquote(value), _evidence(tree, stmt)
                break


def _raw_values(file: str, text: str, pattern: str) -> Iterator[tuple[str, Evidence]]:
    joined = joined_lines(text)
    for lineno, start, groups in regex.matching_lines(pattern, joined):
        value = groups.get("value")
        if value:
            end = joined.find("\n", start)
            line = joined[start : end if end >= 0 else len(joined)]
            ev = Evidence(
                file=file, line_start=lineno, line_end=lineno, raw=mask_secrets(line.strip())
            )
            yield value, ev


def _from_config(tree: ConfigTree, source: IdentitySource) -> Iterator[tuple[str, Evidence]]:
    if source.pattern is None:  # pragma: no cover - the caller routes other sources elsewhere
        return
    pattern = parse_pattern(source.pattern)
    context = tuple(parse_pattern(c) for c in source.context)
    for stmt in tree.statements:
        if not _in_context(tokenize_path(stmt.path), context):
            continue
        caps = match_tokens(pattern, stmt.tokens)
        if caps is not None and "value" in caps:
            value = caps["value"]
            yield (
                (" ".join(value) if isinstance(value, tuple) else str(value)),
                _evidence(tree, stmt),
            )


def _evidence(tree: ConfigTree, stmt: Statement) -> Evidence:
    return Evidence(
        file=tree.source_file,
        line_start=stmt.line_start,
        line_end=stmt.line_end,
        raw=mask_secrets(stmt.text, stmt.path),
    )


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
