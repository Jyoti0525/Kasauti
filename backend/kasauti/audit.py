"""One device, end to end (PLAN §4.1; TODO M1.14): artefact + knowledge base -> audit result.

:func:`audit` is pure: no file, network or clock access. The same input with the same knowledge
base and Kasauti version gives a byte-identical :meth:`AuditResult.canonical_json` (PLAN §3.1,
principle 5), which the determinism test and the golden regression check. The report date is
added by the reporter, not here, for the same reason.

:func:`load_kb` is the adapter that reads packs from disk and fingerprints them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from kasauti import __version__
from kasauti.identity import companion as companion_files
from kasauti.identity.companion import COMMANDS, Companion
from kasauti.identity.detect import Detection, choose, detect_vendor, input_warnings, score_pack
from kasauti.identity.manual import ManualEntryError, clean_entered
from kasauti.identity.resolve import companion_value, resolve_identity
from kasauti.ingest.mask import mask_secrets
from kasauti.ingest.model import Artifact
from kasauti.mapping.engine import apply_mappings
from kasauti.mapping.setform import parse_config
from kasauti.packs.loader import (
    FrameworkPack,
    PackError,
    RuleSet,
    VendorPack,
    load_framework_pack,
    load_ruleset,
    load_vendor_packs,
)
from kasauti.remediation.engine import EntityFacts, Outcome, remediate
from kasauti.remediation.lint import recipe_problems
from kasauti.remediation.model import Remediation
from kasauti.rules.engine import NOTHING_IN_SCOPE, evaluate_rules
from kasauti.rules.enrich import apply_default_role, apply_inferences
from kasauti.rules.evaluate import with_derived
from kasauti.rules.model import Domain, Finding, Severity, Status
from kasauti.rules.scoring import (
    FRAMEWORKS,
    NIST,
    ControlStatus,
    framework_score,
    nist_controls,
    rule_statuses,
)
from kasauti.sbm.document import OUTSIDE, SecurityBaselineModel
from kasauti.sbm.entities import ENTITY_TYPES, SINGLETON_TYPES, Entity, attribute_names
from kasauti.sbm.facts import Evidence
from kasauti.shape.model import Statement

FORMAT_VERSION = 1
CONTENT_DIRS = ("rules", "derivations", "inferences", "exposures")
"""Vendor-neutral content; any change to it is a new rule-set version."""


class AuditError(ValueError):
    """The audit can't run as asked (unknown vendor, no confident fingerprint). User-safe text."""


# --- knowledge base ------------------------------------------------------------------------------


@dataclass(frozen=True)
class KnowledgeBase:
    vendor_packs: dict[str, VendorPack]
    ruleset: RuleSet
    frameworks: dict[str, FrameworkPack]
    version: str
    """SHA-256 over every pack file: vendor packs, frameworks, rules and derivations."""
    ruleset_version: str
    """SHA-256 over the rule and derivation files only."""


def load_kb(packs_root: Path) -> KnowledgeBase:
    """The knowledge base under ``packs_root``. :class:`PackError` if a pack is invalid, or if
    there is no vendor pack, framework or rule: a server or audit started in the wrong folder
    must stop and say so, not run with nothing to judge by."""
    vendor = load_vendor_packs(packs_root)
    frameworks = {
        fw.catalog.framework: fw
        for fw in (load_framework_pack(d) for d in sorted((packs_root / "frameworks").glob("*/")))
    }
    ruleset = load_ruleset(packs_root / "rules", packs_root / "derivations")
    empty = [
        what
        for what, found in (
            ("vendor packs (vendors/)", vendor),
            ("frameworks (frameworks/)", frameworks),
            ("rules (rules/)", ruleset.rules),
        )
        if not found
    ]
    if empty:
        raise PackError(
            [
                f"{packs_root}: no knowledge base here, it has no {' and no '.join(empty)}; "
                "run from the repository root or pass --packs"
            ]
        )
    problems = [p for pack in vendor.values() for p in recipe_problems(pack, ruleset)]
    if problems:
        raise PackError(problems)
    return KnowledgeBase(
        vendor_packs=vendor,
        ruleset=ruleset,
        frameworks=frameworks,
        version=_tree_hash(packs_root, (*CONTENT_DIRS, "vendors", "frameworks")),
        ruleset_version=_tree_hash(packs_root, CONTENT_DIRS),
    )


def _tree_hash(root: Path, parts: Sequence[str]) -> str:
    """Content hash of pack files. Line endings are normalised first: packs are text, and a
    Windows checkout (CRLF) must report the same knowledge-base version as a Linux one (LF).
    Exact-byte integrity is the job of pack signatures (TODO M5.08), not of this version id."""
    digest = hashlib.sha256()
    for part in parts:
        for path in sorted((root / part).rglob("*")):
            if path.is_file():
                digest.update(path.relative_to(root).as_posix().encode() + b"\0")
                content = path.read_bytes().replace(b"\r\n", b"\n")
                digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


# --- result model --------------------------------------------------------------------------------


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class InputInfo(_Out):
    file: str
    sha256: str
    encoding: str
    shape_family: str
    rebuilt_from: str | None = None
    """The file's own syntax, when its lines were rebuilt into ``shape_family``'s tree (a Junos
    ``display set`` export read as the brace configuration it stands for)."""
    parse_warnings: tuple[str, ...] = ()


class DetectionInfo(_Out):
    pack_id: str
    pack_version: int
    chosen_by: str
    """``fingerprint`` or ``operator`` (``--vendor``)."""
    score: float
    min_score: float
    signatures: tuple[str, ...]


class IdentityField(_Out):
    value: str | None
    source: str
    """Where the value came from, or the sentence explaining why it's missing."""


class CompanionInfo(_Out):
    """A companion output given with the configuration (TODO M2.05), used or not."""

    file: str
    sha256: str
    command: str | None
    """The companion kind recognised (``show_version``…), or None."""
    used: bool
    note: str | None = None
    """Why it wasn't used."""


class InventoryItem(_Out):
    """A hardware component, from a companion output (R-07a)."""

    name: str
    description: str | None
    part: str | None
    version: str | None
    serial: str
    source: str
    """The command, file and line it came from."""


class KbInfo(_Out):
    kasauti_version: str
    kb_version: str
    ruleset_version: str
    vendor_pack: str
    frameworks: dict[str, str]


class RuleResult(_Out):
    rule_id: str
    title: str
    domain: Domain
    status: Status
    severity: Severity
    nist_800_53r5: tuple[str, ...]
    hardening_best_practice: bool


class FrameworkScore(_Out):
    framework: str
    title: str
    passed: int
    failed: int
    review: int
    not_applicable: int
    compliance_pct: float | None
    coverage_pct: float | None


class ControlResult(_Out):
    control: str
    title: str
    status: ControlStatus
    rules: tuple[str, ...]


class UnmappedPattern(_Out):
    pattern_key: str
    count: int
    first_line: int
    example: str
    """Masked."""


class MappingUse(_Out):
    mapping: str
    approved_by: tuple[str, ...]
    facts: int


class Assurance(_Out):
    statements: int
    understood: int
    unmapped: int
    near_miss: int
    understood_pct: float | None
    unmapped_patterns: tuple[UnmappedPattern, ...]
    review_findings: int
    mappings_used: tuple[MappingUse, ...]
    defaults_used: tuple[str, ...]
    mappings_skipped_for_version: tuple[str, ...]


class AuditResult(_Out):
    format_version: int = FORMAT_VERSION
    audit_id: str
    input: InputInfo
    detection: DetectionInfo
    identity: dict[str, IdentityField]
    kb: KbInfo
    frameworks: tuple[str, ...]
    scores: tuple[FrameworkScore, ...]
    rules: tuple[RuleResult, ...]
    controls: tuple[ControlResult, ...]
    findings: tuple[Finding, ...]
    assurance: Assurance
    sbm: SecurityBaselineModel
    warnings: tuple[str, ...] = ()
    companions: tuple[CompanionInfo, ...] = ()
    inventory: tuple[InventoryItem, ...] = ()
    remediation: Remediation | None = None
    """How to fix each failed finding, each fix re-audited on a copy (PLAN §14, R-07c)."""

    def canonical_json(self) -> str:
        return self.model_dump_json(indent=2) + "\n"


_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def effective_severity(r: AuditResult) -> dict[str, Severity]:
    """Each failed rule's severity as the audit found it: that of its worst failing finding, which
    exposure may have raised above the rule's own. The PDF, the CLI summary and the web UI
    (kasauti/api/audits.py, ``summarise``) all count this way."""
    worst: dict[str, Severity] = {}
    for f in r.findings:
        if f.status is not Status.FAIL or f.severity is None:
            continue
        seen = worst.get(f.rule_id)
        if seen is None or _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[seen]:
            worst[f.rule_id] = f.severity
    return {x.rule_id: worst.get(x.rule_id, x.severity) for x in r.rules if x.status is Status.FAIL}


# --- the audit -----------------------------------------------------------------------------------


def audit(
    artifact: Artifact,
    kb: KnowledgeBase,
    *,
    vendor: str | None = None,
    frameworks: Sequence[str] = (NIST,),
    companions: Sequence[Artifact] = (),
    entered: Mapping[str, object] | None = None,
    fixes: bool = True,
) -> AuditResult:
    """Audit ``artifact``, a configuration. ``companions`` are command outputs from the same
    device (``show version``…), read for its identity and hardware; one that isn't recognised
    for the chosen vendor, or names another host, is listed with the reason and not used.
    ``entered`` are device details typed by hand (:mod:`kasauti.identity.manual`): shown in
    the identity where no file gives them, never used to judge a rule. With ``fixes``, each
    failed finding gets its remediation, proven by re-auditing a changed copy (the re-audits
    themselves run without)."""
    unknown = [f for f in frameworks if f not in kb.frameworks]
    if unknown:
        raise AuditError(f"framework(s) not installed: {', '.join(unknown)}")
    try:
        by_hand = clean_entered(entered or {})
    except ManualEntryError as err:
        raise AuditError(str(err)) from None
    pack, detection, chosen_by, warnings = _choose_pack(artifact, kb, vendor)

    tree = parse_config(artifact.text, pack, source_file=artifact.name, sha256=artifact.sha256)
    warnings.extend(input_warnings(artifact.text, pack, tree))
    fingerprint = detection if detection.matched else None
    # Companions are checked against the hostname the files give, never one typed by hand.
    ident = resolve_identity(tree, pack, fingerprint, artifact.text)
    used, companion_infos = _pair(companions, pack, kb, ident.device.hostname.value, warnings)
    if used or by_hand:
        ident = resolve_identity(tree, pack, fingerprint, artifact.text, used, entered=by_hand)
    warnings.extend(ident.disagreements)
    mapped = apply_mappings(
        tree,
        pack.mappings,
        negation_words=pack.manifest.negation_words,
        defaults=pack.defaults.defaults,
        os_version=ident.device.os_version.value,
        pack_id=pack.manifest.id,
        device=ident.device,
    )
    base_sbm = _beyond(mapped.sbm, artifact.name) if tree.partial else mapped.sbm
    enriched = apply_inferences(base_sbm, kb.ruleset.inferences, kb.ruleset.derivations)
    enriched = apply_default_role(
        enriched, pack.manifest.default_role, f"{pack.manifest.id}/pack.yaml#default_role"
    )
    sbm = with_derived(enriched, kb.ruleset.derivations)
    findings = evaluate_rules(sbm, kb.ruleset)
    if tree.family is not pack.manifest.shape_family:
        findings = _not_read(findings, kb.ruleset, pack.manifest.shape_family.value)
        warnings.append(
            "the file couldn't be read in its own syntax, so no rule is judged PASS or FAIL: "
            "each is left for review"
        )
    elif tree.partial:
        findings = _partial(findings, kb.ruleset, _writable(pack, kb))
        warnings.append(
            f"the file holds only part of a configuration ({'; '.join(tree.partial)}), so no "
            "rule passes on what it doesn't show: a PASS is left for review, and a FAIL stands "
            "only where the file's own lines show the weakness"
        )
    statuses = rule_statuses(kb.ruleset.rules, findings)

    unmapped = [s for s in mapped.unmapped if s.line_start not in ident.lines]
    # A line identity reads counts once, whether or not a mapping read it too.
    understood = mapped.stats.mapped + len(mapped.unmapped) - len(unmapped)
    titles = (
        {c.id: c.title for c in kb.frameworks[NIST].catalog.controls}
        if NIST in kb.frameworks
        else {}
    )

    given = "".join(f"|{c.sha256}" for c in sorted(companions, key=lambda c: c.sha256))
    if by_hand:
        given += "|" + json.dumps(by_hand, sort_keys=True)
    remedy: Remediation | None = None
    if fixes and tree.family is pack.manifest.shape_family and not tree.partial:

        def reaudit(text: str) -> Outcome:
            copy = Artifact(
                name=artifact.name,
                text=text,
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                encoding="utf-8",
            )
            again = audit(
                copy,
                kb,
                vendor=pack.manifest.id,
                frameworks=frameworks,
                companions=companions,
                entered=entered,
                fixes=False,
            )
            return _outcome(again)

        remedy = remediate(
            findings,
            tree=tree,
            text=artifact.text,
            pack=pack,
            device=(ident.device.os_version.value, ident.device.hostname.value),
            entities={e.entity_id: _facts(e) for e in sbm.entities},
            original=_outcome_of(
                findings,
                statuses,
                _framework_score(kb, statuses, frameworks[0]).compliance_pct
                if frameworks
                else None,
            ),
            reaudit=reaudit,
        )
    return AuditResult(
        remediation=remedy,
        audit_id=hashlib.sha256(
            f"{artifact.sha256}|{kb.version}|{__version__}|{pack.manifest.id}{given}".encode()
        ).hexdigest()[:24],
        input=InputInfo(
            file=artifact.name,
            sha256=artifact.sha256,
            encoding=artifact.encoding,
            shape_family=tree.family.value,
            rebuilt_from=None if tree.rebuilt_from is None else tree.rebuilt_from.value,
            parse_warnings=tree.warnings,
        ),
        detection=DetectionInfo(
            pack_id=pack.manifest.id,
            pack_version=pack.manifest.pack_version,
            chosen_by=chosen_by,
            score=detection.score,
            min_score=detection.min_score,
            signatures=tuple(sid for sid, _ in detection.matched),
        ),
        identity={
            field: IdentityField(
                value=ident.value(field),
                source=ident.sources.get(field) or ident.missing.get(field, "not available"),
            )
            for field in ("hostname", "vendor", "os_version", "model", "serial", "hardware")
        },
        kb=KbInfo(
            kasauti_version=__version__,
            kb_version=kb.version,
            ruleset_version=kb.ruleset_version,
            vendor_pack=f"{pack.manifest.id}@{pack.manifest.pack_version}",
            frameworks={k: fw.catalog.version for k, fw in sorted(kb.frameworks.items())},
        ),
        frameworks=tuple(frameworks),
        scores=tuple(_framework_score(kb, statuses, f) for f in frameworks),
        rules=tuple(
            RuleResult(
                rule_id=r.id,
                title=r.title,
                domain=r.domain,
                status=statuses[r.id],
                severity=r.severity.base,
                nist_800_53r5=r.refs.nist_800_53r5,
                hardening_best_practice=r.hardening_best_practice,
            )
            for r in kb.ruleset.rules
        ),
        controls=tuple(
            ControlResult(control=c, title=titles.get(c, ""), status=status, rules=rules)
            for c, (status, rules) in nist_controls(kb.ruleset.rules, statuses).items()
        )
        if NIST in frameworks
        else (),
        findings=findings,
        assurance=Assurance(
            statements=mapped.stats.statements,
            understood=understood,
            unmapped=len(unmapped),
            near_miss=mapped.stats.near_miss,
            understood_pct=round(100.0 * understood / mapped.stats.statements, 1)
            if mapped.stats.statements
            else None,
            unmapped_patterns=_patterns(unmapped),
            review_findings=sum(1 for f in findings if f.status is Status.REVIEW),
            mappings_used=_mappings_used(sbm),
            defaults_used=tuple(sorted({d for f in findings for d in f.defaults_used})),
            mappings_skipped_for_version=mapped.stats.skipped_for_version,
        ),
        sbm=sbm,
        warnings=(*warnings, *mapped.warnings),
        companions=companion_infos,
        inventory=tuple(
            InventoryItem(
                name=c.name,
                description=c.description,
                part=c.part,
                version=c.version,
                serial=c.serial,
                source=f"{COMMANDS[c.kind]} ({c.file} line {c.line})",
            )
            for c in companion_files.components(used, pack)
        ),
    )


def _may_be_elsewhere(actual: str, writable: frozenset[str]) -> bool:
    """A fact the finding lacks that the part of the file not shown could hold."""
    if actual.endswith("not understood"):
        return True
    if not actual.endswith(": missing"):
        return False
    m = _MISSING.match(actual)
    return m is None or m.group(1) in writable


def _outcome(r: AuditResult) -> Outcome:
    """A re-audit, as the remediator compares it."""
    return _outcome_of(
        r.findings,
        {x.rule_id: x.status for x in r.rules},
        r.scores[0].compliance_pct if r.scores else None,
    )


def _outcome_of(
    findings: Sequence[Finding], rules: Mapping[str, Status], compliance: float | None
) -> Outcome:
    """The worst status of each rule and entity, and the failed checks (rules) counted."""
    rank = {Status.FAIL: 3, Status.REVIEW: 2, Status.PASS: 1, Status.NOT_APPLICABLE: 0}
    statuses: dict[tuple[str, str], Status] = {}
    for f in findings:
        key = (f.rule_id, f.entity_id)
        if key not in statuses or rank[f.status] > rank[statuses[key]]:
            statuses[key] = f.status
    return Outcome(
        statuses=statuses,
        failed=sum(1 for s in rules.values() if s is Status.FAIL),
        compliance_pct=compliance,
    )


def _facts(entity: Entity) -> EntityFacts:
    """An entity's known facts as text, for filling in a recipe (``{{privilege}}``), and where
    it is: the lines that opened it, then those its facts were read from."""
    out: dict[str, str] = {}
    lines = [e.line_start for e in entity.evidence]
    for name in attribute_names(type(entity).__name__):
        lines += [e.line_start for e in getattr(entity, name).evidence]
        value = getattr(entity, name).value
        if value is None:
            continue
        if isinstance(value, bool):
            out[name] = "true" if value else "false"
        elif isinstance(value, (tuple, frozenset, set, list)):
            out[name] = " ".join(sorted(str(v) for v in value))
        else:
            out[name] = str(value)
    return EntityFacts(attrs=out, lines=tuple(dict.fromkeys(lines)))


def _not_read(findings: Sequence[Finding], ruleset: RuleSet, family: str) -> tuple[Finding, ...]:
    """The file couldn't be read in its own syntax and was read line by line instead (cut off,
    damaged, or nested past the limit). Its structure is lost: a setting may be in it unseen, and
    a line that was seen may be undone by one that wasn't. No verdict rests on that; each PASS,
    FAIL, or "nothing to check" becomes REVIEW, keeping its evidence for the reviewer (M2.09).
    A rule skipped for the device's role stays skipped: the role isn't read from the file."""
    base = {r.id: r.severity.base for r in ruleset.rules}
    out: list[Finding] = []
    for f in findings:
        guessed = f.status is Status.NOT_APPLICABLE and f.reason.startswith(NOTHING_IN_SCOPE)
        if f.status not in (Status.PASS, Status.FAIL) and not guessed:
            out.append(f)
            continue
        severity = f.severity or base[f.rule_id]
        reason = (
            f"Would be {f.status.value}, but the file couldn't be read as {family} syntax (see "
            f"the warnings), so settings in it may have been missed or read out of context; "
            f"check it against the file, or export the file again. {f.reason}"
        )
        out.append(
            f.model_copy(
                update={
                    "status": Status.REVIEW,
                    "severity": severity,
                    "severity_reason": f.severity_reason or f"{severity.value.capitalize()} (base)",
                    "reason": reason,
                }
            )
        )
    return tuple(out)


def _beyond(sbm: SecurityBaselineModel, file: str) -> SecurityBaselineModel:
    """The file is part of a configuration: of every type, more may be configured in the rest.
    Quantifiers then treat the type as they treat one with unread statements: a witness in
    the file still decides ("none … telnet" is false when telnet is here), "all" and "none"
    can't be true, and an empty scope is unknown, not "nothing to check"."""
    mark = Evidence(file=file, line_start=1, line_end=1, raw=OUTSIDE)
    unread = dict(sbm.unread)
    for name in ENTITY_TYPES:
        if name != "Device" and name not in SINGLETON_TYPES:
            unread[name] = (*unread.get(name, ()), mark)
    return sbm.model_copy(update={"unread": dict(sorted(unread.items()))})


ENGINE_WRITES = frozenset(
    {
        # kasauti/mapping/resolve.py and addressing.py, from what other entities hold.
        "attribute",
        "default_route",
        "expanded",
        "login_methods",
        "mgmt_restricted",
        "name",
        "permits_any",
        "public_address",
        "resolved",
        "source",
        "target",
        "target_kind",
    }
)
"""Attributes the engine fills from other entities, whatever the pack's mappings are."""
_MISSING = re.compile(r"^[A-Za-z]+(?:\[.*\])?\.([a-z_0-9]+): missing$")


def _writable(pack: VendorPack, kb: KnowledgeBase) -> frozenset[str]:
    """Attribute names anything could set for this pack: its mappings, its defaults, the
    inferences and the engine. One outside them is missing from any file of this vendor (a
    PAN-OS rule's ``applications`` in an AWS export), so a part of the file can't hide it."""
    names = {eff.attr.split(".", 1)[1] for m in pack.mappings for eff in m.effects}
    names |= {d.attr.split(".", 1)[1] for d in pack.defaults.defaults if d.attr}
    names |= {a for inf in kb.ruleset.inferences for a in inf.set}
    return frozenset(names | ENGINE_WRITES)


def _partial(
    findings: Sequence[Finding], ruleset: RuleSet, writable: frozenset[str]
) -> tuple[Finding, ...]:
    """The file is part of a configuration (``ConfigTree.partial``): shown from an edit level,
    filtered, or with placeholders. What it shows is read as it is; what it doesn't show may be
    anything. A PASS may rest on a setting elsewhere, and "nothing to check" on entities
    elsewhere, so both become REVIEW. A FAIL on the file's own lines stands (``telnet`` is in
    it); one that rests on a default, or on something missing that the rest of the file could
    hold, becomes REVIEW."""
    base = {r.id: r.severity.base for r in ruleset.rules}
    out: list[Finding] = []
    for f in findings:
        guessed = f.status is Status.NOT_APPLICABLE and f.reason.startswith(NOTHING_IN_SCOPE)
        shown = (
            f.status is Status.FAIL
            and bool(f.evidence)
            and not f.defaults_used
            and not any(_may_be_elsewhere(a, writable) for a in f.actual)
        )
        if (f.status not in (Status.PASS, Status.FAIL) and not guessed) or shown:
            out.append(f)
            continue
        severity = f.severity or base[f.rule_id]
        reason = (
            f"Would be {f.status.value}, but the file holds only part of the configuration "
            f"(see the warnings), and the rest may change this; check it against the whole "
            f"configuration. {f.reason}"
        )
        out.append(
            f.model_copy(
                update={
                    "status": Status.REVIEW,
                    "severity": severity,
                    "severity_reason": f.severity_reason or f"{severity.value.capitalize()} (base)",
                    "reason": reason,
                }
            )
        )
    return tuple(out)


def _pair(
    given: Sequence[Artifact],
    pack: VendorPack,
    kb: KnowledgeBase,
    hostname: str | None,
    warnings: list[str],
) -> tuple[list[Companion], tuple[CompanionInfo, ...]]:
    """The companions that belong with this configuration, and a record of every one given.
    Another vendor's output, or one that names another host, is refused: its serial number
    in this device's report would be worse than none."""
    used: list[Companion] = []
    infos: list[CompanionInfo] = []
    for art in sorted(given, key=lambda a: (a.name, a.sha256)):
        found = companion_files.recognise(art.text, pack)
        kind: str | None = None
        note: str | None
        if found is None:
            note = _unrecognised(art, pack, kb)
        else:
            companion = companion_files.read(art, found)
            kind, note = companion.kind, _mismatch(companion, pack, hostname, used)
            if note is None:
                used.append(companion)
        if note is not None:
            warnings.append(f"{art.name}: {note}; not used")
        infos.append(
            CompanionInfo(
                file=art.name, sha256=art.sha256, command=kind, used=note is None, note=note
            )
        )
    return used, tuple(infos)


def _unrecognised(art: Artifact, pack: VendorPack, kb: KnowledgeBase) -> str:
    other = companion_files.classify(
        art.text, [p for p in kb.vendor_packs.values() if p is not pack]
    )
    if other is not None:
        other_pack, detection = other
        return (
            f"looks like {COMMANDS[detection.pack_id]} output from a {other_pack.manifest.name}"
            f" device, not {pack.manifest.name}"
        )
    read = ", ".join(COMMANDS[k] for k in pack.identity.companions) or "none"
    return f"not the output of a command {pack.manifest.name} identity is read from ({read})"


def _mismatch(
    companion: Companion, pack: VendorPack, hostname: str | None, used: Sequence[Companion]
) -> str | None:
    """Why ``companion`` can't be used with this configuration, or None."""
    command = COMMANDS[companion.kind]
    own = companion_value(companion, pack, "hostname")
    if own is not None and hostname is not None and own[0].casefold() != hostname.casefold():
        return f"{command} output from host {own[0]}, not {hostname}"
    first = next((c.name for c in used if c.kind == companion.kind), None)
    return None if first is None else f"a second {command}; {first} is used"


def _choose_pack(
    artifact: Artifact, kb: KnowledgeBase, vendor: str | None
) -> tuple[VendorPack, Detection, str, list[str]]:
    warnings: list[str] = []
    if vendor is not None:
        if vendor not in kb.vendor_packs:
            known = ", ".join(sorted(kb.vendor_packs)) or "none"
            raise AuditError(f"no vendor pack {vendor!r} (installed: {known})")
        pack = kb.vendor_packs[vendor]
        detection = score_pack(artifact.text, pack)
        if (note := detection.exclusion_note()) is not None:
            warnings.append(
                f"the operator chose {vendor}, though the file looks like another OS: {note}"
            )
        elif not detection.confident:
            warnings.append(
                f"the operator chose {vendor}; its fingerprint scored {detection.score} "
                f"(threshold {detection.min_score}), so check this is really a {vendor} config"
            )
        return pack, detection, "operator", warnings
    detections = detect_vendor(artifact.text, list(kb.vendor_packs.values()))
    chosen = choose(detections)
    if chosen is None:
        top = ", ".join(f"{d.pack_id}={d.score}" for d in detections[:3]) or "no packs installed"
        ruled_out = "".join(
            f" {d.pack_id} is ruled out: {note}."
            for d in detections
            if (note := d.exclusion_note()) is not None
        )
        raise AuditError(
            f"{artifact.name}: can't tell which vendor this is ({top}).{ruled_out} Name the "
            "vendor explicitly (--vendor on the command line, or the upload's vendor)"
        )
    return kb.vendor_packs[chosen.pack_id], chosen, "fingerprint", warnings


def _framework_score(
    kb: KnowledgeBase, statuses: dict[str, Status], framework: str
) -> FrameworkScore:
    s = framework_score(kb.ruleset.rules, statuses, framework)
    return FrameworkScore(
        framework=framework,
        title=FRAMEWORKS.get(framework, kb.frameworks[framework].catalog.title),
        passed=s.passed,
        failed=s.failed,
        review=s.review,
        not_applicable=s.not_applicable,
        compliance_pct=s.compliance_pct,
        coverage_pct=s.coverage_pct,
    )


def _patterns(unmapped: Sequence[Statement]) -> tuple[UnmappedPattern, ...]:
    """Unread statements grouped by pattern key, most frequent first: the Studio's to-do list."""
    counts: Counter[str] = Counter()
    first: dict[str, tuple[int, str]] = {}
    for stmt in unmapped:
        key = stmt.pattern_key or mask_secrets(stmt.text, stmt.path)
        counts[key] += 1
        first.setdefault(key, (stmt.line_start, mask_secrets(stmt.text, stmt.path)))
    return tuple(
        UnmappedPattern(pattern_key=k, count=n, first_line=first[k][0], example=first[k][1])
        for k, n in sorted(counts.items(), key=lambda kv: (-kv[1], first[kv[0]][0]))
    )


def _mappings_used(sbm: SecurityBaselineModel) -> tuple[MappingUse, ...]:
    uses: Counter[str] = Counter()
    approvers: dict[str, tuple[str, ...]] = {}
    for entity in sbm.all_entities():
        for name, fact in entity:
            evidence = getattr(fact, "evidence", None)
            if name == "evidence" or not evidence:
                continue
            for ev in evidence:
                if ev.mapping_ref:
                    uses[ev.mapping_ref] += 1
                    approvers[ev.mapping_ref] = ev.approved_by
    return tuple(
        MappingUse(mapping=m, approved_by=approvers[m], facts=n) for m, n in sorted(uses.items())
    )


__all__ = ["AuditError", "AuditResult", "KnowledgeBase", "PackError", "audit", "load_kb"]
