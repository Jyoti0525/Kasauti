"""The Training Studio's working set: configurations to learn from, the queue of patterns their
vendor's pack doesn't read yet, suggestions, impact previews and approvals (PLAN §11; TODO
M2.62-M2.68, M3.23, M3.24).

**Files stay in memory.** Uploads to the auditor are deleted as soon as they are audited, and a
masked copy can't be re-audited faithfully (masking removes exactly what verdicts rest on: a
hash prefix, a community string). So a trainer adds the configurations to learn from here; they
are held in this server process's memory only, never written to disk, and are gone when removed
or when the server restarts. What the Studio shows of them is masked.

**Approval is the only way in.** A proposal is rendered from a meaning (:mod:`.meanings`),
previewed against every file in the working set (the same audit, with and without it), and
stored only when approved: into ``<data dir>/learned/<pack>/studio.yaml``, which every later
audit loads with the packs. A proposal that turns any check into PASS needs a second person
(four-eyes, PLAN §11.4): whoever proposed it can't approve it. Here that covers REVIEW -> PASS
too: for a vendor still being taught, a wrongly taught mapping shows up that way.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading
import uuid
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from kasauti.accounts.table import Role
from kasauti.audit import AuditResult, KnowledgeBase, audit
from kasauti.identity.detect import score_pack
from kasauti.identity.resolve import resolve_identity
from kasauti.ingest.mask import mask_secrets
from kasauti.ingest.model import Artifact
from kasauti.mapping.engine import apply_mappings
from kasauti.mapping.match import match_tokens
from kasauti.mapping.model import Mapping, pattern_variants
from kasauti.mapping.setform import parse_config
from kasauti.packs.loader import VendorPack
from kasauti.rules.model import Status
from kasauti.rules.scoring import NIST
from kasauti.shape.model import Statement
from kasauti.shape.patterns import token_class
from kasauti.studio.meanings import Block, Meaning, Token, as_yaml, load_meanings, render

MAX_FILES = 20
MAX_BYTES = 2 * 1024 * 1024
APPROVERS = frozenset({Role.APPROVER, Role.ADMIN})
"""Who may approve a change that makes any check PASS, and only someone other than its proposer
(four-eyes, TODO M3.23). Any trainer may approve a change that only finds failures or review."""
LEARNED_FILE = "studio.yaml"


class StudioError(ValueError):
    """The request can't be done as asked. User-safe text."""


@dataclass(frozen=True, slots=True)
class StudioFile:
    id: str
    name: str
    pack: str
    artifact: Artifact
    added: str


@dataclass(frozen=True, slots=True)
class Example:
    file: str
    line: int
    text: str
    """Masked."""
    block: str | None
    """The block the line sits in, masked."""


@dataclass(frozen=True, slots=True)
class Suggestion:
    meaning: str
    label: str
    score: float
    why: str
    choices: dict[str, Any]
    roles: dict[int, str]
    """Token index -> role, where the value types line up."""


@dataclass(frozen=True, slots=True)
class Pattern:
    key: str
    """Stable id of the pattern within its block."""
    pattern: str
    block: str | None
    """The pattern of the block the lines sit in (``user-interface vty <INT> <INT>``)."""
    count: int
    files: int
    examples: tuple[Example, ...]
    tokens: tuple[tuple[str, str | None], ...]
    """The first example's words, each with the value type it abstracts to (None: a keyword).
    A masked secret is always a value."""
    relevance: float
    suggestions: tuple[Suggestion, ...]


@dataclass(frozen=True, slots=True)
class Flip:
    rule: str
    title: str
    file: str
    before: str
    after: str


@dataclass(frozen=True, slots=True)
class Impact:
    lines: int
    """Statements the mapping reads, across the working set."""
    files: int
    facts: int
    understood_before: int
    understood_after: int
    statements: int
    flips: tuple[Flip, ...]

    @property
    def to_pass(self) -> int:
        """Checks the change turns into PASS, from FAIL or from REVIEW. For a vendor still
        being taught, an unread check is REVIEW, so a wrongly taught mapping ("telnet on" taught
        as "off") shows as REVIEW -> PASS: four-eyes covers both (PLAN §11.4)."""
        return sum(1 for f in self.flips if f.after == "PASS" and f.before != "PASS")


@dataclass(frozen=True, slots=True)
class Proposal:
    id: str
    pack: str
    pattern: str
    meaning: str
    mapping: Mapping
    impact: Impact
    proposed_by: str
    created: str
    needs_second: bool


@dataclass
class Studio:
    """One per server. Thread-safe: requests run in the API's thread pool."""

    learned: Path
    record: Path
    files: dict[str, StudioFile] = field(default_factory=dict)
    proposals: dict[str, Proposal] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)

    # -- the working set ---------------------------------------------------------------------

    def add(self, artifact: Artifact, kb: KnowledgeBase, vendor: str | None) -> StudioFile:
        if len(artifact.text.encode("utf-8")) > MAX_BYTES:
            raise StudioError(f"{artifact.name}: larger than {MAX_BYTES // 1024 // 1024} MiB")
        pack = vendor or _recognise(artifact, kb)
        if pack not in kb.vendor_packs:
            raise StudioError(f"no vendor pack {pack!r} is installed")
        with self.lock:
            if len(self.files) >= MAX_FILES:
                raise StudioError(f"the Studio holds at most {MAX_FILES} files; remove one first")
            if any(f.artifact.sha256 == artifact.sha256 for f in self.files.values()):
                raise StudioError(f"{artifact.name} is already in the Studio")
            f = StudioFile(uuid.uuid4().hex, artifact.name, pack, artifact, _now())
            self.files[f.id] = f
            return f

    def remove(self, file_id: str) -> bool:
        with self.lock:
            return self.files.pop(file_id, None) is not None

    def of_pack(self, pack: str) -> list[StudioFile]:
        with self.lock:
            return sorted((f for f in self.files.values() if f.pack == pack), key=lambda f: f.added)

    # -- the queue ---------------------------------------------------------------------------

    def queue(self, kb: KnowledgeBase, pack_id: str) -> list[Pattern]:
        """What the pack doesn't read yet in the working set, grouped by pattern within its
        block, ranked by how security-relevant the words look times how often it occurs.
        Ignored patterns are left out."""
        pack = kb.vendor_packs[pack_id]
        ignored = set(self._state().get("ignored", {}).get(pack_id, []))
        groups: dict[str, list[tuple[StudioFile, Statement]]] = {}
        for f in self.of_pack(pack_id):
            for stmt in unread(f.artifact, pack):
                groups.setdefault(_key(stmt), []).append((f, stmt))
        meanings = load_meanings()
        out: list[Pattern] = []
        for key, found in groups.items():
            if key in ignored:
                continue
            first = found[0][1]
            tokens = _tokens(first)
            block = _block_pattern(first)
            suggestions = suggest(tokens, block, meanings)
            relevance = suggestions[0].score if suggestions else 0.0
            out.append(
                Pattern(
                    key=key,
                    pattern=" ".join(c or t for t, c in tokens),
                    block=block,
                    count=len(found),
                    files=len({f.id for f, _ in found}),
                    examples=tuple(
                        Example(
                            f.name,
                            s.line_start,
                            mask_secrets(s.text, s.path),
                            mask_secrets(s.path[-1], s.path[:-1]) if s.path else None,
                        )
                        for f, s in found[:5]
                    ),
                    tokens=tokens,
                    relevance=relevance,
                    suggestions=suggestions,
                )
            )
        # Top-level lines first (a block's own line must be taught before the lines inside
        # it), then by relevance weighted by how often the pattern occurs.
        return sorted(
            out,
            key=lambda p: (p.block is not None, -p.relevance * (1 + min(p.count, 10) / 10), p.key),
        )

    def ignore(self, pack: str, key: str, by: str) -> None:
        with self.lock:
            state = self._state()
            listed = state.setdefault("ignored", {}).setdefault(pack, [])
            if key not in listed:
                listed.append(key)
            self._log(state, {"action": "ignore", "pack": pack, "pattern": key, "by": by})

    # -- proposals ---------------------------------------------------------------------------

    def propose(
        self,
        kb: KnowledgeBase,
        *,
        pack: str,
        key: str,
        meaning: str,
        tokens: tuple[Token, ...],
        choices: dict[str, Any],
        by: str,
        role: Role,
    ) -> Proposal:
        if pack not in kb.vendor_packs:
            raise StudioError(f"no vendor pack {pack!r} is installed")
        item = next((p for p in self.queue(kb, pack) if p.key == key), None)
        if item is None:
            raise StudioError("that pattern isn't in the queue any more")
        picked = load_meanings().get(meaning)
        if picked is None:
            raise StudioError(f"no meaning {meaning!r}")
        if [t.text for t in tokens] != [t for t, _ in item.tokens]:
            raise StudioError("the words don't match the pattern's example line")
        suggested = any(s.meaning == meaning for s in item.suggestions)
        mapping = render(
            picked,
            pack=pack,
            tokens=tokens,
            choices=choices,
            block=block_mapping(kb.vendor_packs[pack], item),
            proposed_by=f"{role.value}:{by}",
            signals=("S1", "S4") if suggested else ("S1",),
        )
        if any(m.id == mapping.id for m in kb.vendor_packs[pack].mappings):
            raise StudioError("this exact mapping is already approved")
        impact = self.preview(kb, pack, mapping)
        if impact.lines == 0:
            raise StudioError(
                "the mapping reads no line in the working set: check which words are values"
            )
        proposal = Proposal(
            id=uuid.uuid4().hex,
            pack=pack,
            pattern=item.pattern,
            meaning=meaning,
            mapping=mapping,
            impact=impact,
            proposed_by=by,
            created=_now(),
            needs_second=impact.to_pass > 0,
        )
        with self.lock:
            self.proposals[proposal.id] = proposal
            self._log(
                self._state(),
                {
                    "action": "propose",
                    "pack": pack,
                    "mapping": mapping.id,
                    "line": mapping.match,
                    "by": by,
                },
            )
        return proposal

    def preview(self, kb: KnowledgeBase, pack: str, mapping: Mapping) -> Impact:
        """Every file of the pack in the working set, audited with and without ``mapping``."""
        with_it = _with_mapping(kb, pack, mapping)
        flips: list[Flip] = []
        lines = facts = before_u = after_u = statements = 0
        files = 0
        for f in self.of_pack(pack):
            before = _audit(f.artifact, kb, pack)
            after = _audit(f.artifact, with_it, pack)
            used = next(
                (u for u in after.assurance.mappings_used if u.mapping.split("@")[0] == mapping.id),
                None,
            )
            read = _lines_read(after, mapping.id)
            if read:
                files += 1
            lines += read
            facts += used.facts if used else 0
            before_u += before.assurance.understood
            after_u += after.assurance.understood
            statements += after.assurance.statements
            was = {r.rule_id: r for r in before.rules}
            for r in after.rules:
                if r.status is not was[r.rule_id].status:
                    flips.append(
                        Flip(
                            r.rule_id, r.title, f.name, was[r.rule_id].status.value, r.status.value
                        )
                    )
        return Impact(lines, files, facts, before_u, after_u, statements, tuple(flips))

    def approve(self, kb: KnowledgeBase, proposal_id: str, by: str, role: Role) -> Mapping:
        with self.lock:
            p = self.proposals.get(proposal_id)
            if p is None:
                raise StudioError("no such proposal (it may have been decided already)")
            impact = self.preview(kb, p.pack, p.mapping)  # the knowledge base may have moved on
            if impact.to_pass and by == p.proposed_by:
                raise StudioError(
                    f"this change makes {impact.to_pass} check(s) PASS, so an approver other "
                    f"than {by} must approve it (four-eyes)"
                )
            if impact.to_pass and role not in APPROVERS:
                raise StudioError(
                    f"this change makes {impact.to_pass} check(s) PASS, so it needs an approver; "
                    f"{by} is a {role.value}"
                )
            prov = p.mapping.provenance.model_copy(update={"approved_by": (f"{role.value}:{by}",)})
            mapping = p.mapping.model_copy(update={"provenance": prov})
            self._store(p.pack, mapping)
            del self.proposals[proposal_id]
            self._log(
                self._state(),
                {
                    "action": "approve",
                    "pack": p.pack,
                    "mapping": mapping.id,
                    "line": mapping.match,
                    "proposed_by": p.proposed_by,
                    "by": by,
                    "to_pass": impact.to_pass,
                    "flips": [f"{f.rule} {f.before}->{f.after} ({f.file})" for f in impact.flips],
                },
            )
            return mapping

    def reject(self, proposal_id: str, by: str) -> None:
        with self.lock:
            p = self.proposals.pop(proposal_id, None)
            if p is None:
                raise StudioError("no such proposal")
            self._log(
                self._state(),
                {
                    "action": "reject",
                    "pack": p.pack,
                    "mapping": p.mapping.id,
                    "line": p.mapping.match,
                    "by": by,
                },
            )

    def taught(self, pack: str) -> list[Mapping]:
        path = self.learned / pack / LEARNED_FILE
        if not path.exists():
            return []
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return [Mapping.model_validate(m) for m in doc.get("mappings", [])]

    def undo(self, pack: str, mapping_id: str, by: str) -> None:
        """Take a taught mapping back out; later audits no longer read what it read."""
        with self.lock:
            taught = self.taught(pack)
            gone = next((m for m in taught if m.id == mapping_id), None)
            if gone is None:
                raise StudioError("no such taught mapping")
            self._write(pack, [m for m in taught if m.id != mapping_id])
            self._log(
                self._state(),
                {
                    "action": "undo",
                    "pack": pack,
                    "mapping": mapping_id,
                    "line": gone.match,
                    "by": by,
                },
            )

    def decisions(self) -> list[dict[str, Any]]:
        return list(self._state().get("decisions", []))

    # -- storage -----------------------------------------------------------------------------

    def _store(self, pack: str, mapping: Mapping) -> None:
        self._write(pack, [*self.taught(pack), mapping])

    def _write(self, pack: str, mappings: list[Mapping]) -> None:
        folder = self.learned / pack
        folder.mkdir(parents=True, exist_ok=True)
        header = (
            "# Taught in the Kasauti Training Studio and approved there (PLAN §11). Each mapping\n"
            "# records who proposed and who approved it. Edit through the Studio, not by hand.\n"
        )
        body = "".join("- " + as_yaml(m).replace("\n", "\n  ").rstrip() + "\n" for m in mappings)
        _atomic(
            folder / LEARNED_FILE, header + ("mappings:\n" + body if mappings else "mappings: []\n")
        )

    def _state(self) -> dict[str, Any]:
        path = self.record / "studio.json"
        if not path.exists():
            return {}
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data

    def _log(self, state: dict[str, Any], entry: dict[str, Any]) -> None:
        state.setdefault("decisions", []).append({"at": _now(), **entry})
        self.record.mkdir(parents=True, exist_ok=True)
        _atomic(self.record / "studio.json", json.dumps(state, indent=1) + "\n")


# --- reading the working set -------------------------------------------------------------------


def unread(artifact: Artifact, pack: VendorPack) -> list[Statement]:
    """The statements of ``artifact`` the pack doesn't read, as an audit counts them: identity
    lines (``sysname``) are read by the identity resolver, not by mappings."""
    tree = parse_config(artifact.text, pack, source_file=artifact.name, sha256=artifact.sha256)
    detection = score_pack(artifact.text, pack, tree)
    ident = resolve_identity(tree, pack, detection if detection.matched else None, artifact.text)
    mapped = apply_mappings(
        tree,
        pack.mappings,
        negation_words=pack.manifest.negation_words,
        defaults=pack.defaults.defaults,
        os_version=ident.device.os_version.value,
        pack_id=pack.manifest.id,
        device=ident.device,
    )
    return [s for s in mapped.unmapped if s.line_start not in ident.lines]


def _tokens(stmt: Statement) -> tuple[tuple[str, str | None], ...]:
    shown = mask_secrets(stmt.text, stmt.path).split()
    if len(shown) != len(stmt.tokens):
        shown = list(stmt.tokens)
    return tuple(
        (word, "<STR>" if word != raw and "*" in word else token_class(raw))
        for word, raw in zip(shown, stmt.tokens, strict=True)
    )


def _pattern_of(text: str) -> str:
    return " ".join(token_class(t) or t for t in text.split())


def _block_pattern(stmt: Statement) -> str | None:
    return _pattern_of(stmt.path[-1]) if stmt.path else None


def _key(stmt: Statement) -> str:
    key = f"{_block_pattern(stmt) or ''}\n{stmt.pattern_key or _pattern_of(stmt.text)}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def block_mapping(pack: VendorPack, item: Pattern) -> Block | None:
    """The approved mapping that reads the line of the block the pattern sits in."""
    if not item.examples or item.examples[0].block is None:
        return None
    header = tuple(item.examples[0].block.split())
    for m in pack.mappings:
        if m.entity is None or m.context:
            continue
        if any(match_tokens(v, header) is not None for v in pattern_variants(m.match)):
            return Block(m.match, m.entity.type, m.entity.key)
    return None


def _recognise(artifact: Artifact, kb: KnowledgeBase) -> str:
    best = max(
        (score_pack(artifact.text, p) for p in kb.vendor_packs.values()),
        key=lambda d: (d.confident, d.score),
    )
    if not best.confident:
        raise StudioError(f"{artifact.name}: can't tell which vendor this is; choose it")
    return best.pack_id


# --- suggestions (signals S1 structure + S4 lexicon) --------------------------------------------

SYNONYMS = {
    # Vendor words for the same service (PLAN §10.2 S4): Huawei's STelnet is SSH.
    "telnet": "telnet",
    "stelnet": "ssh",
    "ssh": "ssh",
    "http": "http",
    "secure-server": "https",
    "https": "https",
    "ftp": "ftp",
    "tftp": "tftp",
    "finger": "finger",
    "snmp": "snmp",
    "read": "ro",
    "ro": "ro",
    "write": "rw",
    "rw": "rw",
    "all": "all",
}


def suggest(
    tokens: tuple[tuple[str, str | None], ...], block: str | None, meanings: dict[str, Meaning]
) -> tuple[Suggestion, ...]:
    """Up to three meanings, best first, each saying why. Words of the line shared with a
    meaning's vocabulary (S4), and whether the line sits in a block the meaning belongs in
    (S1). Suggestions only pre-fill the card: nothing is stored until approved."""
    words = [w.lower() for w, c in tokens if c is None]
    block_words = set((block or "").lower().split())
    found: list[Suggestion] = []
    for m in meanings.values():
        vocab = {v.lower() for v in m.words}
        hits = [w for w in words if w in vocab]
        groups = [{r.lower() for r in group} for group in m.requires]
        if not hits or not all(g & set(words) for g in groups):
            continue
        subject = [w for w in words if any(w in g for g in groups)]
        # A word naming the subject ("compatible-ssh1x") says more than a common one ("enable").
        score = (len(hits) + 2 * len(subject)) / max(len(words), 1)
        why = [f"shares {', '.join(repr(h) for h in hits)} with {m.label.lower()}"]
        if m.under is not None:
            inside = bool(block_words & _BLOCK_WORDS.get(m.under, set()))
            score *= 1.5 if inside else 0.3
            if inside:
                why.append("sits in a block of that kind")
        elif (
            block is not None
            and m.entity is not None
            and m.entity.type
            in (
                "MgmtSession",
                "Interface",
            )
        ):
            score *= 0.5  # blocks open at the top level
        choices = _guess_choices(m, words)
        if m.choose and len(choices) < len(m.choose):
            score *= 0.6
        roles = _guess_roles(m, tokens)
        found.append(
            Suggestion(m.id, m.label, round(min(score, 1.0), 3), "; ".join(why), choices, roles)
        )
    ranked = sorted(found, key=lambda s: (-s.score, s.meaning))
    # Only meanings nearly as good as the best, and none on a faint likeness: one shared word
    # ("enable") is no reason, and "No suggestion" is better than a wrong one.
    return tuple(s for s in ranked[:3] if s.score >= max(ranked[0].score / 2, MIN_SCORE))


MIN_SCORE = 0.2


_BLOCK_WORDS = {
    "MgmtSession": {"user-interface", "line", "vty", "con", "console", "management"},
    "Interface": {"interface"},
}


def _guess_choices(m: Meaning, words: list[str]) -> dict[str, Any]:
    """Choices the line's own words name. For one choice, the most specific word wins:
    ``http secure-server enable`` is HTTPS, not HTTP."""
    out: dict[str, Any] = {}
    for name, options in m.choose.items():
        allowed = getattr(options, "many", options)
        hits = [
            (w, SYNONYMS[w])
            for w in words
            if SYNONYMS.get(w) in allowed or SYNONYMS.get(w) == "all"
        ]
        if not hits:
            continue
        if hasattr(options, "many"):
            out[name] = (
                list(allowed)
                if any(v == "all" for _, v in hits)
                else list(dict.fromkeys(v for _, v in hits))
            )
        elif any(v != "all" for _, v in hits):
            out[name] = max((h for h in hits if h[1] != "all"), key=lambda h: len(h[0]))[1]
    return out


def _guess_roles(m: Meaning, tokens: tuple[tuple[str, str | None], ...]) -> dict[int, str]:
    out: dict[int, str] = {}
    taken: set[int] = set()
    for role in m.roles:
        for i, (_, cls) in enumerate(tokens):
            kind = cls[1:-1] if cls else None
            if i not in taken and kind in role.types:
                out[i] = role.name
                taken.add(i)
                break
        else:
            # Free text (a description): the words after the keyword are the value.
            if "LIST" in role.types and len(tokens) > 1 and 1 not in taken:
                out[1] = role.name
                taken.add(1)
    return out


# --- auditing with a draft ---------------------------------------------------------------------


def _with_mapping(kb: KnowledgeBase, pack: str, mapping: Mapping) -> KnowledgeBase:
    """The knowledge base as it would be once ``mapping`` is approved. The preview must show
    what approval does: an unapproved mapping's facts never reach a verdict (PLAN §10.3)."""
    prov = mapping.provenance.model_copy(update={"approved_by": ("preview",)})
    mapping = mapping.model_copy(update={"provenance": prov})
    vp = kb.vendor_packs[pack]
    packs = {**kb.vendor_packs, pack: replace(vp, mappings=(*vp.mappings, mapping))}
    return replace(kb, vendor_packs=packs, version=f"{kb.version}+draft")


def _audit(artifact: Artifact, kb: KnowledgeBase, pack: str) -> AuditResult:
    return audit(artifact, kb, vendor=pack, frameworks=(NIST,), fixes=False)


def _lines_read(result: AuditResult, mapping_id: str) -> int:
    """Lines the mapping read: those behind the facts it set, and those that opened entities
    (a block line that sets nothing yet still opens its interface or line range)."""
    lines: set[int] = set()
    for entity in result.sbm.all_entities():
        for name, fact in entity:
            evidence = fact if name == "evidence" else getattr(fact, "evidence", None)
            for ev in evidence or ():
                ref = getattr(ev, "mapping_ref", None)
                if ref and ref.split("@", 1)[0] == mapping_id:
                    lines.add(ev.line_start)
    return len(lines)


def coverage(result: AuditResult) -> dict[str, Any]:
    counts = Counter(r.status for r in result.rules)
    return {
        "understood": result.assurance.understood,
        "statements": result.assurance.statements,
        "pass": counts[Status.PASS],
        "fail": counts[Status.FAIL],
        "review": counts[Status.REVIEW],
        "na": counts[Status.NOT_APPLICABLE],
    }


# --- small helpers ------------------------------------------------------------------------------


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def _atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))
    tmp.replace(path)
