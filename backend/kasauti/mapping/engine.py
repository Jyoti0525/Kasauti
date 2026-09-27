"""The mapping engine (PLAN §9; TODO M1.05-M1.07): Universal Config Tree -> SBM.

For each statement:

1. **Match.** Every mapping in range for this OS version whose context and pattern match. A
   statement starting with a negation word (``no``, ``undo``…) matches the rest of the pattern
   in negated form; so does a mapping's explicit ``negation`` pattern.
2. **Apply.** Most specific mapping first. An attribute written by a more specific mapping on
   this statement isn't overwritten by a less specific one (``transport input none`` beats
   ``transport input <LIST>``). Every fact records the line, the mapping and its approvers.
3. **Near miss.** If nothing matched, but a mapping's keywords did (``exec-timeout 10`` against
   ``exec-timeout <INT> <INT>``), the facts that mapping would have set become *unknown*, with
   this line as evidence. A misread line must never look like a missing one: a missing line
   can be filled by a default, an unread one mustn't be.
4. Statements nothing understood are returned as ``unmapped``, for the Training Studio.

Then version-scoped defaults fill what is still absent (:mod:`kasauti.mapping.defaults`).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from kasauti.ingest.mask import mask_secrets
from kasauti.mapping import effects as fx
from kasauti.mapping.addressing import mark_addressing
from kasauti.mapping.builder import EntityRef, FactAcc, RefRecord, SbmBuilder
from kasauti.mapping.defaults import apply_defaults
from kasauti.mapping.match import Captures, Compiled, tokenize_path
from kasauti.mapping.model import (
    BLOCK_LINE,
    ORDINAL,
    AssertEffect,
    Mapping,
    RefEffect,
    SetEffect,
    UnknownEffect,
    Word,
)
from kasauti.mapping.resolve import resolve_references
from kasauti.packs.model import DefaultEntry
from kasauti.packs.versions import Version, VersionRange
from kasauti.rules.expr import attribute_type
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.sbm.entities import SINGLETON_TYPES, Device
from kasauti.sbm.facts import Evidence, FactState
from kasauti.shape.model import ConfigTree, Statement

MIN_NEAR_MISS_TOKENS = 2


@dataclass(frozen=True, slots=True)
class MappingStats:
    statements: int
    mapped: int
    near_miss: int
    unmapped: int
    skipped_for_version: tuple[str, ...]
    """Mappings not applied because the OS version is unknown or out of their range."""

    @property
    def understood_pct(self) -> float | None:
        return None if not self.statements else 100.0 * self.mapped / self.statements


@dataclass(frozen=True, slots=True)
class MappingResult:
    sbm: SecurityBaselineModel
    unmapped: tuple[Statement, ...]
    """Statements no mapping understood (near misses included), for the Training Studio."""
    stats: MappingStats
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Hit:
    compiled: Compiled
    caps: Captures
    negated: bool
    specificity: tuple[int, int]


def apply_mappings(
    tree: ConfigTree,
    mappings: Sequence[Mapping],
    *,
    negation_words: Iterable[str] = (),
    defaults: Sequence[DefaultEntry] = (),
    os_version: str | None,
    pack_id: str | None = None,
    device: Device | None = None,
) -> MappingResult:
    """Map ``tree`` into an SBM. ``os_version=None`` means unknown: only mappings and defaults
    scoped to every version (``*``) apply, and the skipped ones are listed in the stats."""
    active, skipped = _in_scope(mappings, os_version)
    engine = _Engine(tree, active, frozenset(negation_words))
    engine.run(device)
    engine.builder.ensure_rulesets()
    warnings = apply_defaults(
        engine.builder, defaults, os_version, f"{pack_id}/" if pack_id else ""
    )
    resolve_references(engine.builder)
    mark_addressing(engine.builder)
    stats = MappingStats(
        statements=len(tree.statements),
        mapped=engine.mapped,
        near_miss=engine.near_miss,
        unmapped=len(engine.unmapped),
        skipped_for_version=skipped,
    )
    return MappingResult(
        engine.builder.build(), tuple(engine.unmapped), stats, (*tree.warnings, *warnings)
    )


def _in_scope(
    mappings: Sequence[Mapping], os_version: str | None
) -> tuple[list[Compiled], tuple[str, ...]]:
    version = Version.parse(os_version) if os_version else None
    active: list[Compiled] = []
    skipped: list[str] = []
    for order, m in enumerate(sorted(mappings, key=lambda m: m.id)):
        scope = VersionRange.parse(m.os_versions)
        if scope.is_any or (version is not None and scope.contains(version)):
            active.append(Compiled(m, order))
        else:
            skipped.append(m.id)
    return active, tuple(skipped)


class _Engine:
    def __init__(self, tree: ConfigTree, compiled: list[Compiled], negation: frozenset[str]):
        self.tree = tree
        self.negation = negation
        self.builder = SbmBuilder()
        self.mapped = 0
        self.near_miss = 0
        self.unmapped: list[Statement] = []
        self._line = 0
        self._stmt_line = 0
        self._ordinals: dict[tuple[str, str], int] = defaultdict(int)
        self._header_lines: dict[tuple[str, ...], int] = {}
        """Block path -> line of its header (headers precede their children in every family)."""
        # Index by first keyword so each statement is only tried against plausible mappings.
        self._by_word: dict[str, list[Compiled]] = defaultdict(list)
        self._slot_first: list[Compiled] = []
        for c in compiled:
            forms = (*c.variants, *(c.negation or ()))
            for word in sorted({f[0].text for f in forms if isinstance(f[0], Word)}):
                self._by_word[word].append(c)
            if any(not isinstance(f[0], Word) for f in forms):
                self._slot_first.append(c)

    def run(self, device: Device | None) -> None:
        self.builder = SbmBuilder(device)
        parents = {stmt.path for stmt in self.tree.statements}
        for stmt in self.tree.statements:
            self._header_lines.setdefault((*stmt.path, stmt.text), stmt.line_start)
            self._line = (
                self._header_lines.get(stmt.path, stmt.line_start) if stmt.path else stmt.line_start
            )
            path = tokenize_path(stmt.path)
            hits = self._hits(stmt, path)
            if hits:
                self.mapped += 1
                self._apply(stmt, hits)
                continue
            self.unmapped.append(stmt)
            # An unread line belongs to the nearest entity whose block encloses it (a Junos
            # term owns what its `from { }` holds). A container's header (`from`, `config
            # ipv6`) says nothing by itself: the lines inside it do.
            owner = next(
                (
                    self.builder.blocks[stmt.path[:i]]
                    for i in range(len(stmt.path), 0, -1)
                    if stmt.path[:i] in self.builder.blocks
                ),
                None,
            )
            if owner is not None and (*stmt.path, stmt.text) not in parents:
                self.builder.unread_children.setdefault(owner, []).append(
                    Evidence(
                        file=self.tree.source_file,
                        line_start=stmt.line_start,
                        line_end=stmt.line_end,
                        raw=mask_secrets(stmt.text, stmt.path),
                    )
                )
            if self._near_miss(stmt, path):
                self.near_miss += 1

    # --- matching --------------------------------------------------------------------------

    def _candidates(self, tokens: tuple[str, ...]) -> list[Compiled]:
        seen: dict[int, Compiled] = {}
        keys = [tokens[0]]
        if len(tokens) > 1 and tokens[0] in self.negation:
            keys.append(tokens[1])
        for key in keys:
            for c in self._by_word.get(key, ()):
                seen[c.order] = c
        for c in self._slot_first:
            seen[c.order] = c
        return [seen[k] for k in sorted(seen)]

    def _hits(self, stmt: Statement, path: tuple[tuple[str, ...], ...]) -> list[_Hit]:
        tokens = stmt.tokens
        hits: list[_Hit] = []
        for c in self._candidates(tokens):
            ctx = c.match_context(path)
            if ctx is None:
                continue
            found = c.match(tokens)
            if found is not None:
                hits.append(_Hit(c, {**ctx, **found[0]}, negated=False, specificity=found[1]))
                continue
            neg = self._negated(c, tokens)
            if neg is not None:
                hits.append(_Hit(c, {**ctx, **neg[0]}, negated=True, specificity=neg[1]))
        return sorted(hits, key=_most_specific_first)

    def _negated(
        self, c: Compiled, tokens: tuple[str, ...]
    ) -> tuple[Captures, tuple[int, int]] | None:
        if c.negation is not None:
            return c.match_negation(tokens)
        if c.mapping.negation != "auto" or len(tokens) < 2 or tokens[0] not in self.negation:
            return None
        rest = tokens[1:]
        found = c.match(rest)
        if found is None and c.prefix and rest == c.prefix:
            # `no exec-timeout`: the negated form may drop the values.
            return {}, c.specificity(c.pattern)
        return found

    # --- applying --------------------------------------------------------------------------

    def _evidence(self, stmt: Statement, m: Mapping) -> Evidence:
        return Evidence(
            file=self.tree.source_file,
            line_start=stmt.line_start,
            line_end=stmt.line_end,
            raw=mask_secrets(stmt.text, stmt.path),
            mapping_id=m.id,
            mapping_version=m.provenance.version,
            approved_by=m.provenance.approved_by,
        )

    def _apply(self, stmt: Statement, hits: list[_Hit]) -> None:
        self._stmt_line = stmt.line_start
        written: set[tuple[EntityRef, str]] = set()
        opened: set[EntityRef] = set()
        keys: dict[tuple[str, str], str] = {}
        for hit in hits:
            m = hit.compiled.mapping
            ev = self._evidence(stmt, m)
            target: EntityRef | None = None
            if m.entity is not None:
                key = self._key(m, hit.caps, keys, count=not hit.negated)
                if key is None:
                    continue  # negated form without the values that name the entity
                if hit.negated and not m.effects:
                    continue  # `no interface X` removes, it doesn't describe
                target = (m.entity.type, key)
                entity = self.builder.entity(target)
                # Lines inside the statement's block that no mapping reads are the entity's
                # unread children (a FortiOS ``edit 3`` under ``config firewall local-in-policy``
                # as much as a Cisco ``ip access-list``).
                self.builder.blocks.setdefault((*stmt.path, stmt.text), target)
                if not m.context and target not in opened:
                    # A context-free statement names the entity (``line vty 0 4``); child lines
                    # are evidence of their own facts, not of where the entity is.
                    entity.evidence.append(ev)
                    opened.add(target)
            for eff in m.effects:
                if isinstance(eff, UnknownEffect | RefEffect) and _read_elsewhere(eff, hit.caps):
                    continue
                etype, attr = eff.attr.split(".", 1)
                ref = target if target and target[0] == etype else self.builder.singleton(etype)
                if (ref, attr) in written:
                    continue
                written.add((ref, attr))
                kind = attribute_type(etype, attr)
                if kind is None:  # pragma: no cover - rejected when the mapping is loaded
                    raise RuntimeError(f"{m.id}: unknown attribute {eff.attr}")
                outcome: fx.Outcome | None = fx.evaluate(eff, hit.caps, kind, negated=hit.negated)
                fact = self.builder.entity(ref).fact(attr)
                if isinstance(eff, SetEffect | AssertEffect) and eff.combine == "any":
                    outcome = _combined(outcome, fact)
                _record(fact, outcome, ev)
                if isinstance(eff, RefEffect) and isinstance(outcome, fx.SetValue | fx.AddItems):
                    self.builder.refs.extend(
                        RefRecord(
                            ref,
                            eff.attr,
                            eff.target_kind,
                            n,
                            ev,
                            eff.expand,
                            eff.take,
                            None if eff.if_empty is None else frozenset(eff.if_empty),
                            eff.literal,
                            eff.unread,
                        )
                        for n in sorted(set(fx.ref_names(eff, hit.caps)))
                    )

    def _key(
        self, m: Mapping, caps: Captures, keys: dict[tuple[str, str], str], *, count: bool
    ) -> str | None:
        """Render the entity key from the captured slots, or None if a slot is missing.

        ``{#}`` is the entity's ordinal among statements opening this type with this template.
        One statement gets one ordinal (``keys`` memoises it) even if several mappings match it;
        a negated statement can't take a new ordinal, since it can't say which entity it means.
        """
        if m.entity is None:  # pragma: no cover - callers check
            raise RuntimeError(f"{m.id} opens no entity")
        slots = m.entity.key_slots()
        if any(s not in caps for s in slots):
            return None
        values = {s: _text(caps[s]) for s in slots}
        line = str(self._line if m.context else self._stmt_line)
        template = m.entity.key.replace(BLOCK_LINE, line)
        parts = [part.format(**values) if slots else part for part in template.split(ORDINAL)]
        if len(parts) == 1:
            return parts[0]
        memo = (m.entity.type, m.entity.key)
        if memo not in keys:
            if not count:
                return None
            self._ordinals[memo] += 1
            keys[memo] = str(self._ordinals[memo])
        return keys[memo].join(parts)

    # --- near misses -----------------------------------------------------------------------

    def _near_miss(self, stmt: Statement, path: tuple[tuple[str, ...], ...]) -> bool:
        tokens = stmt.tokens
        if tokens[0] in self.negation and len(tokens) > 1:
            tokens = tokens[1:]
        found = False
        keys: dict[tuple[str, str], str] = {}
        for c in self._candidates(tokens):
            if not c.prefix:
                continue
            ctx = c.match_context(path)
            if ctx is None:
                continue
            matched, caps = c.partial(tokens)
            needed = min(len(c.pattern), len(c.prefix) + 1)
            if matched < max(needed, MIN_NEAR_MISS_TOKENS) or matched == len(tokens) == len(
                c.pattern
            ):
                continue
            found = True
            self._mark_unknown(stmt, c.mapping, {**ctx, **caps}, keys)
        return found

    def _mark_unknown(
        self, stmt: Statement, m: Mapping, caps: Captures, keys: dict[tuple[str, str], str]
    ) -> None:
        self._stmt_line = stmt.line_start
        ev = self._evidence(stmt, m)
        target: EntityRef | None = None
        if m.entity is not None:
            key = self._key(m, caps, keys, count=True)
            if key is None:
                self.builder.mark_unread(m.entity.type, ev)
                return
            target = (m.entity.type, key)
            if not m.context:
                self.builder.entity(target).evidence.append(ev)
        for eff in m.effects:
            etype, attr = eff.attr.split(".", 1)
            if target and target[0] == etype:
                ref = target
            elif etype in SINGLETON_TYPES:
                ref = self.builder.singleton(etype)
            else:
                continue
            self.builder.entity(ref).fact(attr).unknown(ev)


def _combined(outcome: fx.Outcome | None, fact: FactAcc) -> fx.Outcome | None:
    """``combine: any``: a set gains items instead of being replaced, and a flag that another
    statement made true stays true (None: nothing to record)."""
    match outcome:
        case fx.SetValue(value=frozenset() as items):
            return fx.AddItems(items)
        case fx.SetValue(value=False) if fact.state is FactState.EXPLICIT and fact.value is True:
            return None
    return outcome


def _read_elsewhere(eff: UnknownEffect | RefEffect, caps: Captures) -> bool:
    return eff.from_ is not None and _text(caps.get(eff.from_)) in eff.unless


def _record(fact: FactAcc, outcome: fx.Outcome | None, ev: Evidence) -> None:
    match outcome:
        case fx.SetValue(value=value):
            fact.set(value, ev)
        case fx.AddItems(items=items):
            fact.add(items, ev)
        case fx.RemoveItems(items=items):
            fact.remove(items, ev)
        case fx.Clear():
            fact.clear()
        case fx.Unknown():
            fact.unknown(ev)


def _most_specific_first(hit: _Hit) -> tuple[int, int, int]:
    words, length = hit.specificity
    return (-words, -length, hit.compiled.order)


def _text(value: object) -> str:
    return " ".join(value) if isinstance(value, tuple) else str(value)
