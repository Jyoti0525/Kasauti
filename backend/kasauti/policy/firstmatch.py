"""Ordered first-match evaluation of a filter ruleset (PLAN §13; TODO M2.31, built early for
FortiOS local-in policies and Cisco access lists).

The question is the one management-plane rules ask: **can a source that no entry names** (an
arbitrary address on the Internet) **get this kind of traffic through?** Entries are tried in
order and the first that matches decides; traffic no entry matches gets the ruleset's
``unmatched`` action, which is a quoted vendor fact (``Ruleset.unmatched``), never assumed:
Cisco access lists end in an implicit deny, FortiOS local-in policies don't.

An arbitrary source matches an entry's sources only when they cover every address (``any``, or
a negated list that doesn't include ``any``). So a ``permit`` naming the management network
lets that network in, and the arbitrary source falls through to the next entry.

For each entry the evaluator asks two questions, each YES, NO or MAYBE:

* does it match **some** of the probe's traffic from the arbitrary source? A ``permit`` that
  does lets it in;
* does it match **all** of it? Only a ``deny`` that does blocks it. A deny limited to a
  schedule, to some destinations or to some source ports blocks only part, so evaluation goes
  on past it, which can only make the answer more permissive.

MAYBE is what isn't read: a line in the entry no mapping understood, ports an ACL entry names
but the pack doesn't read, a service object that isn't in the file. A MAYBE entry never
decides; it is remembered, and a later decision it could have pre-empted becomes UNKNOWN
(REVIEW). The answer is TRUE (it gets through), FALSE (blocked) or UNKNOWN, never a guess.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

from kasauti.mapping.builder import EntityAcc, EntityRef, FactAcc, SbmBuilder
from kasauti.sbm.facts import Evidence, FactState

CATCH_ALL = frozenset({"any", "all", "0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0"})
SERVICE_CATCH_ALL = frozenset({"ip", "any"})
PROTOCOLS = frozenset(
    {
        "tcp",
        "udp",
        "sctp",
        "icmp",
        "icmp6",
        "ipv6-icmp",
        "gre",
        "esp",
        "ahp",
        "ah",
        "ospf",
        "eigrp",
        "pim",
        "igmp",
        "ipinip",
        "vrrp",
    }
)
"""Protocol words an entry can name without ports; ``tcp`` alone may carry unread ports."""
PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "sctp": 132}
_PORTS = re.compile(r"^(tcp|udp|sctp)/(\d+)(?:-(\d+))?(:.*)?$")
_PROTO_NUMBER = re.compile(r"^ip-proto-(\d+)$")
DENY_ACTIONS = frozenset({"deny", "drop", "reject"})


class Tri(IntEnum):
    NO = 0
    MAYBE = 1
    YES = 2

    def negate(self) -> Tri:
        return Tri(2 - self.value)


@dataclass(frozen=True, slots=True)
class Probe:
    """The traffic asked about, always from a source no entry names."""

    service: str | None = None
    """``tcp/443``; ``None``: any traffic (an ACL on vty lines filters every connection)."""
    interface: str | None = None
    """The incoming interface; ``None`` where the ruleset is applied by reference."""
    to_device: bool = False
    """The traffic is addressed to the device itself (a local-in policy). A permit naming
    specific destinations then may or may not include the device's own address; for an ACL
    applied by reference, any destination counts, as it always has."""


@dataclass(frozen=True, slots=True)
class Decision:
    permitted: bool | None
    """TRUE: the arbitrary source gets through; FALSE: it's blocked; ``None``: can't tell."""
    evidence: tuple[Evidence, ...]
    """The deciding entry's lines, or the lines that leave it open. Empty when the vendor's
    ``unmatched`` behaviour decided: the caller cites its own line and the default."""
    reason: str


@dataclass(frozen=True, slots=True)
class _Entry:
    line: int
    position: int | None
    action: str | None
    some: Tri
    all: Tri
    evidence: tuple[Evidence, ...]


def evaluate(
    builder: SbmBuilder, objects: dict[str, EntityAcc], ruleset: str, probe: Probe
) -> Decision:
    """First-match evaluation of ``ruleset`` for ``probe``. ``objects`` are the ObjectDefs by
    key (``service:HTTPS``), after group expansion and widening."""
    rs = builder.entities.get(("Ruleset", ruleset))
    entries = [
        _entry(builder, ref, acc, objects, probe)
        for ref, acc in sorted(builder.entities.items())
        if ref[0] == "FilterRule" and _value(acc.facts.get("ruleset")) == ruleset
    ]
    # An entry whose ruleset wasn't read (an AWS network ACL entry's direction is one of its
    # fields) may belong to this one: it can't decide, but it may pre-empt what comes after.
    entries += [
        _unplaced(builder, ref, acc, objects, probe)
        for ref, acc in sorted(builder.entities.items())
        if ref[0] == "FilterRule" and not _known(acc.facts.get("ruleset"))
    ]
    enabled = [e for e in entries if e is not None]
    unread = builder.unread_children.get(("ObjectDef", f"acl:{ruleset}"), [])
    if not entries and not unread:
        empty = _value(rs.facts.get("when_empty")) if rs else None
        if empty in ("permit", "deny"):
            return Decision(empty == "permit", (), f"the ruleset has no entries ({empty})")
        return Decision(None, (), "the ruleset has no entries and what that does isn't quoted")
    ordered = _ordered(rs, enabled, unread, builder.position)
    if ordered is None:
        ev = tuple(e.evidence[0] for e in enabled if e.evidence)[:1]
        return Decision(None, ev, "the order of its entries can't be told")
    return _walk(ordered, _value(rs.facts.get("unmatched")) if rs else None)


def _walk(entries: list[_Entry], unmatched: object) -> Decision:
    maybe_permit: list[Evidence] = []
    maybe_block: list[Evidence] = []
    for e in entries:
        can_permit = e.action is None or e.action == "permit"
        can_block = e.action is None or e.action in DENY_ACTIONS
        if e.action == "permit" and e.some is Tri.YES:
            if maybe_block:
                return Decision(None, tuple(maybe_block), "an earlier entry might block it")
            return Decision(True, e.evidence, "a permit entry lets a source no entry names in")
        if e.action in DENY_ACTIONS and e.all is Tri.YES:
            if maybe_permit:
                return Decision(None, tuple(maybe_permit), "an earlier entry might permit it")
            return Decision(False, e.evidence, "a deny entry blocks all of it from any source")
        if can_permit and e.some is not Tri.NO:
            maybe_permit.extend(e.evidence)
        if can_block and e.all is not Tri.NO:
            maybe_block.extend(e.evidence)
    if unmatched == "permit":
        if maybe_block:
            return Decision(None, tuple(maybe_block), "an entry might block it")
        return Decision(True, (), "no entry matches it, and unmatched traffic is permitted")
    if unmatched == "deny":
        if maybe_permit:
            return Decision(None, tuple(maybe_permit), "an entry might permit it")
        return Decision(False, (), "no entry matches it, and unmatched traffic is denied")
    ev = tuple(maybe_permit or maybe_block)
    return Decision(None, ev, "what happens to unmatched traffic isn't quoted")


# --- order ---------------------------------------------------------------------------------


def _ordered(
    rs: EntityAcc | None,
    entries: list[_Entry],
    unread: list[Evidence],
    position: Callable[[int], int],
) -> list[_Entry] | None:
    """Entries in evaluation order, with lines no mapping read as MAYBE entries of unknown
    action. ``None`` if the order can't be told."""
    lines = [
        _Entry(position(ev.line_start), None, None, Tri.MAYBE, Tri.MAYBE, (ev,)) for ev in unread
    ]
    order = _value(rs.facts.get("order")) if rs else None
    if order == "config":
        return sorted([*entries, *lines], key=lambda e: e.line)
    positions = [e.position for e in entries]
    if order == "position":
        if any(p is None for p in positions):
            return None
        # Unread lines have no position: they might come first.
        return [*lines, *sorted(entries, key=lambda e: (e.position or 0, e.line))]
    if all(p is None for p in positions):
        return sorted([*entries, *lines], key=lambda e: e.line)
    if any(p is None for p in positions):
        return None
    by_position = sorted(entries, key=lambda e: (e.position or 0, e.line))
    if [e.line for e in by_position] != sorted(e.line for e in by_position):
        return None  # numbers and the file disagree, and no quoted default says which counts
    return sorted([*entries, *lines], key=lambda e: e.line)


# --- one entry -----------------------------------------------------------------------------


def _entry(
    builder: SbmBuilder,
    ref: EntityRef,
    acc: EntityAcc,
    objects: dict[str, EntityAcc],
    probe: Probe,
) -> _Entry | None:
    """``None`` for a disabled entry: it filters nothing either way."""
    facts = acc.facts
    enabled = facts.get("enabled")
    if _known(enabled) and enabled is not None and enabled.value is False:
        return None
    evidence = _evidence(acc)
    negated_fact = facts.get("negated")
    negated: frozenset[str] | None = frozenset()
    if negated_fact is not None and negated_fact.state is FactState.UNKNOWN:
        negated = None
    elif _known(negated_fact) and negated_fact is not None:
        negated = frozenset(negated_fact.value)

    src = _source(facts.get("src"), negated)
    dst_some, dst_all = _destination(facts.get("dst"), negated, to_device=probe.to_device)
    svc_some, svc_all = _service_match(facts.get("service"), negated, objects, probe)
    intf = _interface(facts.get("interfaces"), probe)
    some = min(src, dst_some, svc_some, intf)
    every = min(src, dst_all, svc_all, intf)

    narrowed = facts.get("narrowed")
    if narrowed is not None and narrowed.state is FactState.UNKNOWN:
        some, every = min(some, Tri.MAYBE), min(every, Tri.MAYBE)
    elif _known(narrowed) and narrowed is not None and narrowed.value is True:
        some, every = min(some, Tri.MAYBE), Tri.NO
    if enabled is not None and enabled.state is FactState.UNKNOWN:
        some, every = min(some, Tri.MAYBE), min(every, Tri.MAYBE)
    if builder.unread_children.get(ref):
        # A line in the entry no mapping read might narrow or widen it (a negation).
        some, every = Tri.MAYBE, Tri.MAYBE
        evidence = (*evidence, *builder.unread_children[ref])

    action = _value(facts.get("action"))
    position = _value(facts.get("position"))
    return _Entry(
        line=min((builder.position(e.line_start) for e in evidence), default=0),
        position=position if isinstance(position, int) else None,
        action=str(action) if action is not None else None,
        some=some,
        all=every,
        evidence=evidence,
    )


def _unplaced(
    builder: SbmBuilder,
    ref: EntityRef,
    acc: EntityAcc,
    objects: dict[str, EntityAcc],
    probe: Probe,
) -> _Entry | None:
    entry = _entry(builder, ref, acc, objects, probe)
    if entry is None:
        return None
    return _Entry(entry.line, entry.position, entry.action, Tri.MAYBE, Tri.MAYBE, entry.evidence)


def _source(fact: FactAcc | None, negated: frozenset[str] | None) -> Tri:
    if negated is None or not _known(fact) or fact is None:
        return Tri.MAYBE
    covers_all = bool(fact.value & CATCH_ALL)
    return Tri.YES if covers_all != ("src" in negated) else Tri.NO


def _destination(
    fact: FactAcc | None, negated: frozenset[str] | None, *, to_device: bool
) -> tuple[Tri, Tri]:
    """Specific destinations are some of the traffic; whether they include the device's own
    address can't be told."""
    if negated is None or not _known(fact) or fact is None:
        return Tri.MAYBE, Tri.MAYBE
    covers_all = bool(fact.value & CATCH_ALL)
    partial = Tri.MAYBE if to_device else Tri.YES
    if "dst" in negated:
        return (Tri.NO, Tri.NO) if covers_all else (partial, Tri.NO)
    return (Tri.YES, Tri.YES) if covers_all else (partial, Tri.NO)


def _interface(fact: FactAcc | None, probe: Probe) -> Tri:
    if probe.interface is None:
        return Tri.YES
    if not _known(fact) or fact is None:
        return Tri.MAYBE
    return Tri.YES if probe.interface in fact.value or "any" in fact.value else Tri.NO


def _service_match(
    fact: FactAcc | None,
    negated: frozenset[str] | None,
    objects: dict[str, EntityAcc],
    probe: Probe,
) -> tuple[Tri, Tri]:
    if negated is None or not _known(fact) or fact is None:
        return Tri.MAYBE, Tri.MAYBE
    some, every = Tri.NO, Tri.NO
    for value in sorted(fact.value):
        s, a = _covers(str(value), objects, probe, depth=0)
        some, every = max(some, s), max(every, a)
    if "service" in negated:
        return every.negate(), some.negate()
    return some, every


def _covers(value: str, objects: dict[str, EntityAcc], probe: Probe, depth: int) -> tuple[Tri, Tri]:
    """Does this service value cover some / all of the probe's traffic?"""
    if value in SERVICE_CATCH_ALL:
        return Tri.YES, Tri.YES
    if depth > 8:
        return Tri.MAYBE, Tri.MAYBE
    named = _named_service(value, objects, probe, depth)
    if named is not None:
        return named
    if probe.service is None:
        return Tri.YES, Tri.NO  # some traffic, not all of it
    proto, _, port_text = probe.service.partition("/")
    port = int(port_text)
    if m := _PORTS.match(value):
        low = int(m.group(2))
        high = int(m.group(3) or low)
        if m.group(1) != proto or not low <= port <= high:
            return Tri.NO, Tri.NO
        # Limited by source port too (``443:1024-65535``): only some clients match.
        return (Tri.YES, Tri.NO) if m.group(4) else (Tri.YES, Tri.YES)
    if m := _PROTO_NUMBER.match(value):
        hit = PROTOCOL_NUMBERS.get(proto) == int(m.group(1))
        return (Tri.YES, Tri.YES) if hit else (Tri.NO, Tri.NO)
    if value.lower() in PROTOCOLS:
        # ``tcp`` alone: the entry may name ports the pack doesn't read.
        return (Tri.MAYBE, Tri.MAYBE) if value.lower() == proto else (Tri.NO, Tri.NO)
    return Tri.MAYBE, Tri.MAYBE  # a name that is no object in the file


def _named_service(
    name: str, objects: dict[str, EntityAcc], probe: Probe, depth: int
) -> tuple[Tri, Tri] | None:
    group = objects.get(f"service_group:{name}")
    if group is not None:
        expanded = group.facts.get("expanded")
        if not _known(expanded) or expanded is None:
            return Tri.MAYBE, Tri.MAYBE
        some, every = Tri.NO, Tri.NO
        for leaf in sorted(expanded.value):
            s, a = _covers(str(leaf), objects, probe, depth + 1)
            some, every = max(some, s), max(every, a)
        return some, every
    obj = objects.get(f"service:{name}")
    if obj is None:
        return None
    members = obj.facts.get("members")
    if not _known(members) or members is None:
        return Tri.MAYBE, Tri.MAYBE
    some, every = Tri.NO, Tri.NO
    for member in sorted(members.value):
        s, a = _covers(str(member), objects, probe, depth + 1)
        some, every = max(some, s), max(every, a)
    dests = obj.facts.get("destinations")
    if dests is not None and dests.state is FactState.UNKNOWN:
        return min(some, Tri.MAYBE), min(every, Tri.MAYBE)
    if _known(dests) and dests is not None and not dests.value & CATCH_ALL:
        return min(some, Tri.MAYBE), Tri.NO  # only to some destinations (FortiOS ``iprange``)
    return some, every


# --- helpers -------------------------------------------------------------------------------


def _known(fact: FactAcc | None) -> bool:
    return fact is not None and fact.state in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT)


def _value(fact: FactAcc | None) -> object:
    return fact.value if _known(fact) and fact is not None else None


def _evidence(acc: EntityAcc) -> tuple[Evidence, ...]:
    lines = {
        (e.file, e.line_start, e.line_end, e.mapping_ref): e
        for e in (*acc.evidence, *(ev for f in acc.facts.values() for ev in f.evidence))
    }
    return tuple(sorted(lines.values(), key=lambda e: (e.line_start, e.mapping_ref or "")))
