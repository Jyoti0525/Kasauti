"""The reference resolver (PLAN §9.1 "the seventh building block"; TODO M2.23).

Configurations point at other named things all the time: ``access-class MGMT-ACL in`` on a vty
line, ``set srcaddr "LAN_GRP"`` in a FortiOS policy, an address group in PAN-OS. After mapping,
the resolver turns every ``ref`` into a :class:`~kasauti.sbm.entities.Reference` entity:

* **resolved or dangling**: does an object of the right kind with that name exist?
  (``acl`` -> ``ObjectDef[acl:<name>]``; ``any_object`` accepts any kind);
* **ACL targets**: does any entry permit traffic from *any* source? That's the chain
  vty -> ACL -> permitted sources, and it's *unknown* if a permit entry's sources weren't read;
* **groups**: ``ObjectDef.expanded`` holds members after recursive expansion, and is
  *unknown* if the nesting has a cycle or names an object that doesn't exist;
* **filter entries naming objects** (a FortiOS policy's ``set srcaddr "WEB-SRV"`` or
  ``set service "WEB-PORTS"``): if the address object or group covers every address, ``any``
  is added to the entry's ``src``/``dst``; if the service object or group covers every
  protocol, ``ip`` is added to its ``service``. The object's line is the evidence, so a
  catch-all hidden behind a name is still a permit-any. If the object's extent wasn't read,
  the entry's fact becomes *unknown*: REVIEW, never an assumed-harmless PASS.

* **expanding references** (``ref`` with ``expand``): each target's name in the source
  attribute is replaced by the target's members (or ``take``: its ``expanded`` members or
  ``permitted_sources``), so a PAN-OS interface naming its management profile gets the
  protocols the profile allows, and ``aaa authentication login default group TACACS-GRP``
  gets ``tacacs``. A target that lists nothing contributes ``if_empty`` (default: nothing).
  A missing target, or one whose list is unknown, makes the attribute *unknown*.
* **user groups** (FortiOS ``config user group``) expand to the *kinds* of the servers they
  name (``tacacs``), since what a login through the group is checked against is the question.

A dangling reference is a finding of its own (rule REF-DANGLING-01): on many platforms a
filter naming a missing ACL filters nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from kasauti.mapping.builder import EntityAcc, EntityRef, FactAcc, RefRecord, SbmBuilder
from kasauti.sbm.facts import Evidence, FactState

GROUP_KINDS = {"address_group": "address", "service_group": "service", "user_group": "auth_server"}
LEAF_MEMBERS = frozenset({"user_group"})
"""Groups whose ``expanded`` holds their leaves' members (a server's kind), not leaf names."""
CATCH_ALL = frozenset({"any", "all", "0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0"})
SERVICE_CATCH_ALL = frozenset({"ip", "any"})
"""A service object's members name what it covers; ``ip`` is every IP protocol."""


@dataclass(frozen=True, slots=True)
class _Family:
    """How a filter entry attribute names objects: which kinds, and what covers everything."""

    kind: str
    group: str
    catch_all: frozenset[str]
    widened: str
    """The value added to the entry when a named object covers everything."""


ADDRESSES = _Family("address", "address_group", CATCH_ALL, "any")
SERVICES = _Family("service", "service_group", SERVICE_CATCH_ALL, "ip")
FAMILIES = {"src": ADDRESSES, "dst": ADDRESSES, "service": SERVICES}


def resolve_references(builder: SbmBuilder) -> None:
    objects = {key: acc for (etype, key), acc in builder.entities.items() if etype == "ObjectDef"}
    _expand_groups(objects)
    _widen_named_objects(builder, objects)
    for record in sorted(builder.refs, key=lambda r: (r.source, r.attribute, r.name)):
        _reference(builder, objects, record)
    _expand_references(builder, objects)


def _target_key(objects: dict[str, EntityAcc], kind: str, name: str) -> str | None:
    if kind == "any_object":
        return next((k for k in sorted(objects) if k.split(":", 1)[-1] == name), None)
    key = f"{kind}:{name}"
    return key if key in objects else None


def _reference(builder: SbmBuilder, objects: dict[str, EntityAcc], record: RefRecord) -> None:
    source = f"{record.source[0]}[{record.source[1]}]"
    ref = builder.entity(
        ("Reference", f"{source}.{record.attribute.split('.', 1)[1]} -> {record.name}")
    )
    ev = record.evidence
    ref.evidence.append(ev)
    ref.fact("source").set(source, ev)
    ref.fact("attribute").set(record.attribute, ev)
    ref.fact("target_kind").set(record.target_kind, ev)
    ref.fact("name").set(record.name, ev)
    target = _target_key(objects, record.target_kind, record.name)
    ref.fact("resolved").set(target is not None, ev)
    if target is None:
        return
    ref.fact("target").set(f"ObjectDef[{target}]", ev)
    if target.startswith("acl:"):
        unread = builder.unread_children.get(("ObjectDef", target), [])
        _permits_any(builder, ref, target.split(":", 1)[1], ev, unread)


def _expand_references(builder: SbmBuilder, objects: dict[str, EntityAcc]) -> None:
    groups: dict[tuple[EntityRef, str], list[RefRecord]] = {}
    for record in builder.refs:
        if record.expand:
            attr = record.attribute.split(".", 1)[1]
            groups.setdefault((record.source, attr), []).append(record)
    for (source, attr), records in sorted(groups.items()):
        items: set[str] = set()
        evidence: list[Evidence] = []
        unknown: Evidence | None = None
        for record in sorted(records, key=lambda r: r.name):
            target = _target_key(objects, record.target_kind, record.name)
            members = objects[target].facts.get(record.take) if target else None
            if target is None or (members is not None and members.state is FactState.UNKNOWN):
                unknown = unknown or record.evidence
                continue
            evidence.append(record.evidence)
            listed = members.value if members and members.state is FactState.EXPLICIT else None
            if listed:
                items |= listed
                evidence.extend(members.evidence if members else [])
            elif record.if_empty is not None:
                items |= record.if_empty
        fact = builder.entity(source).fact(attr)
        if unknown is not None:
            fact.unknown(unknown)
            continue
        # Items the attribute got from other lines stay; the targets' names give way to what
        # the targets contain.
        names = {r.name for r in records}
        own = fact.value - names if fact.state is FactState.EXPLICIT and fact.value else set()
        fact.set(frozenset(items | own), evidence[0])
        fact.evidence.extend(evidence[1:])


def _permits_any(
    builder: SbmBuilder, ref: EntityAcc, acl: str, ev: Evidence, unread: list[Evidence]
) -> None:
    """TRUE with the permitting entry as evidence; UNKNOWN if a permit entry's sources weren't
    read, or an entry line wasn't understood at all; FALSE only when every entry was read and
    no permit entry has ``any`` as its source."""
    unknown: list[Evidence] = list(unread)
    for (etype, _), acc in sorted(builder.entities.items()):
        if etype != "FilterRule":
            continue
        ruleset = acc.facts.get("ruleset")
        if ruleset is None or ruleset.value != acl:
            continue
        action = acc.facts.get("action")
        src = acc.facts.get("src")
        if action is None or action.state is not FactState.EXPLICIT:
            unknown.extend(acc.evidence or [])
            continue
        if action.value != "permit":
            continue
        if src is None or src.state is not FactState.EXPLICIT:
            unknown.extend(acc.evidence or (action.evidence if action.evidence else []))
            continue
        if "any" in src.value:
            ref.fact("permits_any").set(True, src.evidence[0])
            return
    if unknown:
        ref.fact("permits_any").unknown(unknown[0])
        return
    ref.fact("permits_any").set(False, ev)


def _expand_groups(objects: dict[str, EntityAcc]) -> None:
    for key, acc in sorted(objects.items()):
        kind = key.split(":", 1)[0]
        if kind not in GROUP_KINDS:
            continue
        members = acc.facts.get("members")
        if members is None or members.state is not FactState.EXPLICIT:
            continue
        expanded, ok = _expand(objects, key, set())
        evidence = members.evidence[0]
        if ok:
            acc.fact("expanded").set(frozenset(expanded), evidence)
        else:
            acc.fact("expanded").unknown(evidence)


def _expand(objects: dict[str, EntityAcc], key: str, trail: set[str]) -> tuple[set[str], bool]:
    """Leaf member names of a group. ``ok`` is False on a cycle or a missing object."""
    if key in trail:
        return set(), False
    kind, _ = key.split(":", 1)
    members = objects[key].facts.get("members")
    if members is None or members.state is not FactState.EXPLICIT:
        return set(), False
    leaf_kind = GROUP_KINDS[kind]
    out: set[str] = set()
    ok = True
    for name in sorted(members.value):
        nested = f"{kind}:{name}"
        leaf = f"{leaf_kind}:{name}"
        if nested in objects:
            sub, sub_ok = _expand(objects, nested, trail | {key})
            out |= sub
            ok &= sub_ok
        elif kind in LEAF_MEMBERS:
            kinds = objects[leaf].facts.get("members") if leaf in objects else None
            if kinds is None or kinds.state is not FactState.EXPLICIT:
                ok = False  # a local user, or a server whose kind wasn't read
            else:
                out |= kinds.value
        elif leaf in objects or name in ("any", "all"):
            out.add(name)
        else:
            ok = False
    return out, ok


def _widen_named_objects(builder: SbmBuilder, objects: dict[str, EntityAcc]) -> None:
    """Filter entries whose ``src``/``dst``/``service`` name objects: see the module docstring.
    A name that is no object of that family (a literal address, ``any``) is left as it is."""
    for (etype, _), acc in sorted(builder.entities.items()):
        if etype != "FilterRule":
            continue
        for attr, family in FAMILIES.items():
            fact = acc.facts.get(attr)
            if fact is None or fact.state is not FactState.EXPLICIT:
                continue
            for name in sorted(fact.value):
                extent, ev = _extent(objects, family, name)
                if extent == "unknown" and ev is not None:
                    fact.unknown(ev)
                    break
                if extent == "any" and ev is not None:
                    fact.add(frozenset({family.widened}), ev)


def _extent(
    objects: dict[str, EntityAcc], family: _Family, name: str
) -> tuple[str, Evidence | None]:
    """``any`` (covers everything), ``some``, ``unknown`` (extent not read) or ``none`` (no
    object of this family has this name), with the deciding evidence."""
    group = objects.get(f"{family.group}:{name}")
    if group is not None:
        expanded = group.facts.get("expanded")
        if expanded is None or expanded.state is not FactState.EXPLICIT:
            return "unknown", _first(expanded, group)
        leaves = [
            _extent(objects, family, leaf) if leaf not in family.catch_all else ("any", None)
            for leaf in sorted(expanded.value)
        ]
        if any(kind == "any" for kind, _ in leaves):
            return "any", _first(expanded, group)
        if any(kind == "unknown" for kind, _ in leaves):
            return "unknown", _first(expanded, group)
        return "some", None
    obj = objects.get(f"{family.kind}:{name}")
    if obj is None:
        return "none", None
    members = obj.facts.get("members")
    if members is None or members.state is not FactState.EXPLICIT:
        return "unknown", _first(members, obj)
    # A service limited to some destinations (FortiOS `set iprange`) doesn't cover all traffic.
    dests = obj.facts.get("destinations")
    limited = dests is not None and dests.state is FactState.EXPLICIT and "any" not in dests.value
    if members.value & family.catch_all and not limited:
        return "any", _first(members, obj)
    return "some", None


def _first(fact: FactAcc | None, owner: EntityAcc) -> Evidence | None:
    """The deciding line: the fact's, else the object's own, else any line about the object
    (its header's ``kind``). An object always has one, so widening is never skipped."""
    if fact is not None and fact.evidence:
        return fact.evidence[0]
    if owner.evidence:
        return owner.evidence[0]
    return next((f.evidence[0] for _, f in sorted(owner.facts.items()) if f.evidence), None)
