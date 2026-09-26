"""The reference resolver (PLAN §9.1 "the seventh building block"; TODO M2.23).

Configurations point at other named things all the time: ``access-class MGMT-ACL in`` on a vty
line, ``set srcaddr "LAN_GRP"`` in a FortiOS policy, an address group in PAN-OS. After mapping,
the resolver turns every ``ref`` into a :class:`~kasauti.sbm.entities.Reference` entity:

* **resolved or dangling**: does an object of the right kind with that name exist?
  (``acl`` -> ``ObjectDef[acl:<name>]``; ``any_object`` accepts any kind);
* **ACL targets**: does any entry permit traffic from *any* source? That's the chain
  vty -> ACL -> permitted sources, and it's *unknown* if a permit entry's sources weren't read;
* **groups**: ``ObjectDef.expanded`` holds members after recursive expansion, and is
  *unknown* if the nesting has a cycle or names an object that doesn't exist.

A dangling reference is a finding of its own (rule REF-DANGLING-01): on many platforms a
filter naming a missing ACL filters nothing.
"""

from __future__ import annotations

from kasauti.mapping.builder import EntityAcc, RefRecord, SbmBuilder
from kasauti.sbm.facts import Evidence, FactState

GROUP_KINDS = {"address_group": "address", "service_group": "service"}


def resolve_references(builder: SbmBuilder) -> None:
    objects = {key: acc for (etype, key), acc in builder.entities.items() if etype == "ObjectDef"}
    for record in sorted(builder.refs, key=lambda r: (r.source, r.attribute, r.name)):
        _reference(builder, objects, record)
    _expand_groups(objects)


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
        if nested in objects:
            sub, sub_ok = _expand(objects, nested, trail | {key})
            out |= sub
            ok &= sub_ok
        elif f"{leaf_kind}:{name}" in objects or name in ("any", "all"):
            out.add(name)
        else:
            ok = False
    return out, ok
