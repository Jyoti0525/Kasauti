"""The reference resolver (PLAN §9.1 "the seventh building block"; TODO M2.23).

Configurations point at other named things all the time: ``access-class MGMT-ACL in`` on a vty
line, ``set srcaddr "LAN_GRP"`` in a FortiOS policy, an address group in PAN-OS. After mapping,
the resolver turns every ``ref`` into a :class:`~kasauti.sbm.entities.Reference` entity:

* **resolved or dangling**: does an object of the right kind with that name exist?
  (``acl`` -> ``ObjectDef[acl:<name>]``; ``address|address_group`` tries each kind in turn;
  ``any_object`` accepts any kind). Where the name may point at something the pack doesn't
  read (``unread``: a PAN-OS country), a name no object has is *unknown*, not dangling; where
  it may be written in place (``literal: address``, a PAN-OS ``10.1.1.0/24``), it is a value
  and no reference at all;
* **ACL targets**: can a source the ACL doesn't name get through? That's the chain
  vty -> ACL -> permitted sources, answered by ordered first-match evaluation
  (:mod:`kasauti.policy.firstmatch`) with the vendor's quoted implicit action, and *unknown*
  where an entry that might decide wasn't read;
* **groups**: ``ObjectDef.expanded`` holds members after recursive expansion, and is
  *unknown* if the nesting has a cycle or names an object that doesn't exist;
* **filter entries naming objects** (a FortiOS policy's ``set srcaddr "WEB-SRV"`` or
  ``set service "WEB-PORTS"``): if the address object or group covers every address, ``any``
  is added to the entry's ``src``/``dst``; if the service object or group covers every
  protocol, ``ip`` is added to its ``service``. The object's line is the evidence, so a
  catch-all hidden behind a name is still a permit-any. If the object's extent wasn't read
  (a threat feed's addresses are fetched by the device), or the pack records the name as a
  reference and no object has it, the entry's fact becomes *unknown*: REVIEW, never an
  assumed-harmless PASS.

* **expanding references** (``ref`` with ``expand``): each target's name in the source
  attribute is replaced by the target's members (or ``take``: its ``expanded`` members or
  ``permitted_sources``), so a PAN-OS interface naming its management profile gets the
  protocols the profile allows, and ``aaa authentication login default group TACACS-GRP``
  gets ``tacacs``. A target that lists nothing contributes ``if_empty`` (default: nothing).
  A missing target, or one whose list is unknown, makes the attribute *unknown*.
* **user groups** (FortiOS ``config user group``) expand to the *kinds* of the servers they
  name (``tacacs``), since what a login through the group is checked against is the question.
  Expansions into objects run first, so a Cisco named login list naming a server group
  expands to ``tacacs`` before the vty line naming the list takes it.
* **lines with their own login list** (Cisco ``login authentication VTY-LOGIN``): remote
  logins are checked against what every vty line's list has in common, a line naming no list
  using the device default. ``AuthPolicy.login_methods`` becomes that shared set.
* **security groups named as a source** (AWS ``UserIdGroupPairs``): the members of a group of
  instances, never every address (``NARROW_KINDS``). A pair AWS returns with an account names
  a group that exists (``exists``: AWS drops the account once a referenced group is deleted,
  and a group in the same VPC can't be deleted while referenced): resolved, in the file or
  not. One without an account names a deleted group (a stale rule): dangling. A managed
  prefix list's entries are not in the export, so a rule naming one is *unknown*.
* **filters guarding the device itself** (``Ruleset.applies_to: device``, FortiOS local-in
  policies): for each interface and management protocol it offers, is every source the
  filter doesn't list blocked, on IPv4 and, where offered, IPv6? The protocols for which it
  is go into ``Interface.mgmt_restricted``.

A dangling reference is a finding of its own (rule REF-DANGLING-01): on many platforms a
filter naming a missing ACL filters nothing.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from kasauti.mapping.builder import EntityAcc, EntityRef, FactAcc, RefRecord, SbmBuilder
from kasauti.policy.firstmatch import Decision, Probe, evaluate
from kasauti.sbm.facts import Evidence, FactState

GROUP_KINDS = {
    "address_group": "address",
    "address6_group": "address6",
    "vip_group": "vip",
    "service_group": "service",
    "user_group": "auth_server",
}
LEAF_MEMBERS = frozenset({"user_group"})
"""Groups whose ``expanded`` holds their leaves' members (a server's kind), not leaf names."""
CATCH_ALL = frozenset({"any", "all", "0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0"})
SERVICE_CATCH_ALL = frozenset({"ip", "any"})
"""A service object's members name what it covers; ``ip`` is every IP protocol."""
NARROW_KINDS = frozenset({"security_group"})
"""Kinds that stand for the members of a group of instances, never for every address: "When
you specify a security group as the source or destination for a rule, the rule affects all
instances that are associated with the security groups" (VPC User Guide, Security group
referencing). Their extent is ``some`` whether or not the group is in the file, and whether or
not it still exists (a stale reference matches nothing)."""


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


MGMT_PORTS = {"ssh": "tcp", "telnet": "tcp", "http": "tcp", "https": "tcp"}
"""Management protocols a device filter is evaluated for, and their transport; the port is
``MgmtService[<protocol>].port`` (read, or a quoted default)."""


def resolve_references(builder: SbmBuilder) -> None:
    objects = {key: acc for (etype, key), acc in builder.entities.items() if etype == "ObjectDef"}
    _expand_groups(objects)
    _widen_named_objects(builder, objects)
    for record in sorted(builder.refs, key=lambda r: (r.source, r.attribute, r.name)):
        _reference(builder, objects, record)
    _expand_references(builder, objects)
    _session_login_lists(builder)
    _device_filters(builder, objects)


def _target_key(objects: dict[str, EntityAcc], kinds: str, name: str) -> str | None:
    """The object ``name`` points at: the first of the ``|``-separated kinds that has it."""
    for kind in kinds.split("|"):
        if kind == "any_object":
            found = next((k for k in sorted(objects) if k.split(":", 1)[-1] == name), None)
        else:
            found = f"{kind}:{name}" if f"{kind}:{name}" in objects else None
        if found is not None:
            return found
    return None


def _written_in_place(record: RefRecord) -> bool:
    """An address, prefix or range where the vendor lets one stand for an object."""
    return record.literal == "address" and is_address_literal(record.name)


def is_address_literal(text: str) -> bool:
    """``10.1.1.1``, ``10.1.1.0/24``, ``2001:db8::/32`` or ``10.1.1.1-10.1.1.9``."""
    parts = text.split("-")
    if len(parts) == 2:
        return all(_address(p) is not None for p in parts)
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _reference(builder: SbmBuilder, objects: dict[str, EntityAcc], record: RefRecord) -> None:
    target = _target_key(objects, record.target_kind, record.name)
    if target is None and _written_in_place(record):
        return  # a value, not a name
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
    if target is None:
        if record.exists is not None:
            ref.fact("resolved").set(True, ev)  # the export says it exists; it isn't in the file
        elif record.unread is not None:
            ref.fact("resolved").unknown(ev)  # perhaps what the pack doesn't read
        else:
            ref.fact("resolved").set(False, ev)
        return
    ref.fact("resolved").set(True, ev)
    ref.fact("target").set(f"ObjectDef[{target}]", ev)
    if target.startswith("acl:"):
        decision = evaluate(builder, objects, target.split(":", 1)[1], Probe())
        _record_decision(ref.fact("permits_any"), decision, ev)


def _record_decision(fact: FactAcc, decision: Decision, anchor: Evidence) -> None:
    """The deciding entry is the evidence; where the vendor's implicit action decided, the
    referring line is."""
    evidence = decision.evidence or (anchor,)
    if decision.permitted is None:
        fact.unknown(evidence[0])
    else:
        fact.set(decision.permitted, evidence[0])
    fact.evidence.extend(e for e in evidence[1:] if e not in fact.evidence)


def _expand_references(builder: SbmBuilder, objects: dict[str, EntityAcc]) -> None:
    groups: dict[tuple[EntityRef, str], list[RefRecord]] = {}
    for record in builder.refs:
        if record.expand:
            attr = record.attribute.split(".", 1)[1]
            groups.setdefault((record.source, attr), []).append(record)
    # Objects first: a named login list takes its server group's kind before a line takes it.
    ordered = sorted(groups.items(), key=lambda kv: (kv[0][0][0] != "ObjectDef", kv[0]))
    for (source, attr), records in ordered:
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


def _session_login_lists(builder: SbmBuilder) -> None:
    """Remote logins go through vty lines. Where some name their own method list, what remote
    logins are checked against is what every vty line's list has in common (a line naming no
    list uses the device default): a TACACS+ default doesn't help a line whose list is local.
    Different central servers on different lines share only ``local``; that is a FAIL to
    explain, never a PASS to regret."""
    vty = [
        acc
        for (etype, _), acc in sorted(builder.entities.items())
        if etype == "MgmtSession" and _str(acc.facts.get("kind")) == "vty"
    ]
    own = [s.facts["login_methods"] for s in vty if _present(s.facts.get("login_methods"))]
    if not own:
        return
    policy = builder.entity(builder.singleton("AuthPolicy")).fact("login_methods")
    lists = list(own)
    if any(not _present(s.facts.get("login_methods")) for s in vty):
        lists.append(policy)  # a line with no list of its own uses the default
    evidence = [ev for f in own for ev in f.evidence]
    if not evidence:
        return
    if any(f.state is FactState.UNKNOWN for f in lists):
        policy.unknown(evidence[0])
    elif any(f.state is FactState.ABSENT for f in lists):
        return  # the default list isn't set: the rule's own absent handling applies
    else:
        shared = frozenset.intersection(*(frozenset(f.value) for f in lists))
        before = list(policy.evidence)
        policy.set(shared, evidence[0])
        policy.evidence.extend(e for e in [*evidence[1:], *before] if e not in policy.evidence)
        policy.default_source = None
        return
    policy.evidence.extend(e for e in evidence[1:] if e not in policy.evidence)


def _device_filters(builder: SbmBuilder, objects: dict[str, EntityAcc]) -> None:
    """``Interface.mgmt_restricted``: see the module docstring. A protocol counts only where
    every IP version the interface offers it on is guarded, and the ruleset blocks every
    source it doesn't list."""
    families: dict[str | None, list[str]] = {}
    for (etype, key), acc in sorted(builder.entities.items()):
        if etype == "Ruleset" and _str(acc.facts.get("applies_to")) == "device":
            families.setdefault(_str(acc.facts.get("family")), []).append(key)
    if not families:
        return
    for (etype, name), iface in sorted(builder.entities.items()):
        protocols = iface.facts.get("mgmt_protocols")
        if etype != "Interface" or protocols is None:
            continue
        if protocols.state not in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT):
            continue
        v6 = iface.facts.get("mgmt_protocols_v6")
        verdicts = {
            proto: _protocol_guard(builder, objects, families, interface=name, proto=proto, v6=v6)
            for proto in sorted(set(protocols.value) & MGMT_PORTS.keys())
        }
        restricted = frozenset(p for p, d in verdicts.items() if d.permitted is False)
        unknown = [ev for d in verdicts.values() if d.permitted is None for ev in d.evidence]
        decided = [ev for d in verdicts.values() if d.permitted is False for ev in d.evidence]
        anchor = [*protocols.evidence[:1], *decided, *unknown]
        if not anchor:
            continue
        fact = iface.fact("mgmt_restricted")
        if any(d.permitted is None for d in verdicts.values()):
            fact.unknown(anchor[0])
        else:
            fact.set(restricted, anchor[0])
        fact.evidence.extend(e for e in anchor if e not in fact.evidence)


def _protocol_guard(
    builder: SbmBuilder,
    objects: dict[str, EntityAcc],
    families: dict[str | None, list[str]],
    *,
    interface: str,
    proto: str,
    v6: FactAcc | None,
) -> Decision:
    """Can a source the device filters don't list reach ``proto`` on ``interface``? Over
    IPv4, and over IPv6 unless the interface is known not to offer it there."""
    port = _port(builder, proto)
    if port is None:
        return Decision(None, (), f"the port {proto} listens on isn't known")
    probe = Probe(f"{MGMT_PORTS[proto]}/{port}", interface, to_device=True)
    needed = ["ipv4"]
    if v6 is None or v6.state in (FactState.ABSENT, FactState.UNKNOWN) or proto in v6.value:
        needed.append("ipv6")
    verdicts = [_guarded(builder, objects, families, family, probe) for family in needed]
    permitted = [v for v in verdicts if v.permitted is True]
    if permitted:
        return permitted[0]
    open_ = [v for v in verdicts if v.permitted is None]
    if open_:
        return open_[0]
    return Decision(False, tuple(ev for v in verdicts for ev in v.evidence), verdicts[0].reason)


def _guarded(
    builder: SbmBuilder,
    objects: dict[str, EntityAcc],
    families: dict[str | None, list[str]],
    family: str,
    probe: Probe,
) -> Decision:
    """Blocked if any device ruleset for this IP version blocks it (traffic must pass them
    all); permitted if none exists or none blocks it."""
    rulesets = [*families.get(family, []), *families.get(None, [])]
    if not rulesets:
        return Decision(True, (), f"no filter guards the device over {family}")
    decisions = [evaluate(builder, objects, rs, probe) for rs in rulesets]
    blocked = [d for d in decisions if d.permitted is False]
    if blocked:
        return blocked[0]
    open_ = [d for d in decisions if d.permitted is None]
    return open_[0] if open_ else decisions[0]


def _port(builder: SbmBuilder, proto: str) -> int | None:
    service = builder.entities.get(("MgmtService", proto))
    port = service.facts.get("port") if service else None
    if port is None or port.state not in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT):
        return None
    return int(port.value)


def _present(fact: FactAcc | None) -> bool:
    return fact is not None and fact.state is not FactState.ABSENT


def _str(fact: FactAcc | None) -> str | None:
    if fact is None or fact.state not in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT):
        return None
    return str(fact.value)


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
    A name the pack records as a reference is judged by the object it resolves to; other names
    that are no object of that family (a literal address, ``any``) are left as they are."""
    named: dict[tuple[EntityRef, str], dict[str, RefRecord]] = {}
    for rec in builder.refs:
        named.setdefault((rec.source, rec.attribute.split(".", 1)[1]), {})[rec.name] = rec
    for ref, acc in sorted(builder.entities.items()):
        if ref[0] != "FilterRule":
            continue
        for attr, family in FAMILIES.items():
            fact = acc.facts.get(attr)
            if fact is None or fact.state is not FactState.EXPLICIT:
                continue
            records = named.get((ref, attr), {})
            if fact.value & family.catch_all and _plain(acc, attr):
                # Already every address (or protocol): what else it names can't narrow it.
                continue
            for name in sorted(fact.value):
                record = records.get(name)
                if record is None:
                    extent, ev = _extent(objects, family, name)
                else:
                    extent, ev = _referenced_extent(objects, family, record)
                if extent == "unknown" and ev is not None:
                    fact.unknown(ev)
                    break
                if extent == "any" and ev is not None:
                    fact.add(frozenset({family.widened}), ev)


def _plain(entry: EntityAcc, attr: str) -> bool:
    """The entry is known to match ``attr`` as listed, not its complement (``negated``)."""
    negated = entry.facts.get("negated")
    if negated is None or negated.state is FactState.ABSENT:
        return True
    known = negated.state in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT)
    return known and attr not in negated.value


def _referenced_extent(
    objects: dict[str, EntityAcc], family: _Family, record: RefRecord
) -> tuple[str, Evidence | None]:
    """The extent of the object a reference resolves to. Unresolved, it is unknown (the
    configuration names what it doesn't define, or what the pack doesn't read), unless it
    is an address written in place."""
    if set(record.target_kind.split("|")) <= NARROW_KINDS:
        return "some", None
    target = _target_key(objects, record.target_kind, record.name)
    if target is not None:
        return _object_extent(objects, family, target)
    if _written_in_place(record):
        return ("any", record.evidence) if record.name in family.catch_all else ("some", None)
    return "unknown", record.evidence


def _extent(
    objects: dict[str, EntityAcc], family: _Family, name: str
) -> tuple[str, Evidence | None]:
    """``any`` (covers everything), ``some``, ``unknown`` (extent not read) or ``none`` (no
    object of this family has this name), with the deciding evidence."""
    for key in (f"{family.group}:{name}", f"{family.kind}:{name}"):
        if key in objects:
            return _object_extent(objects, family, key)
    return "none", None


def _object_extent(
    objects: dict[str, EntityAcc], family: _Family, key: str
) -> tuple[str, Evidence | None]:
    obj = objects[key]
    kind = key.split(":", 1)[0]
    if kind in GROUP_KINDS:
        expanded = obj.facts.get("expanded")
        if expanded is None or expanded.state is not FactState.EXPLICIT:
            return "unknown", _first(expanded, obj)
        leaf_kind = GROUP_KINDS[kind]
        leaves = [_leaf_extent(objects, family, f"{leaf_kind}:{leaf}") for leaf in expanded.value]
        if any(extent == "any" for extent, _ in leaves):
            return "any", _first(expanded, obj)
        if any(extent == "unknown" for extent, _ in leaves):
            return "unknown", _first(expanded, obj)
        return "some", None
    members = obj.facts.get("members")
    if members is None or members.state is not FactState.EXPLICIT:
        return "unknown", _first(members, obj)
    # A service limited to some destinations (FortiOS `set iprange`) doesn't cover all traffic.
    dests = obj.facts.get("destinations")
    limited = dests is not None and dests.state is FactState.EXPLICIT and "any" not in dests.value
    if members.value & family.catch_all and not limited:
        return "any", _first(members, obj)
    return "some", None


def _leaf_extent(
    objects: dict[str, EntityAcc], family: _Family, key: str
) -> tuple[str, Evidence | None]:
    """A group's expanded member: a catch-all word (``any``), or an object of the leaf kind."""
    if key.split(":", 1)[1] in family.catch_all:
        return "any", None
    return _object_extent(objects, family, key) if key in objects else ("none", None)


def _first(fact: FactAcc | None, owner: EntityAcc) -> Evidence | None:
    """The deciding line: the fact's, else the object's own, else any line about the object
    (its header's ``kind``). An object always has one, so widening is never skipped."""
    if fact is not None and fact.evidence:
        return fact.evidence[0]
    if owner.evidence:
        return owner.evidence[0]
    return next((f.evidence[0] for _, f in sorted(owner.facts.items()) if f.evidence), None)
