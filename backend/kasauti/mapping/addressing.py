"""Addresses and routes, for role inference (PLAN §12.7; TODO M2.22).

Two interface facts the configuration implies but never states, computed after mapping:

* ``Interface.public_address``: one of its IPv4 addresses is **globally reachable**, as IANA's
  IPv4 Special-Purpose Address Registry defines it. Only the registry decides what isn't
  public (private use, shared CGN space, documentation ranges, benchmarking, …); an address
  it doesn't list is ordinary unicast space and counts. IPv4 only: inside networks number
  their hosts with global IPv6 addresses as a matter of course, so a global IPv6 address says
  nothing about facing the internet.
* ``Interface.default_route``: a default route (``0.0.0.0/0``, ``::/0``) leaves by it, because
  the route names the interface, or because its next hop is on one of the interface's
  subnets (the longest prefix wins, as on a router). A route switched off doesn't count, nor
  does one whose interface isn't in the model (``Null0``).

The facts are evidence for inferences in ``packs/inferences/roles.yaml``, never verdicts on
their own. Their evidence is the lines that decided them.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from kasauti.mapping.builder import EntityAcc, FactAcc, SbmBuilder
from kasauti.sbm.facts import Evidence, FactState

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPInterface = ipaddress.IPv4Interface | ipaddress.IPv6Interface

IANA_IPV4_SPECIAL = "https://www.iana.org/assignments/iana-ipv4-special-registry/"
"""IANA IPv4 Special-Purpose Address Registry, last updated 2025-10-09 (read 2026-09-27)."""

# (address block, "Globally Reachable") for every row of the registry, as published. The most
# specific block containing an address decides. The one terminated row (192.88.99.0/24, 6to4
# relay anycast, deprecated 2015-03) has no values in the registry; it is not counted as public,
# since nobody can be reached there.
_IPV4_SPECIAL: tuple[tuple[str, bool], ...] = (
    ("0.0.0.0/8", False),  # "This network", RFC 791
    ("0.0.0.0/32", False),  # "This host on this network", RFC 1122
    ("10.0.0.0/8", False),  # Private-Use, RFC 1918
    ("100.64.0.0/10", False),  # Shared Address Space, RFC 6598
    ("127.0.0.0/8", False),  # Loopback, RFC 1122
    ("169.254.0.0/16", False),  # Link Local, RFC 3927
    ("172.16.0.0/12", False),  # Private-Use, RFC 1918
    ("192.0.0.0/24", False),  # IETF Protocol Assignments, RFC 6890
    ("192.0.0.0/29", False),  # IPv4 Service Continuity Prefix, RFC 7335
    ("192.0.0.8/32", False),  # IPv4 dummy address, RFC 7600
    ("192.0.0.9/32", True),  # Port Control Protocol Anycast, RFC 7723
    ("192.0.0.10/32", True),  # Traversal Using Relays around NAT Anycast, RFC 8155
    ("192.0.0.170/32", False),  # NAT64/DNS64 Discovery, RFC 8880
    ("192.0.0.171/32", False),  # NAT64/DNS64 Discovery, RFC 8880
    ("192.0.2.0/24", False),  # Documentation (TEST-NET-1), RFC 5737
    ("192.31.196.0/24", True),  # AS112-v4, RFC 7535
    ("192.52.193.0/24", True),  # AMT, RFC 7450
    ("192.88.99.0/24", False),  # Deprecated (6to4 Relay Anycast), RFC 7526: terminated
    ("192.88.99.2/32", False),  # 6a44-relay anycast address, RFC 6751
    ("192.168.0.0/16", False),  # Private-Use, RFC 1918
    ("192.175.48.0/24", True),  # Direct Delegation AS112 Service, RFC 7534
    ("198.18.0.0/15", False),  # Benchmarking, RFC 2544
    ("198.51.100.0/24", False),  # Documentation (TEST-NET-2), RFC 5737
    ("203.0.113.0/24", False),  # Documentation (TEST-NET-3), RFC 5737
    ("240.0.0.0/4", False),  # Reserved, RFC 1112
    ("255.255.255.255/32", False),  # Limited Broadcast, RFC 8190
)
_SPECIAL = sorted(
    ((ipaddress.IPv4Network(block), reachable) for block, reachable in _IPV4_SPECIAL),
    key=lambda row: -row[0].prefixlen,
)
_MULTICAST = ipaddress.IPv4Network("224.0.0.0/4")
"""Not in the special-purpose registry (IANA keeps multicast in its own), and never an
interface's unicast address."""

DEFAULT_ROUTES = frozenset({"0.0.0.0/0", "::/0"})


def globally_reachable(address: ipaddress.IPv4Address) -> bool:
    """Whether IANA's IPv4 special-purpose registry lets this address be reached from the
    internet: the most specific block containing it decides; unlisted unicast space is."""
    for block, reachable in _SPECIAL:
        if address in block:
            return reachable
    return address not in _MULTICAST


def to_cidr(text: str) -> str:
    """One form for an address or prefix with its length: ``198.51.100.2/30`` from
    ``198.51.100.2/30`` or ``198.51.100.2 255.255.255.252``; IPv6 compressed, lower case.

    Raises ``ValueError`` for anything else, a bare address included: its length isn't known.
    A mask must be a contiguous netmask (Cisco's wildcard masks belong to ACLs, not here)."""
    parts = text.split()
    if len(parts) == 2:
        address, mask = parts
        return str(ipaddress.IPv4Interface(f"{ipaddress.IPv4Address(address)}/{_length(mask)}"))
    if len(parts) == 1 and "/" in parts[0]:
        address, length = parts[0].split("/", 1)
        if not length.isdigit():
            raise ValueError(f"{text!r}: the prefix length must be a number")
        return str(ipaddress.ip_interface(f"{address}/{int(length)}"))
    raise ValueError(f"{text!r} is not an address with a prefix length")


def _length(mask: str) -> int:
    value = int(ipaddress.IPv4Address(mask))
    length = bin(value).count("1")
    if value != (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF:
        raise ValueError(f"{mask!r} is not a netmask")
    return length


def mark_addressing(builder: SbmBuilder) -> None:
    """Compute ``Interface.public_address`` and ``Interface.default_route``: see the module
    docstring."""
    interfaces = {
        key: acc for (etype, key), acc in builder.entities.items() if etype == "Interface"
    }
    for _, iface in sorted(interfaces.items()):
        _public(iface)
    for (etype, _), route in sorted(builder.entities.items()):
        if etype == "Route":
            _default_route(route, interfaces)


def _public(iface: EntityAcc) -> None:
    addresses = iface.facts.get("addresses")
    if addresses is None or addresses.state is FactState.ABSENT or not addresses.evidence:
        return
    fact = iface.fact("public_address")
    if addresses.state is FactState.UNKNOWN:
        fact.unknown(addresses.evidence[0])
        fact.evidence.extend(addresses.evidence[1:])
        return
    v4 = [a for a in _interfaces(addresses.value) if a.version == 4 and not a.ip.is_unspecified]
    if not v4:
        return
    fact.set(any(globally_reachable(a.ip) for a in v4), addresses.evidence[0])
    fact.evidence.extend(addresses.evidence[1:])


def _default_route(route: EntityAcc, interfaces: dict[str, EntityAcc]) -> None:
    destination = _known(route.facts.get("destination"))
    enabled = _known(route.facts.get("enabled"))
    if destination not in DEFAULT_ROUTES or enabled is False:
        return
    family = 4 if destination == "0.0.0.0/0" else 6
    named_fact = route.facts.get("interface")
    if named_fact is not None and named_fact.state is FactState.UNKNOWN:
        return  # a blackhole, SD-WAN zone or other router: where it leaves isn't read
    named = _known(named_fact)
    exits: list[tuple[str, list[Evidence]]] = []
    if isinstance(named, str) and named in interfaces:
        exits.append((named, []))
    # A route may name an interface and addresses both (a Junos `next-hop [ 192.0.2.1
    # ge-0/0/1.0 ]`): it leaves by each.
    hops = _known(route.facts.get("next_hops"))
    for hop in sorted(str(h) for h in hops) if isinstance(hops, frozenset) else ():
        found = _subnet_of(_address(hop), family, interfaces)
        if found is not None and found[0] not in (name for name, _ in exits):
            exits.append(found)
    route_lines = [
        *route.evidence,
        *(ev for attr in ("destination", "next_hops", "interface") for ev in _lines(route, attr)),
    ]
    if not route_lines:
        return
    for name, address_lines in exits:
        fact = interfaces[name].fact("default_route")
        lines = [*route_lines, *address_lines]
        if fact.state is FactState.EXPLICIT:
            fact.evidence.extend(e for e in lines if e not in fact.evidence)
            continue
        fact.set(True, lines[0])
        fact.evidence.extend(e for e in lines[1:] if e not in fact.evidence)


def _subnet_of(
    hop: IPAddress | None, family: int, interfaces: dict[str, EntityAcc]
) -> tuple[str, list[Evidence]] | None:
    """The interface whose subnet holds ``hop`` most specifically, with its address lines.
    Unspecified addresses (FortiOS ``set ip 0.0.0.0 0.0.0.0``: none set) and ``/0`` hold
    nothing."""
    if hop is None or hop.version != family:
        return None
    best: tuple[int, str] | None = None
    for name, iface in sorted(interfaces.items()):
        addresses = iface.facts.get("addresses")
        if addresses is None or addresses.state is not FactState.EXPLICIT:
            continue
        for a in _interfaces(addresses.value):
            if a.version != family or a.ip.is_unspecified or a.network.prefixlen == 0:
                continue
            if hop in a.network and (best is None or a.network.prefixlen > best[0]):
                best = (a.network.prefixlen, name)
    if best is None:
        return None
    return best[1], list(interfaces[best[1]].facts["addresses"].evidence)


def _interfaces(values: Iterable[str]) -> list[IPInterface]:
    out: list[IPInterface] = []
    for value in sorted(values):
        try:
            out.append(ipaddress.ip_interface(value))
        except ValueError:
            continue  # the mapping's `cidr` transform only lets valid forms through
    return out


def _address(text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _known(fact: FactAcc | None) -> object:
    if fact is None or fact.state not in (FactState.EXPLICIT, FactState.VENDOR_DEFAULT):
        return None
    return fact.value


def _lines(owner: EntityAcc, attr: str) -> list[Evidence]:
    fact = owner.facts.get(attr)
    return list(fact.evidence) if fact is not None else []
