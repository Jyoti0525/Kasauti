"""TODO M2.22: interface addresses and static routes, and the role inferences that read them
(PLAN §12.7: an interface is untrusted by "public addressing, default-route egress")."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import AuditResult, KnowledgeBase, audit, load_kb
from kasauti.ingest.read import decode, read_file
from kasauti.mapping.addressing import globally_reachable, to_cidr
from kasauti.sbm.facts import FactState

REPO = Path(__file__).resolve().parents[3]
AUTHORED = REPO / "datasets" / "authored"
PUBLIC_BY = "inference/interface.role.untrusted_by_public_address"
ROUTE_BY = "inference/interface.role.untrusted_by_default_route"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def _run(kb: KnowledgeBase, text: str, name: str, vendor: str) -> AuditResult:
    return audit(decode(text.encode(), name), kb, vendor=vendor)


def _entity(result: AuditResult, etype: str, key: str) -> Any:
    return next(e for e in result.sbm.entities if type(e).__name__ == etype and e.key == key)


def _why(fact: Any) -> set[str | None]:
    return {e.mapping_id for e in fact.evidence}


# --- one form for addresses, IANA's word on what is public --------------------------------------


@pytest.mark.parametrize(
    ("text", "cidr"),
    [
        ("198.51.100.2 255.255.255.252", "198.51.100.2/30"),
        ("10.0.0.1/24", "10.0.0.1/24"),
        ("0.0.0.0 0.0.0.0", "0.0.0.0/0"),
        ("2001:DB8::1/64", "2001:db8::1/64"),
        ("::/0", "::/0"),
    ],
)
def test_addresses_are_written_one_way(text: str, cidr: str) -> None:
    assert to_cidr(text) == cidr


@pytest.mark.parametrize(
    "text",
    [
        "10.0.0.1",  # no length: not a guess of /32
        "10.0.0.1 0.0.0.255",  # a wildcard mask belongs to an ACL
        "10.0.0.1 255.0.255.0",  # not contiguous
        "10.0.0.1/33",
        "10.0.0.1/+4",
        "wan1/24",
        "2001:db8::1 255.255.255.0",
    ],
)
def test_anything_else_is_refused(text: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - the mapping turns any of them into unknown
        to_cidr(text)


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("8.8.8.8", True),  # ordinary unicast space the registry doesn't list
        ("10.1.1.1", False),  # RFC 1918
        ("172.31.255.1", False),
        ("192.168.1.1", False),
        ("100.64.0.1", False),  # shared (carrier-grade NAT) space
        ("169.254.1.1", False),
        ("127.0.0.1", False),
        ("192.0.2.1", False),  # the documentation ranges the samples use
        ("198.51.100.2", False),
        ("203.0.113.2", False),
        ("198.18.0.1", False),  # benchmarking
        ("192.0.0.1", False),  # IETF protocol assignments...
        ("192.0.0.9", True),  # ...except the more specific PCP anycast row
        ("192.31.196.1", True),  # AS112
        ("192.88.99.1", False),  # terminated 6to4 relay block: nobody to reach
        ("240.0.0.1", False),  # reserved
        ("224.0.0.5", False),  # multicast is never an interface's unicast address
    ],
)
def test_public_follows_the_iana_registry(address: str, public: bool) -> None:
    assert globally_reachable(ipaddress.IPv4Address(address)) is public


# --- each seed pack reads addresses and routes -------------------------------------------------

CISCO = """\
hostname R1
interface GigabitEthernet1
 ip address 8.8.4.1 255.255.255.252
interface GigabitEthernet2
 ip address 10.0.0.1 255.255.255.0
 ip address 10.0.1.1 255.255.255.0 secondary
 ipv6 address 2001:DB8:1::1/64
 ipv6 address FE80::1 link-local
interface GigabitEthernet3
 ip address 172.16.0.1 255.255.255.252
interface GigabitEthernet4
 no ip address
ip route 0.0.0.0 0.0.0.0 172.16.0.2 name ISP
ip route 10.9.0.0 255.255.0.0 Null0
ipv6 route ::/0 GigabitEthernet2 2001:DB8:1::FFFF
"""


def test_cisco_addresses_routes_and_both_signals(kb: KnowledgeBase) -> None:
    result = _run(kb, CISCO, "r1.cfg", "cisco_ios_xe")
    gi1, gi2, gi3, gi4 = (_entity(result, "Interface", f"GigabitEthernet{n}") for n in (1, 2, 3, 4))
    assert gi2.addresses.value == {"10.0.0.1/24", "10.0.1.1/24", "2001:db8:1::1/64"}
    assert gi4.addresses.state is FactState.EXPLICIT
    assert gi4.addresses.value == frozenset()  # `no ip address`: none, not unknown
    # A public IPv4 address.
    assert gi1.public_address.value is True
    assert gi1.role.value == "untrusted"
    assert _why(gi1.role) == {PUBLIC_BY}
    # The default route's next hop is on Gi3's subnet; the IPv6 one names Gi2.
    assert gi3.public_address.value is False
    assert gi3.default_route.value is True
    assert {e.line_start for e in gi3.default_route.evidence} == {10, 13}
    assert _why(gi3.role) == {ROUTE_BY}
    assert gi2.default_route.value is True
    assert gi2.role.value == "untrusted"
    # A route to Null0 leaves by no interface in the model.
    null = _entity(result, "Route", "10.9.0.0 255.255.0.0 Null0")
    assert (null.destination.value, null.interface.value) == ("10.9.0.0/16", "Null0")
    assert gi4.default_route.state is FactState.ABSENT


ARISTA = """\
hostname A1
interface Ethernet1
   no switchport
   ip address 10.1.0.1/24
interface Ethernet2
   no switchport
   ip address 10.2.0.1/24
ip route 0.0.0.0/0 10.1.0.254 name UPSTREAM
ip route 10.8.0.0/16 Ethernet2 10.2.0.9
"""

JUNOS = """\
system {
    host-name J1;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 172.16.1.2/30;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet6 {
                address 2001:db8:1:1::2/64;
            }
        }
    }
}
routing-options {
    rib inet6.0 {
        static {
            route ::/0 {
                next-hop 2001:db8:1:1::1;
            }
        }
    }
    static {
        route 0.0.0.0/0 next-hop 172.16.1.1;
        route 10.99.0.0/16 discard;
    }
}
"""

FORTIOS = """\
config system interface
    edit "port1"
        set ip 172.16.9.2 255.255.255.252
    next
    edit "port2"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "port3"
        set ip 0.0.0.0 0.0.0.0
    next
end
config router static
    edit 1
        set gateway 172.16.9.1
        set device "port1"
    next
    edit 2
        set dstaddr "BRANCH"
        set device "port2"
    next
    edit 3
        set gateway 10.0.0.9
        set device "port2"
        set status disable
    next
end
"""

PANOS = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip>
                  <entry name="172.16.4.2/30"/>
                </ip>
              </layer3>
            </entry>
            <entry name="ethernet1/2">
              <layer3>
                <ip>
                  <entry name="10.20.0.1/24"/>
                </ip>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <routing-table>
              <ip>
                <static-route>
                  <entry name="to-isp">
                    <nexthop>
                      <ip-address>172.16.4.1</ip-address>
                    </nexthop>
                    <interface>ethernet1/1</interface>
                    <destination>0.0.0.0/0</destination>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


@pytest.mark.parametrize(
    ("text", "name", "vendor", "outside", "inside"),
    [
        (ARISTA, "a1.cfg", "arista_eos", "Ethernet1", "Ethernet2"),
        (JUNOS, "j1.conf", "juniper_junos", "ge-0/0/0.0", None),
        (FORTIOS, "f1.conf", "fortinet_fortios", "port1", "port2"),
        (PANOS, "p1.xml", "paloalto_panos", "ethernet1/1", "ethernet1/2"),
    ],
)
def test_every_seed_pack_finds_where_the_default_route_leaves(
    kb: KnowledgeBase, *, text: str, name: str, vendor: str, outside: str, inside: str | None
) -> None:
    result = _run(kb, text, name, vendor)
    out = _entity(result, "Interface", outside)
    assert out.default_route.value is True
    assert out.role.value == "untrusted"
    assert ROUTE_BY in _why(out.role)
    if inside is not None:
        assert _entity(result, "Interface", inside).default_route.state is FactState.ABSENT


def test_junos_ipv6_default_route_in_block_form(kb: KnowledgeBase) -> None:
    result = _run(kb, JUNOS, "j1.conf", "juniper_junos")
    assert _entity(result, "Interface", "ge-0/0/1.0").default_route.value is True
    assert _entity(result, "Route", "10.99.0.0/16").next_hops.state is FactState.ABSENT


def test_fortios_route_without_dst_is_a_quoted_default_route(kb: KnowledgeBase) -> None:
    result = _run(kb, FORTIOS, "f1.conf", "fortinet_fortios")
    first = _entity(result, "Route", "static:1")
    assert first.destination.state is FactState.VENDOR_DEFAULT
    assert first.destination.value == "0.0.0.0/0"
    assert first.destination.default_source == "fortinet_fortios/defaults.yaml#route-dst-default"
    # A destination named by an address object isn't read, so it's no default route...
    assert _entity(result, "Route", "static:2").destination.state is FactState.UNKNOWN
    # ...and a route switched off leads nowhere.
    assert _entity(result, "Route", "static:3").enabled.value is False
    assert _entity(result, "Interface", "port2").default_route.state is FactState.ABSENT
    # `set ip 0.0.0.0 0.0.0.0` is FortiOS's "no address".
    port3 = _entity(result, "Interface", "port3")
    assert port3.addresses.value == frozenset()
    assert port3.public_address.state is FactState.ABSENT


# --- limits of the signals ---------------------------------------------------------------------


def test_a_global_ipv6_address_is_not_a_public_signal(kb: KnowledgeBase) -> None:
    text = "hostname R1\ninterface GigabitEthernet1\n ipv6 address 2600:1f18::1/64\n"
    gi1 = _entity(_run(kb, text, "r1.cfg", "cisco_ios_xe"), "Interface", "GigabitEthernet1")
    assert gi1.public_address.state is FactState.ABSENT
    assert gi1.role.state is FactState.ABSENT


def test_on_a_switch_the_default_route_is_not_a_signal(kb: KnowledgeBase) -> None:
    text = (
        "hostname SW1\n"
        "interface GigabitEthernet1/0/1\n switchport mode access\n"
        "interface Vlan10\n ip address 10.10.0.2 255.255.255.0\n"
        "ip route 0.0.0.0 0.0.0.0 10.10.0.1\n"
    )
    result = _run(kb, text, "sw1.cfg", "cisco_ios_xe")
    assert result.sbm.device.role.value == "switch"
    vlan = _entity(result, "Interface", "Vlan10")
    assert vlan.default_route.value is True
    assert vlan.role.state is FactState.ABSENT


def test_what_the_admin_said_wins(kb: KnowledgeBase) -> None:
    text = FORTIOS.replace(
        "        set ip 172.16.9.2 255.255.255.252\n",
        "        set ip 172.16.9.2 255.255.255.252\n        set role lan\n",
    )
    port1 = _entity(_run(kb, text, "f1.conf", "fortinet_fortios"), "Interface", "port1")
    assert port1.default_route.value is True
    assert port1.role.value == "trusted"
    assert ROUTE_BY not in _why(port1.role)


# --- the point of it: exposure (PLAN §12.7) ----------------------------------------------------


def test_a_default_route_makes_telnet_critical_where_no_name_says_outside(
    kb: KnowledgeBase,
) -> None:
    """The weak Cisco sample's WAN interface is untrusted twice over: its description says so,
    and the default route leaves by it. With neither, Telnet is High; the default route alone
    makes it Critical again, and the finding says why."""
    weak = read_file(AUTHORED / "cisco_ios_xe" / "weak.cfg").text
    route = "ip route 0.0.0.0 0.0.0.0 203.0.113.1\n"
    unnamed = weak.replace(" description WAN uplink\n", "")
    assert unnamed != weak
    assert route in unnamed

    def telnet(text: str) -> Any:
        result = _run(kb, text, "weak.cfg", "cisco_ios_xe")
        return next(f for f in result.findings if f.rule_id == "MGMT-TELNET-01")

    assert telnet(unnamed.replace(route, "")).severity == "high"
    finding = telnet(unnamed)
    assert finding.severity == "critical"
    assert finding.severity_reason.startswith("High (base) → Critical")
    assert any(e.mapping_id == ROUTE_BY for e in finding.evidence)
