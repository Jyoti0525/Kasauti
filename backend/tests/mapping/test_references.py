"""TODO M2.23: the reference resolver on the plan's own examples beyond Cisco: FortiOS
``set srcaddr "LAN_GRP"`` and PAN-OS ``<source><member>web-servers</member>`` (PLAN §9.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import AuditResult, KnowledgeBase, audit, load_kb
from kasauti.ingest.read import decode
from kasauti.mapping.model import RefEffect
from kasauti.mapping.resolve import is_address_literal
from kasauti.rules.model import Status
from kasauti.sbm.facts import FactState

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def _entity(result: AuditResult, etype: str, key: str) -> Any:
    return next(e for e in result.sbm.entities if type(e).__name__ == etype and e.key == key)


def _refs(result: AuditResult) -> dict[str, Any]:
    return {e.key: e for e in result.sbm.entities if type(e).__name__ == "Reference"}


def _dangling(result: AuditResult) -> dict[str, Status]:
    return {f.entity_id: f.status for f in result.findings if f.rule_id == "REF-DANGLING-01"}


def _status(result: AuditResult, rule_id: str) -> Status:
    return {r.rule_id: r.status for r in result.rules}[rule_id]


# --- FortiOS ------------------------------------------------------------------------------------

FORTIOS = """\
config firewall address
    edit "all"
    next
    edit "LAN-NET"
        set subnet 10.20.0.0 255.255.255.0
    next
    edit "EVERYWHERE"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall addrgrp
    edit "LAN_GRP"
        set member "LAN-NET"
    next
    edit "WIDE_GRP"
        set member "LAN_GRP" "EVERYWHERE"
    next
end
config firewall vip
    edit "WEB-VIP"
        set extip 198.51.100.10
        set extintf "wan1"
        set mappedip "10.20.0.10"
    next
end
config firewall vipgrp
    edit "WEB-VIPS"
        set interface "wan1"
        set member "WEB-VIP"
    next
end
config system external-resource
    edit "BLOCKLIST"
        set type address
        set resource "https://blocklist.example/ip.txt"
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config firewall policy
    edit 1
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr {src}
        set dstaddr {dst}
        set action accept
        set schedule "always"
        set service {svc}
    next
end
"""


def _fortios(kb: KnowledgeBase, src: str, dst: str = '"all"', svc: str = '"ALL"') -> AuditResult:
    text = FORTIOS.format(src=src, dst=dst, svc=svc)
    return audit(decode(text.encode(), "fgt.conf"), kb, vendor="fortinet_fortios")


def test_fortios_policy_names_link_to_their_objects(kb: KnowledgeBase) -> None:
    """The plan's example: ``set srcaddr "LAN_GRP"`` is a reference to an address group."""
    result = _fortios(kb, '"LAN_GRP"', '"WEB-VIP" "WEB-VIPS"', '"HTTPS"')
    refs = _refs(result)
    src = refs["FilterRule[policy:1].src -> LAN_GRP"]
    assert (src.resolved.value, src.target.value) == (True, "ObjectDef[address_group:LAN_GRP]")
    assert src.target_kind.value == "address|address_group|external_list"
    assert src.evidence[0].raw == 'set srcaddr "LAN_GRP"'
    assert refs["FilterRule[policy:1].dst -> WEB-VIP"].target.value == "ObjectDef[vip:WEB-VIP]"
    assert refs["FilterRule[policy:1].dst -> WEB-VIPS"].target.value == (
        "ObjectDef[vip_group:WEB-VIPS]"
    )
    assert refs["FilterRule[policy:1].service -> HTTPS"].resolved.value is True
    # `all` and `ALL` are FortiOS's own catch-alls, written as values, never references.
    assert not any(k.endswith(("-> all", "-> ALL")) for k in refs)
    assert set(_dangling(result).values()) == {Status.PASS}
    group = _entity(result, "ObjectDef", "address_group:LAN_GRP")
    assert group.expanded.value == frozenset({"LAN-NET"})
    policy = _entity(result, "FilterRule", "policy:1")
    assert policy.src.value == frozenset({"LAN_GRP"})  # the group covers some addresses


def test_fortios_threat_feed_resolves_but_its_addresses_are_unknown(kb: KnowledgeBase) -> None:
    """Fortinet's own example: ``set srcaddr "AWS_IP_Blocklist"``, a threat feed. The device
    fetches its addresses, so what the policy covers can't be read from the file."""
    result = _fortios(kb, '"BLOCKLIST"')
    ref = _refs(result)["FilterRule[policy:1].src -> BLOCKLIST"]
    assert ref.target.value == "ObjectDef[external_list:BLOCKLIST]"
    assert _entity(result, "FilterRule", "policy:1").src.state is FactState.UNKNOWN
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.REVIEW


def test_fortios_catch_all_behind_nested_groups_is_still_permit_any(kb: KnowledgeBase) -> None:
    result = _fortios(kb, '"WIDE_GRP"')
    assert "any" in _entity(result, "FilterRule", "policy:1").src.value
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL


def test_fortios_missing_object_is_dangling_and_never_a_narrow_policy(kb: KnowledgeBase) -> None:
    """Before M2.23 a name the file doesn't define was taken as some addresses: a permit-any
    hidden behind it passed. Now the reference dangles and the policy is unknown."""
    result = _fortios(kb, '"NO-SUCH-GRP"')
    ref = _refs(result)["FilterRule[policy:1].src -> NO-SUCH-GRP"]
    assert ref.resolved.value is False
    assert _dangling(result) == {"Reference[FilterRule[policy:1].src -> NO-SUCH-GRP]": Status.FAIL}
    src = _entity(result, "FilterRule", "policy:1").src
    assert src.state is FactState.UNKNOWN
    assert src.evidence[0].raw == 'set srcaddr "NO-SUCH-GRP"'
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.REVIEW


def test_fortios_missing_service_is_dangling(kb: KnowledgeBase) -> None:
    result = _fortios(kb, '"LAN-NET"', svc='"WEB-PORTS"')
    assert _refs(result)["FilterRule[policy:1].service -> WEB-PORTS"].resolved.value is False
    assert _entity(result, "FilterRule", "policy:1").service.state is FactState.UNKNOWN


def test_fortios_local_in_policy6_names_ipv6_objects(kb: KnowledgeBase) -> None:
    text = """\
config firewall address6
    edit "NOC6"
        set ip6 2001:db8:10::/48
    next
    edit "OPEN6"
    next
end
config firewall addrgrp6
    edit "NOC6-GRP"
        set member "NOC6"
    next
end
config firewall local-in-policy6
    edit 1
        set intf "wan1"
        set srcaddr "NOC6-GRP"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set schedule "always"
    next
    edit 2
        set intf "wan1"
        set srcaddr "OPEN6"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set schedule "always"
    next
end
"""
    result = audit(decode(text.encode(), "fgt.conf"), kb, vendor="fortinet_fortios")
    refs = _refs(result)
    grp = refs["FilterRule[local-in6:1].src -> NOC6-GRP"]
    assert grp.target.value == "ObjectDef[address6_group:NOC6-GRP]"
    assert _entity(result, "ObjectDef", "address6:NOC6").members.value == frozenset(
        {"2001:db8:10::/48"}
    )
    assert _entity(result, "FilterRule", "local-in6:1").src.value == frozenset({"NOC6-GRP"})
    # An address6 without `ip6` covers ::/0 by Fortinet's default, which the pack doesn't
    # apply yet (it depends on the object's type): unknown, never taken as narrow.
    assert refs["FilterRule[local-in6:2].src -> OPEN6"].resolved.value is True
    assert _entity(result, "FilterRule", "local-in6:2").src.state is FactState.UNKNOWN


FORTIOS_DUAL = """\
config firewall address
    edit "LAN-NET"
        set subnet 10.20.0.0 255.255.255.0
    next
end
config firewall address6
    edit "LAN6"
        set ip6 2001:db8:20::/48
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "LAN-NET"
        set dstaddr "LAN-NET"
{extra}        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        # IPv6 from anywhere to anywhere: a permit-any, though the IPv4 half is narrow. Before
        # M2.23 `srcaddr6`/`dstaddr6` weren't read and this passed.
        ('        set srcaddr6 "all"\n        set dstaddr6 "all"\n', Status.FAIL),
        ('        set srcaddr6 "LAN6"\n        set dstaddr6 "LAN6"\n', Status.PASS),
        # "What the source address must NOT be": everything but LAN-NET.
        ("        set srcaddr-negate enable\n        set dstaddr-negate enable\n", Status.FAIL),
        ("        set srcaddr-negate disable\n", Status.PASS),
    ],
)
def test_fortios_ipv6_and_negated_addresses_count(
    kb: KnowledgeBase, extra: str, expected: Status
) -> None:
    text = FORTIOS_DUAL.format(extra=extra)
    result = audit(decode(text.encode(), "fgt.conf"), kb, vendor="fortinet_fortios")
    assert _status(result, "FILTER-PERMIT-ANY-01") is expected


# --- PAN-OS -------------------------------------------------------------------------------------

PANOS = """<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.2">
  <devices>
    <entry name="localhost.localdomain">
      <vsys><entry name="vsys1">
        <address>
          <entry name="web-1"><ip-netmask>10.20.0.10/32</ip-netmask></entry>
          <entry name="web-2"><ip-netmask>10.20.0.11/32</ip-netmask></entry>
          <entry name="internet"><ip-netmask>0.0.0.0/0</ip-netmask></entry>
        </address>
        <address-group>
          <entry name="web-servers">
            <static><member>web-1</member><member>web-2</member></static>
          </entry>
          <entry name="tagged"><dynamic><filter>'web'</filter></dynamic></entry>
        </address-group>
        <region>
          <entry name="BRANCHES"><address><member>192.0.2.0/24</member></address></entry>
        </region>
        <external-list>
          <entry name="bad-ips"><type><ip><url>https://edl.example/ips.txt</url></ip></type></entry>
        </external-list>
        <rulebase><security><rules><entry name="r1">
          <from><member>untrust</member></from><to><member>trust</member></to>
          <source>{source}</source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service>{service}</service>
          <action>allow</action>
        </entry></rules></security></rulebase>
      </entry></vsys>
    </entry>
  </devices>
</config>
"""


def _panos(kb: KnowledgeBase, *sources: str, service: str = "any") -> AuditResult:
    members = "".join(f"<member>{s}</member>" for s in sources)
    text = PANOS.format(source=members, service=f"<member>{service}</member>")
    result = audit(decode(text.encode(), "running-config.xml"), kb)
    assert result.detection.pack_id == "paloalto_panos"
    return result


def test_panos_rule_member_links_to_its_address_group(kb: KnowledgeBase) -> None:
    """The plan's example: ``<source><member>web-servers</member>``."""
    result = _panos(kb, "web-servers")
    ref = _refs(result)["FilterRule[security:r1].src -> web-servers"]
    assert (ref.resolved.value, ref.target.value) == (
        True,
        "ObjectDef[address_group:web-servers]",
    )
    assert ref.evidence[0].raw == "member web-servers"
    assert _entity(result, "ObjectDef", "address_group:web-servers").expanded.value == (
        frozenset({"web-1", "web-2"})
    )
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.PASS
    assert set(_dangling(result).values()) == {Status.PASS}


def test_panos_address_object_covering_everything_is_permit_any(kb: KnowledgeBase) -> None:
    result = _panos(kb, "internet")
    assert "any" in _entity(result, "FilterRule", "security:r1").src.value
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL


@pytest.mark.parametrize(
    ("member", "permit_any"),
    [("10.30.0.0/16", Status.PASS), ("0.0.0.0/0", Status.FAIL), ("10.0.0.1-10.0.0.9", Status.PASS)],
)
def test_panos_addresses_written_in_place_are_values(
    kb: KnowledgeBase, member: str, permit_any: Status
) -> None:
    """ "Specify a Source IP Address or leave the value set to any": no reference."""
    result = _panos(kb, member)
    assert _refs(result) == {}
    assert _status(result, "FILTER-PERMIT-ANY-01") is permit_any


def test_panos_regions_and_external_lists_resolve(kb: KnowledgeBase) -> None:
    result = _panos(kb, "BRANCHES", "bad-ips")
    refs = _refs(result)
    assert refs["FilterRule[security:r1].src -> BRANCHES"].target.value == (
        "ObjectDef[region:BRANCHES]"
    )
    assert refs["FilterRule[security:r1].src -> bad-ips"].target.value == (
        "ObjectDef[external_list:bad-ips]"
    )
    # The list's addresses are fetched by the firewall: what the rule covers isn't known.
    assert _entity(result, "FilterRule", "security:r1").src.state is FactState.UNKNOWN


def test_panos_unfound_name_is_unknown_not_dangling(kb: KnowledgeBase) -> None:
    """A country from the firewall's own list (``CN``) is in no configuration, so a name no
    object has may be one: REVIEW, never a FAIL for a rule that is fine."""
    result = _panos(kb, "CN")
    ref = _refs(result)["FilterRule[security:r1].src -> CN"]
    assert ref.resolved.state is FactState.UNKNOWN
    assert _dangling(result) == {"Reference[FilterRule[security:r1].src -> CN]": Status.REVIEW}
    assert _entity(result, "FilterRule", "security:r1").src.state is FactState.UNKNOWN


def test_panos_dynamic_group_extent_is_unknown(kb: KnowledgeBase) -> None:
    result = _panos(kb, "tagged")
    assert _refs(result)["FilterRule[security:r1].src -> tagged"].resolved.value is True
    assert _entity(result, "FilterRule", "security:r1").src.state is FactState.UNKNOWN


@pytest.mark.parametrize("service", ["service-http", "service-https", "application-default"])
def test_panos_predefined_services_are_not_references(kb: KnowledgeBase, service: str) -> None:
    result = _panos(kb, "web-servers", service=service)
    assert not any(k.startswith("FilterRule[security:r1].service") for k in _refs(result))


def test_panos_missing_service_is_dangling(kb: KnowledgeBase) -> None:
    result = _panos(kb, "web-servers", service="web-ports")
    assert _refs(result)["FilterRule[security:r1].service -> web-ports"].resolved.value is False
    assert _entity(result, "FilterRule", "security:r1").service.state is FactState.UNKNOWN


# --- the mapping language -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "literal"),
    [
        ("10.1.1.1", True),
        ("10.1.1.0/24", True),
        ("2001:db8::/32", True),
        ("10.1.1.1-10.1.1.9", True),
        ("web-servers", False),
        ("CN", False),
        ("10.1.1.1-web", False),
    ],
)
def test_address_literals(text: str, literal: bool) -> None:
    assert is_address_literal(text) is literal


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"expand": True, "unread": "a country from the vendor's list"}, "don't apply"),
        ({"target": []}, "at least one kind"),
        ({"map": {"all": "any"}, "builtin": ["all"]}, "either in `map`"),
    ],
)
def test_ref_options_are_checked(extra: dict[str, Any], message: str) -> None:
    raw = {"ref": "FilterRule.src", "from": "a", "target": "address", **extra}
    with pytest.raises(ValueError, match=message):
        RefEffect.model_validate(raw)
