"""TODO M2.31: AWS security groups and network ACLs, read from the AWS CLI's JSON or YAML.

Covers the record reading (one statement per list item), the pack's references between security
groups (the case moved here from M2.23: resolved, dangling, or in another account), network ACL
first-match by rule number, IPv4 and IPv6 kept apart, and the ways an export can hold less
than it seems (a missing section, several VPCs, a field no mapping reads)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import AuditResult, KnowledgeBase, audit, load_kb
from kasauti.identity.detect import choose, detect_vendor
from kasauti.ingest.read import decode, read_file
from kasauti.mapping.builder import SbmBuilder
from kasauti.mapping.defaults import apply_defaults
from kasauti.mapping.engine import _Engine
from kasauti.mapping.match import Compiled
from kasauti.mapping.resolve import resolve_references
from kasauti.mapping.setform import parse_config
from kasauti.packs.loader import VendorPack
from kasauti.packs.model import IdentitySource
from kasauti.policy.firstmatch import Probe, evaluate
from kasauti.rules.model import Status
from kasauti.sbm.facts import FactState
from kasauti.shape.model import ShapeFamily
from kasauti.shape.structured import parse_records

REPO = Path(__file__).resolve().parents[3]
AWS = REPO / "datasets" / "authored" / "aws_vpc"
VPC = "vpc-0a1b2c3d4e5f60718"
OWNER = "111122223333"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


@pytest.fixture(scope="module")
def pack(kb: KnowledgeBase) -> VendorPack:
    return kb.vendor_packs["aws_vpc"]


# --- building exports ---------------------------------------------------------------------------


def _group(
    gid: str, *ingress: dict[str, Any], egress: tuple[dict[str, Any], ...] = ()
) -> dict[str, Any]:
    return {
        "Description": f"group {gid}",
        "GroupName": gid,
        "IpPermissions": list(ingress),
        "IpPermissionsEgress": list(egress),
        "OwnerId": OWNER,
        "GroupId": gid,
        "Tags": [],
        "VpcId": VPC,
    }


def _perm(
    protocol: str = "-1", ports: tuple[int, int] | None = None, **sources: Any
) -> dict[str, Any]:
    perm: dict[str, Any] = {
        "IpProtocol": protocol,
        "IpRanges": [],
        "Ipv6Ranges": [],
        "PrefixListIds": [],
        "UserIdGroupPairs": [],
    }
    if ports is not None:
        perm["FromPort"], perm["ToPort"] = ports
    perm.update(sources)
    return perm


def _nacl(*entries: dict[str, Any], acl: str = "acl-0a1b2c3d4e5f60701") -> dict[str, Any]:
    return {
        "Associations": [],
        "Entries": list(entries),
        "IsDefault": False,
        "NetworkAclId": acl,
        "Tags": [],
        "VpcId": VPC,
        "OwnerId": OWNER,
    }


def _entry(
    number: int,
    action: str,
    *,
    cidr: str = "0.0.0.0/0",
    protocol: str = "-1",
    ports: tuple[int, int] | None = None,
    egress: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "Egress": egress,
        "Protocol": protocol,
        "RuleAction": action,
        "RuleNumber": number,
    }
    entry["Ipv6CidrBlock" if ":" in cidr else "CidrBlock"] = cidr
    if ports is not None:
        entry["PortRange"] = {"From": ports[0], "To": ports[1]}
    return entry


# The AWS default network ACL's closing rules, as describe-network-acls prints them.
CLOSING = (
    _entry(32767, "deny"),
    _entry(32768, "deny", cidr="::/0"),
    _entry(32767, "deny", egress=True),
    _entry(32768, "deny", cidr="::/0", egress=True),
)


def _export(groups: list[dict[str, Any]], acls: list[dict[str, Any]] | None = None) -> str:
    acls = [_nacl(*CLOSING)] if acls is None else acls
    return json.dumps({"SecurityGroups": groups, "NetworkAcls": acls}, indent=4)


def _audit(kb: KnowledgeBase, text: str, name: str = "vpc.json") -> AuditResult:
    return audit(decode(text.encode(), name), kb)


def _status(result: AuditResult, rule_id: str) -> Status:
    return {r.rule_id: r.status for r in result.rules}[rule_id]


def _refs(result: AuditResult) -> dict[str, Any]:
    return {e.key: e for e in result.sbm.entities if type(e).__name__ == "Reference"}


def _rule(result: AuditResult, key: str) -> Any:
    return next(e for e in result.sbm.entities if type(e).__name__ == "FilterRule" and e.key == key)


def _builder(text: str, pack: VendorPack) -> SbmBuilder:
    tree = parse_config(text, pack, source_file="vpc.json")
    engine = _Engine(tree, [Compiled(m, i) for i, m in enumerate(pack.mappings)], frozenset())
    engine.run(None)
    engine.builder.ensure_rulesets()
    apply_defaults(engine.builder, pack.defaults.defaults, None, "aws_vpc/")
    resolve_references(engine.builder)
    return engine.builder


def _decide(builder: SbmBuilder, ruleset: str, service: str | None) -> bool | None:
    objects = {k: a for (t, k), a in builder.entities.items() if t == "ObjectDef"}
    return evaluate(builder, objects, ruleset, Probe(service)).permitted


# --- reading records ----------------------------------------------------------------------------


def test_records_are_one_statement_per_item_in_key_order() -> None:
    text = json.dumps(
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-1",
                    "Entries": [
                        {"RuleNumber": 100, "PortRange": {"To": 22, "From": 22}, "Egress": False}
                    ],
                }
            ]
        },
        indent=2,
    )
    rows, keys = parse_records(text, {"NetworkAcls": "NetworkAclId"})
    assert keys == {"NetworkAcls"}
    assert [(r.path, r.text) for r in rows] == [
        ((), "NetworkAcls acl-1"),
        (("NetworkAcls acl-1",), "@ NetworkAclId acl-1"),
        (("NetworkAcls acl-1",), "Entries 0"),
        (
            ("NetworkAcls acl-1", "Entries 0"),
            "@ Egress false PortRange.From 22 PortRange.To 22 RuleNumber 100",
        ),
    ]
    # The record's lines span the fields it gathers.
    record = rows[-1]
    assert (record.line_start, record.line_end) == (7, 12)


@pytest.mark.parametrize(
    "text",
    [
        '{"SecurityGroups": [{"GroupId": "sg-1", "GroupId": "sg-2"}]}',
        '{"SecurityGroups": [{"GroupId": "sg-1", "A.B": 1, "A": {"B": 2}}]}',
        '{"SecurityGroups": [], "SecurityGroups": []}',
    ],
)
def test_a_key_given_twice_is_refused_and_read_line_by_line(text: str, pack: VendorPack) -> None:
    """Readers disagree on which of two equal keys counts; a rule must not hide behind that."""
    tree = parse_config(text, pack, source_file="dup.json")
    assert tree.family is ShapeFamily.FLAT
    assert "given twice" in tree.warnings[0]


def test_the_corpus_is_read_whole(kb: KnowledgeBase) -> None:
    for name in ("hardened", "weak"):
        result = audit(read_file(AWS / f"{name}.json"), kb)
        assert result.detection.pack_id == "aws_vpc"
        assert result.detection.chosen_by == "fingerprint"
        assert result.assurance.understood == result.assurance.statements
        assert result.warnings == ()


def test_yaml_output_reads_like_json(kb: KnowledgeBase) -> None:
    """``aws ec2 describe-security-groups --output yaml`` prints the same structure."""
    yaml = pytest.importorskip("yaml")
    data = json.loads((AWS / "weak.json").read_text(encoding="utf-8"))
    as_yaml = audit(decode(yaml.safe_dump(data).encode(), "weak.yaml"), kb)
    as_json = audit(read_file(AWS / "weak.json"), kb)
    assert as_yaml.detection.pack_id == "aws_vpc"
    assert {r.rule_id: r.status for r in as_yaml.rules} == {
        r.rule_id: r.status for r in as_json.rules
    }


def test_minified_json_is_detected(kb: KnowledgeBase) -> None:
    text = json.dumps(json.loads((AWS / "hardened.json").read_text(encoding="utf-8")))
    assert "\n" not in text
    found = choose(detect_vendor(text, list(kb.vendor_packs.values())))
    assert found is not None
    assert found.pack_id == "aws_vpc"


# --- security groups ----------------------------------------------------------------------------


def test_permit_all_from_anywhere_fails(kb: KnowledgeBase) -> None:
    text = _export([_group("sg-1", _perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}]))])
    result = _audit(kb, text)
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL
    rule = _rule(result, "sg-1:ingress:0")
    assert rule.ruleset.value == "sg:sg-1:ingress"
    assert rule.src.value == frozenset({"any"})
    assert rule.dst.value == frozenset({"any"})
    assert rule.service.value == frozenset({"ip"})


def test_an_ipv6_catch_all_and_host_bits_count_as_anywhere(kb: KnowledgeBase) -> None:
    cases: tuple[dict[str, Any], ...] = (
        {"Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        {"IpRanges": [{"CidrIp": "10.1.2.3/0"}]},
    )
    for sources in cases:
        result = _audit(kb, _export([_group("sg-1", _perm(**sources))]))
        assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL, sources


def test_rules_naming_ports_or_narrow_sources_pass(kb: KnowledgeBase) -> None:
    groups = [
        _group("sg-1", _perm("tcp", (443, 443), IpRanges=[{"CidrIp": "0.0.0.0/0"}])),
        _group("sg-2", _perm(IpRanges=[{"CidrIp": "10.0.0.0/8"}])),
        _group("sg-3", _perm(UserIdGroupPairs=[{"GroupId": "sg-1", "UserId": OWNER}])),
    ]
    result = _audit(kb, _export(groups))
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.PASS
    assert _rule(result, "sg-1:ingress:0").service.value == frozenset({"tcp/443-443"})


@pytest.mark.parametrize(
    ("protocol", "ports", "service"),
    [
        ("tcp", (22, 22), "tcp/22-22"),
        ("6", (0, 65535), "tcp/0-65535"),
        ("udp", (161, 162), "udp/161-162"),
        ("17", (53, 53), "udp/53-53"),
        ("icmp", None, "icmp"),
        ("icmpv6", None, "icmp6"),
        ("58", None, "icmp6"),
        ("47", None, "ip-proto-47"),
        ("-1", None, "ip"),
    ],
)
def test_protocols_and_ports(
    protocol: str, ports: tuple[int, int] | None, service: str, kb: KnowledgeBase
) -> None:
    perm = _perm(protocol, ports, IpRanges=[{"CidrIp": "10.0.0.0/8"}])
    if protocol == "icmp":
        perm["FromPort"], perm["ToPort"] = 8, -1  # type 8, every code
    result = _audit(kb, _export([_group("sg-1", perm)]))
    assert _rule(result, "sg-1:ingress:0").service.value == frozenset({service})


def test_egress_rules_are_their_own_ruleset(kb: KnowledgeBase) -> None:
    """AWS: "When you first create a security group, it has an outbound rule that allows all
    outbound traffic"; everything allowed to anywhere is a permit-any."""
    egress = (_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}]),)
    result = _audit(kb, _export([_group("sg-1", egress=egress)]))
    rule = _rule(result, "sg-1:egress:0")
    assert rule.ruleset.value == "sg:sg-1:egress"
    assert rule.dst.value == frozenset({"any"})
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL


# --- references to other security groups (moved here from M2.23) -------------------------------


def test_a_group_in_the_file_resolves_to_it(kb: KnowledgeBase) -> None:
    pair = {"GroupId": "sg-2", "UserId": OWNER}
    result = _audit(kb, _export([_group("sg-1", _perm(UserIdGroupPairs=[pair])), _group("sg-2")]))
    ref = _refs(result)["FilterRule[sg-1:ingress:0].src -> sg-2"]
    assert ref.resolved.value is True
    assert ref.target.value == "ObjectDef[security_group:sg-2]"
    assert ref.target_kind.value == "security_group"
    assert _status(result, "REF-DANGLING-01") is Status.PASS


def test_a_group_aws_returns_with_its_account_exists_outside_the_file(kb: KnowledgeBase) -> None:
    """AWS drops the account once a referenced group is deleted, so one that has it exists."""
    pair = {"GroupId": "sg-0f9e", "UserId": "444455556666"}
    result = _audit(kb, _export([_group("sg-1", _perm("tcp", (22, 22), UserIdGroupPairs=[pair]))]))
    ref = _refs(result)["FilterRule[sg-1:ingress:0].src -> sg-0f9e"]
    assert ref.resolved.value is True
    assert ref.target.state is FactState.ABSENT
    assert _status(result, "REF-DANGLING-01") is Status.PASS


def test_a_deleted_peer_group_is_dangling(kb: KnowledgeBase) -> None:
    """A stale rule: "If the referenced security group is deleted, this value [UserId] is not
    returned"."""
    pair = {
        "GroupId": "sg-dead",
        "PeeringStatus": "active",
        "VpcId": "vpc-peer",
        "VpcPeeringConnectionId": "pcx-1",
    }
    result = _audit(kb, _export([_group("sg-1", _perm(UserIdGroupPairs=[pair]))]))
    ref = _refs(result)["FilterRule[sg-1:ingress:0].src -> sg-dead"]
    assert ref.resolved.value is False
    assert _status(result, "REF-DANGLING-01") is Status.FAIL
    # A group is the instances in it, never every address: all protocols from a stale group
    # is no permit-any, and a stale rule matches nothing.
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.PASS


def test_a_peered_group_that_exists_resolves(kb: KnowledgeBase) -> None:
    pair = {
        "GroupId": "sg-peer",
        "PeeringStatus": "active",
        "UserId": "444455556666",
        "VpcId": "vpc-peer",
        "VpcPeeringConnectionId": "pcx-1",
    }
    result = _audit(kb, _export([_group("sg-1", _perm(UserIdGroupPairs=[pair]))]))
    assert _refs(result)["FilterRule[sg-1:ingress:0].src -> sg-peer"].resolved.value is True


def test_a_prefix_list_exists_but_its_addresses_are_unknown(kb: KnowledgeBase) -> None:
    perm = _perm(PrefixListIds=[{"PrefixListId": "pl-1234abcd"}])
    result = _audit(kb, _export([_group("sg-1", perm)]))
    assert _refs(result)["FilterRule[sg-1:ingress:0].src -> pl-1234abcd"].resolved.value is True
    assert _rule(result, "sg-1:ingress:0").src.state is FactState.UNKNOWN
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.REVIEW


def test_anywhere_beside_a_prefix_list_is_still_anywhere(kb: KnowledgeBase) -> None:
    """What else a rule names can't narrow a source that is already every address."""
    perm = _perm(
        IpRanges=[{"CidrIp": "0.0.0.0/0"}], PrefixListIds=[{"PrefixListId": "pl-1234abcd"}]
    )
    result = _audit(kb, _export([_group("sg-1", perm)]))
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL


# --- what isn't read is never a PASS ------------------------------------------------------------


def test_an_unexpected_field_makes_the_rule_unknown(kb: KnowledgeBase) -> None:
    """A field AWS may add later might change what the rule matches: REVIEW, never PASS."""
    cases: tuple[dict[str, Any], ...] = (
        {"IpRanges": [{"CidrIp": "0.0.0.0/0", "Zone": "a"}]},
        {"IpRanges": [{"AaaNew": "x", "CidrIp": "0.0.0.0/0"}]},
    )
    for sources in cases:
        result = _audit(kb, _export([_group("sg-1", _perm(**sources))]))
        assert _status(result, "FILTER-PERMIT-ANY-01") is Status.REVIEW, sources


def test_an_unreadable_nacl_entry_is_never_skipped(pack: VendorPack) -> None:
    """Its direction is one of its fields; unread, it may be in any ruleset and may come
    first, so the answer is unknown."""
    odd = _entry(50, "deny", protocol="6", ports=(22, 22))
    odd["Unexpected"] = True
    acl = _nacl(odd, _entry(100, "allow"), *CLOSING)
    builder = _builder(_export([], [acl]), pack)
    assert _decide(builder, "nacl:acl-0a1b2c3d4e5f60701:ingress:ipv4", "tcp/22") is None


def test_tcp_without_its_ports_is_not_all_of_tcp(kb: KnowledgeBase) -> None:
    perm = _perm("tcp", IpRanges=[{"CidrIp": "10.0.0.0/8"}])
    result = _audit(kb, _export([_group("sg-1", perm)]))
    assert _rule(result, "sg-1:ingress:0").service.value == frozenset({"tcp"})


def test_a_file_with_one_section_is_partial(kb: KnowledgeBase) -> None:
    groups = [_group("sg-1", _perm("tcp", (443, 443), IpRanges=[{"CidrIp": "0.0.0.0/0"}]))]
    text = json.dumps({"SecurityGroups": groups})
    result = _audit(kb, text)
    assert any("doesn't hold NetworkAcls" in w for w in result.warnings)
    # The groups pass, but the network ACLs aren't shown: no PASS on what the file lacks.
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.REVIEW
    open_group = _group("sg-1", _perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}]))
    weak = json.dumps({"SecurityGroups": [open_group]})
    assert _status(_audit(kb, weak), "FILTER-PERMIT-ANY-01") is Status.FAIL


def test_an_export_of_several_vpcs_is_no_single_device(kb: KnowledgeBase) -> None:
    other = _group("sg-2")
    other["VpcId"] = "vpc-other"
    result = _audit(kb, _export([_group("sg-1"), other]))
    hostname = result.identity["hostname"]
    assert hostname.value is None
    assert "2 different values" in hostname.source
    assert "vpc-other" in hostname.source
    one = _audit(kb, _export([_group("sg-1")]))
    assert one.identity["hostname"].value == VPC


def test_a_peer_vpc_named_in_a_rule_is_not_another_device(kb: KnowledgeBase) -> None:
    pair = {
        "GroupId": "sg-p",
        "PeeringStatus": "active",
        "UserId": "444455556666",
        "VpcId": "vpc-peer",
    }
    result = _audit(kb, _export([_group("sg-1", _perm(UserIdGroupPairs=[pair]))]))
    assert result.identity["hostname"].value == VPC


def test_cloud_filters_are_judged_only_by_rules_for_them(kb: KnowledgeBase) -> None:
    result = audit(read_file(AWS / "weak.json"), kb)
    judged = {r.rule_id for r in result.rules if r.status is not Status.NOT_APPLICABLE}
    assert judged == {"FILTER-PERMIT-ANY-01", "REF-DANGLING-01"}
    assert result.sbm.device.role.value == "cloud_filter"


def test_identity_sources_are_checked() -> None:
    with pytest.raises(ValueError, match="exactly one of"):
        IdentitySource.model_validate(
            {"source": "config", "field": "VpcId", "pattern": "hostname <STR:value>"}
        )
    with pytest.raises(ValueError, match="configuration's records"):
        IdentitySource.model_validate({"source": "show_version", "field": "VpcId"})


# --- network ACLs: first match by rule number ---------------------------------------------------


def test_lowest_rule_number_decides_whatever_the_file_order(pack: VendorPack) -> None:
    """AWS: "Rules are evaluated starting with the lowest numbered rule.\""""
    acl = _nacl(
        _entry(200, "allow", protocol="6", ports=(22, 22)),
        _entry(100, "deny", protocol="6", ports=(22, 22)),
        *CLOSING,
    )
    builder = _builder(_export([], [acl]), pack)
    ingress = "nacl:acl-0a1b2c3d4e5f60701:ingress:ipv4"
    assert _decide(builder, ingress, "tcp/22") is False
    assert _decide(builder, ingress, "tcp/443") is False  # the closing * rule
    swapped = _nacl(
        _entry(100, "allow", protocol="6", ports=(22, 22)),
        _entry(200, "deny", protocol="6", ports=(22, 22)),
        *CLOSING,
    )
    assert _decide(_builder(_export([], [swapped]), pack), ingress, "tcp/22") is True


def test_ipv4_and_ipv6_rules_are_evaluated_apart(pack: VendorPack) -> None:
    """AWS: "IPv4 and IPv6 traffic are evaluated separately.\""""
    acl = _nacl(_entry(50, "deny", cidr="::/0"), _entry(100, "allow"), *CLOSING)
    builder = _builder(_export([], [acl]), pack)
    assert _decide(builder, "nacl:acl-0a1b2c3d4e5f60701:ingress:ipv4", "tcp/22") is True
    assert _decide(builder, "nacl:acl-0a1b2c3d4e5f60701:ingress:ipv6", "tcp/22") is False


def test_the_default_network_acl_is_a_permit_any(kb: KnowledgeBase) -> None:
    acl = _nacl(_entry(100, "allow"), _entry(100, "allow", egress=True), *CLOSING)
    result = _audit(kb, _export([], [acl]))
    assert _status(result, "FILTER-PERMIT-ANY-01") is Status.FAIL
    rule = _rule(result, "acl-0a1b2c3d4e5f60701:0")
    assert (rule.ruleset.value, rule.position.value, rule.action.value) == (
        "nacl:acl-0a1b2c3d4e5f60701:ingress:ipv4",
        100,
        "permit",
    )


def test_security_groups_are_permit_only_and_deny_the_rest(pack: VendorPack) -> None:
    groups = [_group("sg-1", _perm("tcp", (443, 443), IpRanges=[{"CidrIp": "0.0.0.0/0"}]))]
    builder = _builder(_export(groups), pack)
    assert _decide(builder, "sg:sg-1:ingress", "tcp/443") is True
    assert _decide(builder, "sg:sg-1:ingress", "tcp/22") is False
