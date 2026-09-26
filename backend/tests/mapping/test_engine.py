"""The mapping engine (PLAN §9; TODO M1.05-M1.07, M2.24)."""

from __future__ import annotations

from typing import Any

import pytest

from kasauti.mapping.engine import MappingResult, apply_mappings
from kasauti.mapping.model import Mapping
from kasauti.packs.model import DefaultEntry
from kasauti.sbm.entities import Entity
from kasauti.sbm.facts import FactState
from kasauti.shape.model import ShapeFamily
from kasauti.shape.parse import parse_text

PROV = {"version": 2, "proposed_by": "test", "approved_by": ["approver:a"]}


def m(**fields: Any) -> Mapping:
    fields.setdefault("vendor", fields["id"].split("/")[0])
    fields.setdefault("provenance", PROV)
    return Mapping.model_validate(fields)


def run(
    config: str,
    mappings: list[Mapping],
    *,
    family: ShapeFamily = ShapeFamily.INDENT,
    negation: tuple[str, ...] = ("no",),
    defaults: list[dict[str, Any]] | None = None,
    os_version: str | None = "17.9",
) -> MappingResult:
    tree = parse_text(config, source_file="r1.cfg", family=family, fallback=False)
    return apply_mappings(
        tree,
        mappings,
        negation_words=negation,
        defaults=[DefaultEntry.model_validate(d) for d in defaults or []],
        os_version=os_version,
        pack_id="v",
    )


def entity(result: MappingResult, etype: str, key: str) -> Entity:
    return next(e for e in result.sbm.all_entities() if e.type == etype and e.key == key)


VTY = m(
    id="v/vty",
    entity={"type": "MgmtSession", "key": "vty {a}-{b}"},
    match="line vty <INT:a> <INT:b>",
    effect={"assert": "MgmtSession.kind", "value": "vty"},
)


def vty_child(name: str, **fields: Any) -> Mapping:
    return m(
        id=f"v/{name}",
        context=["line vty <INT:a> <INT:b>"],
        entity={"type": "MgmtSession", "key": "vty {a}-{b}"},
        **fields,
    )


# --- the four transforms named in TODO M1.05 ---------------------------------------------------


def test_cisco_exec_timeout_minutes_and_seconds_to_seconds() -> None:
    timeout = vty_child(
        "timeout",
        match="exec-timeout <INT:min> <INT:sec>",
        effect={"set": "MgmtSession.idle_timeout_s", "from": {"min": 60, "sec": 1}},
    )
    r = run("line vty 0 4\n exec-timeout 10 0\n", [VTY, timeout])
    fact = entity(r, "MgmtSession", "vty 0-4").idle_timeout_s  # type: ignore[attr-defined]
    assert (fact.value, fact.state) == (600, FactState.EXPLICIT)


def test_fortios_admintimeout_minutes_unit_transform() -> None:
    mapping = m(
        id="f/admintimeout",
        context=["config system global"],
        entity={"type": "MgmtSession", "key": "admin"},
        match="set admintimeout <INT:t>",
        effect={
            "set": "MgmtSession.idle_timeout_s",
            "from": "t",
            "transform": [{"unit": "minutes"}],
        },
    )
    r = run(
        "config system global\n    set admintimeout 5\nend\n",
        [mapping],
        family=ShapeFamily.BLOCK_EDIT,
        negation=("unset",),
    )
    assert entity(r, "MgmtSession", "admin").idle_timeout_s.value == 300  # type: ignore[attr-defined]


@pytest.mark.parametrize(("word", "value"), [("enable", True), ("disable", False)])
def test_enable_disable_value_map(word: str, value: bool) -> None:
    mapping = m(
        id="f/ssh-status",
        entity={"type": "MgmtService", "key": "ssh"},
        match="set ssh-status <STR:s>",
        effect={
            "set": "MgmtService.enabled",
            "from": "s",
            "map": {"enable": True, "disable": False},
        },
    )
    r = run(f"set ssh-status {word}\n", [mapping])
    assert entity(r, "MgmtService", "ssh").enabled.value is value  # type: ignore[attr-defined]


def test_boolean_inversion() -> None:
    mapping = m(
        id="p/disable-telnet",
        entity={"type": "MgmtService", "key": "telnet"},
        match="disable-telnet <STR:v>",
        effect={
            "set": "MgmtService.enabled",
            "from": "v",
            "map": {"yes": True, "no": False},
            "transform": ["invert"],
        },
        negation=None,
    )
    r = run("disable-telnet yes\n", [mapping])
    assert entity(r, "MgmtService", "telnet").enabled.value is False  # type: ignore[attr-defined]


# --- evidence (M1.06) --------------------------------------------------------------------------


def test_every_fact_carries_file_lines_masked_raw_mapping_and_approvers() -> None:
    mapping = m(
        id="v/user",
        entity={"type": "LocalUser", "key": "{name}"},
        match="username <STR:name> password <INT:t> <STR>",
        effect={"set": "LocalUser.hash_type", "from": "t", "map": {"7": "cisco-type-7"}},
    )
    r = run("!\nusername bob password 7 SECRETVALUE\n", [mapping])
    (ev,) = entity(r, "LocalUser", "bob").hash_type.evidence  # type: ignore[attr-defined]
    assert (ev.file, ev.line_start, ev.line_end) == ("r1.cfg", 2, 2)
    assert ev.raw == "username bob password 7 ****"
    assert ev.mapping_ref == "v/user@2"
    assert ev.approved_by == ("approver:a",)


# --- negation, specificity, accumulation --------------------------------------------------------

HTTP = m(
    id="v/http",
    entity={"type": "MgmtService", "key": "http"},
    match="ip http server",
    effect={"assert": "MgmtService.enabled", "value": True},
)


def test_auto_negation_flips_a_boolean_assert() -> None:
    r = run("no ip http server\n", [HTTP])
    fact = entity(r, "MgmtService", "http").enabled  # type: ignore[attr-defined]
    assert (fact.value, fact.state) == (False, FactState.EXPLICIT)
    assert fact.evidence[0].raw == "no ip http server"


def test_negated_set_returns_to_absent_so_a_default_can_apply() -> None:
    timeout = vty_child(
        "timeout",
        match="exec-timeout <INT:min> <INT:sec>",
        effect={"set": "MgmtSession.idle_timeout_s", "from": {"min": 60, "sec": 1}},
    )
    default = {
        "id": "t",
        "attr": "MgmtSession.idle_timeout_s",
        "value": 600,
        "source": "curated",
        "reference": "doc",
    }
    r = run(
        "line vty 0 4\n exec-timeout 0 0\n no exec-timeout\n", [VTY, timeout], defaults=[default]
    )
    fact = entity(r, "MgmtSession", "vty 0-4").idle_timeout_s  # type: ignore[attr-defined]
    assert (fact.value, fact.state) == (600, FactState.VENDOR_DEFAULT)
    assert fact.default_source == "v/defaults.yaml#t"


def test_explicit_negation_pattern_clears_a_member_set() -> None:
    allow = m(
        id="f/allowaccess",
        context=["config system interface", "edit <STR:ifname>"],
        entity={"type": "Interface", "key": "{ifname}"},
        match="set allowaccess <LIST:p>",
        effect={"members": "Interface.mgmt_protocols", "from": "p"},
        negation="unset allowaccess",
    )
    text = 'config system interface\n    edit "wan1"\n        unset allowaccess\n    next\nend\n'
    r = run(text, [allow], family=ShapeFamily.BLOCK_EDIT, negation=("unset",))
    fact = entity(r, "Interface", "wan1").mgmt_protocols  # type: ignore[attr-defined]
    assert (fact.value, fact.state) == (frozenset(), FactState.EXPLICIT)


def test_most_specific_mapping_wins_for_the_same_attribute() -> None:
    general = vty_child(
        "transport",
        match="transport input <LIST:p>",
        effect={"members": "MgmtSession.transport", "from": "p"},
    )
    none = vty_child(
        "transport-none",
        match="transport input none",
        effect={"assert": "MgmtSession.transport", "value": []},
        negation=None,
    )
    r = run("line vty 0 4\n transport input none\n", [VTY, general, none])
    fact = entity(r, "MgmtSession", "vty 0-4").transport  # type: ignore[attr-defined]
    assert fact.value == frozenset()
    assert [e.mapping_id for e in fact.evidence] == ["v/transport-none"]


def test_members_map_vendor_words_and_accumulate() -> None:
    allow = m(
        id="f/allowaccess",
        context=["config system interface", "edit <STR:ifname>"],
        entity={"type": "Interface", "key": "{ifname}"},
        match="set allowaccess <LIST:p>",
        effect={"members": "Interface.mgmt_protocols", "from": "p", "map": {"ping": "icmp"}},
    )
    text = (
        'config system interface\n    edit "wan1"\n'
        "        set allowaccess ping ssh\n    next\nend\n"
    )
    r = run(text, [allow], family=ShapeFamily.BLOCK_EDIT, negation=("unset",))
    assert entity(r, "Interface", "wan1").mgmt_protocols.value == {"icmp", "ssh"}  # type: ignore[attr-defined]


def test_a_word_missing_from_a_set_map_makes_the_fact_unknown_unless_otherwise() -> None:
    access = m(
        id="v/community",
        entity={"type": "SnmpCommunity", "key": "community-{#}"},
        match="snmp-server community <STR:c> <STR:a>",
        effect=[
            {"set": "SnmpCommunity.access", "from": "a", "map": {"RO": "ro", "RW": "rw"}},
            {
                "set": "SnmpCommunity.is_well_known",
                "from": "c",
                "map": {"public": True},
                "otherwise": False,
            },
        ],
        negation=None,
    )
    r = run("snmp-server community s3cret XX\nsnmp-server community public RO\n", [access])
    first = entity(r, "SnmpCommunity", "community-1")
    second = entity(r, "SnmpCommunity", "community-2")
    assert first.access.state is FactState.UNKNOWN  # type: ignore[attr-defined]
    assert first.is_well_known.value is False  # type: ignore[attr-defined]
    assert (second.access.value, second.is_well_known.value) == ("ro", True)  # type: ignore[attr-defined]
    assert "s3cret" not in r.sbm.canonical_json()


# --- near misses: seen but not understood -------------------------------------------------------


def test_a_near_miss_makes_the_fact_unknown_and_unknown_is_sticky() -> None:
    timeout = vty_child(
        "timeout",
        match="exec-timeout <INT:min> <INT:sec>",
        effect={"set": "MgmtSession.idle_timeout_s", "from": {"min": 60, "sec": 1}},
    )
    r = run("line vty 0 4\n exec-timeout 5 0 extra\n exec-timeout 10 0\n", [VTY, timeout])
    fact = entity(r, "MgmtSession", "vty 0-4").idle_timeout_s  # type: ignore[attr-defined]
    assert fact.state is FactState.UNKNOWN
    assert [e.line_start for e in fact.evidence] == [2, 3]
    assert r.stats.near_miss == 1
    assert [s.line_start for s in r.unmapped] == [2]


def test_a_near_miss_that_cannot_name_its_entity_marks_the_type_unread() -> None:
    r = run("line vty 0\n", [VTY])
    assert [e.line_start for e in r.sbm.unread["MgmtSession"]] == [1]


def test_keyword_mismatches_are_not_near_misses() -> None:
    legacy = m(
        id="v/logging",
        entity={"type": "LogTarget", "key": "{h}"},
        match="logging <IP:h>",
        effect={"set": "LogTarget.host", "from": "h"},
    )
    r = run("logging buffered 4096\n", [legacy])
    assert r.stats.near_miss == 0
    assert "LogTarget" not in r.sbm.unread


def test_context_must_be_a_suffix_and_empty_context_means_top_level() -> None:
    top = m(
        id="v/pad",
        entity={"type": "MgmtService", "key": "pad"},
        match="service pad",
        effect={"assert": "MgmtService.enabled", "value": True},
    )
    r = run("interface Gi1\n service pad\n", [top])
    assert not any(e.type == "MgmtService" for e in r.sbm.entities)


# --- versions and defaults (M1.07, M2.24) -------------------------------------------------------


def test_two_os_versions_resolve_mappings_and_defaults_differently() -> None:
    old = m(
        id="v/ssh-old",
        entity={"type": "MgmtService", "key": "ssh"},
        os_versions="<17.0",
        match="ip ssh enable",
        effect={"assert": "MgmtService.enabled", "value": True},
    )
    new = m(
        id="v/ssh-new",
        entity={"type": "MgmtService", "key": "ssh"},
        os_versions=">=17.0",
        match="ip ssh server enable",
        effect={"assert": "MgmtService.enabled", "value": True},
    )
    defaults = [
        {
            "id": "telnet-16",
            "attr": "MgmtService.enabled",
            "entity_key": "telnet",
            "value": True,
            "os_versions": "<17.0",
            "source": "curated",
            "reference": "doc",
        },
        {
            "id": "telnet-17",
            "attr": "MgmtService.enabled",
            "entity_key": "telnet",
            "value": False,
            "os_versions": ">=17.0",
            "source": "curated",
            "reference": "doc",
        },
    ]
    config = "ip ssh enable\nip ssh server enable\n"
    v16 = run(config, [old, new], defaults=defaults, os_version="16.12.4")
    v17 = run(config, [old, new], defaults=defaults, os_version="17.9.4")
    assert [e.mapping_id for e in entity(v16, "MgmtService", "ssh").enabled.evidence] == [
        "v/ssh-old"
    ]  # type: ignore[attr-defined]
    assert [e.mapping_id for e in entity(v17, "MgmtService", "ssh").enabled.evidence] == [
        "v/ssh-new"
    ]  # type: ignore[attr-defined]
    assert entity(v16, "MgmtService", "telnet").enabled.value is True  # type: ignore[attr-defined]
    assert entity(v17, "MgmtService", "telnet").enabled.value is False  # type: ignore[attr-defined]
    assert v16.stats.skipped_for_version == ("v/ssh-new",)


def test_unknown_os_version_uses_only_unscoped_mappings_and_defaults() -> None:
    scoped = m(
        id="v/scoped",
        entity={"type": "MgmtService", "key": "ssh"},
        os_versions=">=17.0",
        match="ip ssh server enable",
        effect={"assert": "MgmtService.enabled", "value": True},
    )
    defaults = [
        {
            "id": "scoped",
            "attr": "MgmtService.enabled",
            "entity_key": "telnet",
            "value": False,
            "os_versions": ">=17.0",
            "source": "curated",
            "reference": "doc",
        }
    ]
    r = run("ip ssh server enable\n", [scoped], defaults=defaults, os_version=None)
    assert not r.sbm.entities
    assert r.stats.skipped_for_version == ("v/scoped",)


def test_conflicting_defaults_are_both_ignored_and_reported() -> None:
    defaults = [
        {
            "id": "a",
            "attr": "MgmtService.enabled",
            "entity_key": "telnet",
            "value": False,
            "source": "curated",
            "reference": "doc",
        },
        {
            "id": "b",
            "attr": "MgmtService.enabled",
            "entity_key": "telnet",
            "value": True,
            "source": "curated",
            "reference": "doc",
        },
    ]
    r = run("hostname R1\n", [], defaults=defaults)
    assert not r.sbm.entities
    assert "conflicting defaults" in r.warnings[0]


def test_none_of_default_marks_a_type_known_empty_only_if_nothing_was_seen() -> None:
    community = m(
        id="v/c",
        entity={"type": "SnmpCommunity", "key": "community-{#}"},
        match="snmp-server community <STR:c> <STR:a>",
        effect={"set": "SnmpCommunity.access", "from": "a", "map": {"RO": "ro"}},
        negation=None,
    )
    empty = [{"id": "none", "none_of": "SnmpCommunity", "source": "curated", "reference": "doc"}]
    assert run("hostname R1\n", [community], defaults=empty).sbm.known_empty == {
        "SnmpCommunity": "v/defaults.yaml#none"
    }
    assert run("snmp-server community x RO\n", [community], defaults=empty).sbm.known_empty == {}
    unread = run("snmp-server community x RO 10 extra\n", [community], defaults=empty)
    assert unread.sbm.known_empty == {}


def test_defaults_never_overwrite_explicit_or_unknown_facts() -> None:
    timeout = vty_child(
        "timeout",
        match="exec-timeout <INT:min> <INT:sec>",
        effect={"set": "MgmtSession.idle_timeout_s", "from": {"min": 60, "sec": 1}},
    )
    default = [
        {
            "id": "t",
            "attr": "MgmtSession.idle_timeout_s",
            "value": 600,
            "source": "curated",
            "reference": "doc",
        }
    ]
    r = run(
        "line vty 0 4\n exec-timeout 0 0\nline vty 5 15\n exec-timeout 1 2 3\n",
        [VTY, timeout],
        defaults=default,
    )
    assert entity(r, "MgmtSession", "vty 0-4").idle_timeout_s.value == 0  # type: ignore[attr-defined]
    assert entity(r, "MgmtSession", "vty 5-15").idle_timeout_s.state is FactState.UNKNOWN  # type: ignore[attr-defined]


def test_a_default_for_every_entity_can_leave_named_ones_out() -> None:
    """FortiOS: the per-server NTP default doesn't describe the implicit FortiGuard source."""
    server = m(
        id="v/ntp",
        entity={"type": "TimeSource", "key": "{h}"},
        match="ntp server <STR:h>",
        effect={"set": "TimeSource.host", "from": "h"},
        negation=None,
    )
    default = [
        {
            "id": "unkeyed",
            "attr": "TimeSource.authenticated",
            "except_keys": ["fortiguard"],
            "value": False,
            "source": "curated",
            "reference": "doc",
        }
    ]
    r = run("ntp server 10.0.0.1\nntp server fortiguard\n", [server], defaults=default)
    assert entity(r, "TimeSource", "10.0.0.1").authenticated.value is False  # type: ignore[attr-defined]
    assert entity(r, "TimeSource", "fortiguard").authenticated.state is FactState.ABSENT  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="every entity"):
        DefaultEntry.model_validate({**default[0], "entity_key": "x"})
    with pytest.raises(ValueError, match="singleton"):
        DefaultEntry.model_validate(
            {**default[0], "attr": "TimePolicy.auth_enforced", "except_keys": ["x"]}
        )


def test_default_values_must_fit_the_attribute_type() -> None:
    with pytest.raises(ValueError, match="doesn't fit"):
        DefaultEntry.model_validate(
            {
                "id": "x",
                "attr": "MgmtSession.idle_timeout_s",
                "value": "600",
                "source": "curated",
                "reference": "doc",
            }
        )
    with pytest.raises(ValueError, match="exactly one"):
        DefaultEntry.model_validate({"id": "x", "source": "curated", "reference": "doc"})


def test_mapping_yaml_rejects_otherwise_without_map() -> None:
    with pytest.raises(ValueError, match="otherwise"):
        m(
            id="v/x",
            entity={"type": "MgmtService", "key": "ssh"},
            match="x <STR:v>",
            effect={"set": "MgmtService.version", "from": "v", "otherwise": "2"},
        )


# --- optional groups and templates (M1 hardening) ------------------------------------------------

ACL = ["ip access-list extended <STR:acl>"]


def test_optional_groups_match_with_and_without_the_optional_words() -> None:
    any_any = m(
        id="v/ace",
        context=ACL,
        entity={"type": "FilterRule", "key": "{acl}:{seq}"},
        match="<INT:seq> <STR:action> ip any any [log]",
        effect=[
            {"assert": "FilterRule.src", "value": ["any"]},
            {"set": "FilterRule.action", "from": "action"},
        ],
        negation=None,
    )
    r = run(
        "ip access-list extended E\n 10 permit ip any any\n 20 deny ip any any log\n", [any_any]
    )
    assert entity(r, "FilterRule", "E:10").action.value == "permit"  # type: ignore[attr-defined]
    assert entity(r, "FilterRule", "E:20").src.value == {"any"}  # type: ignore[attr-defined]


def test_templates_join_several_slots_into_one_value() -> None:
    net = m(
        id="v/ace-net",
        context=ACL,
        entity={"type": "FilterRule", "key": "{acl}:{seq}"},
        match="<INT:seq> <STR:action> ip <IP:sn> <IP:sw> any",
        effect={"members": "FilterRule.src", "template": "{sn} {sw}"},
        negation=None,
    )
    r = run("ip access-list extended E\n 10 permit ip 10.0.0.0 0.0.0.255 any\n", [net])
    assert entity(r, "FilterRule", "E:10").src.value == {"10.0.0.0 0.0.0.255"}  # type: ignore[attr-defined]


USER = ["user <STR:u>"]


def test_a_template_map_renames_only_the_values_it_lists() -> None:
    trusted = m(
        id="v/trusthost",
        context=USER,
        entity={"type": "LocalUser", "key": "{u}"},
        match="trusthost <IP:a> <IP:k>",
        effect={
            "members": "LocalUser.permitted_sources",
            "template": "{a}/{k}",
            "map": {"0.0.0.0/0.0.0.0": "any"},
        },
        negation=None,
    )
    r = run("user a\n trusthost 0.0.0.0 0.0.0.0\n trusthost 10.0.0.0 255.0.0.0\n", [trusted])
    sources = entity(r, "LocalUser", "a").permitted_sources  # type: ignore[attr-defined]
    assert sources.value == {"any", "10.0.0.0/255.0.0.0"}


def test_set_with_a_template_replaces_a_set_with_one_item() -> None:
    """FortiOS: `set protocol IP` covers every protocol until `set protocol-number 47`."""
    service = ["service <STR:n>"]
    ip = m(
        id="v/ip",
        context=service,
        entity={"type": "ObjectDef", "key": "service:{n}"},
        match="protocol ip",
        effect={"assert": "ObjectDef.members", "value": ["ip"]},
        negation=None,
    )
    number = m(
        id="v/number",
        context=service,
        entity={"type": "ObjectDef", "key": "service:{n}"},
        match="protocol-number <INT:p>",
        effect={
            "set": "ObjectDef.members",
            "template": "ip-proto-{p}",
            "map": {"ip-proto-0": "ip"},
        },
        negation=None,
    )
    r = run(
        "service GRE\n protocol ip\n protocol-number 47\n"
        "service ANY\n protocol ip\n protocol-number 0\n",
        [ip, number],
    )
    assert entity(r, "ObjectDef", "service:GRE").members.value == {"ip-proto-47"}  # type: ignore[attr-defined]
    assert entity(r, "ObjectDef", "service:ANY").members.value == {"ip"}  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="use `members`"):
        m(
            id="v/x",
            context=service,
            entity={"type": "ObjectDef", "key": "service:{n}"},
            match="protocol-number <INT:p>",
            effect={"set": "ObjectDef.members", "from": "p"},
        )


def test_combine_any_keeps_a_service_on_whatever_the_order() -> None:
    """PAN-OS: HTTP is on if the MGT port *or* an interface profile turns it on."""
    mgt = m(
        id="v/mgt-http",
        entity={"type": "MgmtService", "key": "http"},
        match="disable-http <STR:v>",
        effect={
            "set": "MgmtService.enabled",
            "from": "v",
            "map": {"yes": False, "no": True},
            "combine": "any",
        },
        negation=None,
    )
    profile = m(
        id="v/profile-http",
        entity={"type": "MgmtService", "key": "http"},
        match="profile http yes",
        effect=[
            {"assert": "MgmtService.enabled", "value": True, "combine": "any"},
            {"assert": "MgmtService.permitted_sources", "value": ["any"], "combine": "any"},
        ],
        negation=None,
    )
    sources = m(
        id="v/permitted",
        entity={"type": "MgmtService", "key": "http"},
        match="permitted-ip <STR:a>",
        effect={"members": "MgmtService.permitted_sources", "from": "a"},
        negation=None,
    )
    for config in (
        "profile http yes\ndisable-http yes\npermitted-ip 10.0.0.0/8\n",
        "permitted-ip 10.0.0.0/8\ndisable-http yes\nprofile http yes\n",
    ):
        http = entity(run(config, [mgt, profile, sources]), "MgmtService", "http")
        assert http.enabled.value is True  # type: ignore[attr-defined]
        assert http.permitted_sources.value == {"any", "10.0.0.0/8"}  # type: ignore[attr-defined]
    off = entity(run("disable-http yes\n", [mgt]), "MgmtService", "http")
    assert off.enabled.value is False  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="flag or a set"):
        m(
            id="v/x",
            entity={"type": "MgmtSession", "key": "a"},
            match="timeout <INT:t>",
            effect={"set": "MgmtSession.idle_timeout_s", "from": "t", "combine": "any"},
        )


PROFILE = [
    m(
        id="v/profile",
        entity={"type": "ObjectDef", "key": "mgmt_profile:{p}"},
        match="profile <STR:p>",
        effect={"assert": "ObjectDef.kind", "value": "mgmt_profile"},
        negation=None,
    ),
    m(
        id="v/profile-svc",
        context=["profile <STR:p>"],
        entity={"type": "ObjectDef", "key": "mgmt_profile:{p}"},
        match="<STR:s> yes",
        effect={"members": "ObjectDef.members", "from": "s"},
        negation=None,
    ),
    m(
        id="v/if-profile",
        context=["interface <STR:i>"],
        entity={"type": "Interface", "key": "{i}"},
        match="management-profile <STR:p>",
        effect={
            "ref": "Interface.mgmt_protocols",
            "from": "p",
            "target": "mgmt_profile",
            "expand": True,
        },
        negation=None,
    ),
]


def test_an_expanding_reference_takes_the_target_members() -> None:
    r = run(
        "profile WEB\n https yes\n telnet no\nprofile NONE\n"
        "interface e1\n management-profile WEB\ninterface e2\n management-profile NONE\n"
        "interface e3\n management-profile MISSING\n",
        PROFILE,
    )
    assert entity(r, "Interface", "e1").mgmt_protocols.value == {"https"}  # type: ignore[attr-defined]
    assert entity(r, "Interface", "e2").mgmt_protocols.value == frozenset()  # type: ignore[attr-defined]
    missing = entity(r, "Interface", "e3").mgmt_protocols  # type: ignore[attr-defined]
    assert missing.state is FactState.UNKNOWN  # a dangling profile: REVIEW, never "nothing"
    with pytest.raises(ValueError, match="set-valued"):
        m(
            id="v/x",
            context=["interface <STR:i>"],
            entity={"type": "Interface", "key": "{i}"},
            match="management-profile <STR:p>",
            effect={"ref": "Interface.zone", "from": "p", "target": "mgmt_profile", "expand": True},
        )


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("a [b [c]]", "nested"),
        ("a [b", "unclosed"),
        ("[a] [b] [c] [d] e", "at most"),
        ("<LIST:x> [log]", "last"),
    ],
)
def test_bad_optional_groups_are_rejected(pattern: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        m(
            id="v/x",
            entity={"type": "MgmtService", "key": "ssh"},
            match=pattern,
            effect={"assert": "MgmtService.enabled", "value": True},
        )


def test_slots_inside_optional_groups_cannot_name_entities() -> None:
    with pytest.raises(ValueError, match="not captured"):
        m(
            id="v/x",
            entity={"type": "LogTarget", "key": "{h}"},
            match="logging [host <IP:h>]",
            effect={"assert": "LogTarget.transport", "value": "udp"},
        )


def test_optional_groups_are_refused_in_contexts() -> None:
    with pytest.raises(ValueError, match="only allowed"):
        m(
            id="v/x",
            context=["interface [<IFNAME:n>]"],
            entity={"type": "MgmtService", "key": "a"},
            match="x",
            effect={"assert": "MgmtService.enabled", "value": True},
        )


SOURCES = [
    *PROFILE,
    m(
        id="v/profile-permit",
        context=["profile <STR:p>"],
        entity={"type": "ObjectDef", "key": "mgmt_profile:{p}"},
        match="permit <STR:a>",
        effect={"members": "ObjectDef.permitted_sources", "from": "a"},
        negation=None,
    ),
    m(
        id="v/if-profile-sources",
        context=["interface <STR:i>"],
        entity={"type": "Interface", "key": "{i}"},
        match="management-profile <STR:p>",
        effect={
            "ref": "Interface.mgmt_permitted_sources",
            "from": "p",
            "target": "mgmt_profile",
            "expand": True,
            "take": "permitted_sources",
            "if_empty": ["any"],
        },
        negation=None,
    ),
]


def test_an_expanding_reference_can_take_another_attribute_and_fill_an_empty_list() -> None:
    r = run(
        "profile NOC\n https yes\n permit 10.0.0.0/8\nprofile OPEN\n https yes\n"
        "interface e1\n management-profile NOC\ninterface e2\n management-profile OPEN\n",
        SOURCES,
    )
    e1, e2 = entity(r, "Interface", "e1"), entity(r, "Interface", "e2")
    assert e1.mgmt_permitted_sources.value == {"10.0.0.0/8"}  # type: ignore[attr-defined]
    assert e2.mgmt_permitted_sources.value == {"any"}  # type: ignore[attr-defined]
    assert e1.mgmt_protocols.value == {"https"}  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="only apply with `expand"):
        m(
            id="v/x",
            context=["interface <STR:i>"],
            entity={"type": "Interface", "key": "{i}"},
            match="management-profile <STR:p>",
            effect={
                "ref": "Interface.mgmt_protocols",
                "from": "p",
                "target": "mgmt_profile",
                "if_empty": ["any"],
            },
        )


LOGIN = [
    m(
        id="v/server-group",
        entity={"type": "ObjectDef", "key": "server_group:{g}"},
        match="group tacacs <STR:g>",
        effect=[
            {"assert": "ObjectDef.kind", "value": "server_group"},
            {"assert": "ObjectDef.members", "value": ["tacacs"]},
        ],
        negation=None,
    ),
    m(
        id="v/login-local",
        match="login local",
        effect={"assert": "AuthPolicy.login_methods", "value": ["local"], "combine": "any"},
        negation=None,
    ),
    m(
        id="v/login-group",
        match="login group <STR:g>",
        effect={
            "ref": "AuthPolicy.login_methods",
            "from": "g",
            "target": "server_group",
            "expand": True,
        },
        negation=None,
    ),
]


def test_expansion_replaces_the_names_and_keeps_items_from_other_lines() -> None:
    r = run("group tacacs TG\nlogin local\nlogin group TG\n", LOGIN)
    policy = entity(r, "AuthPolicy", "auth-policy")
    assert policy.login_methods.value == {"local", "tacacs"}  # type: ignore[attr-defined]


USER_GROUPS = [
    m(
        id="v/server",
        entity={"type": "ObjectDef", "key": "auth_server:{s}"},
        match="tacacs <STR:s>",
        effect=[
            {"assert": "ObjectDef.kind", "value": "auth_server"},
            {"assert": "ObjectDef.members", "value": ["tacacs"]},
        ],
        negation=None,
    ),
    m(
        id="v/user-group",
        entity={"type": "ObjectDef", "key": "user_group:{g}"},
        match="user-group <STR:g> <LIST:m>",
        effect=[
            {"assert": "ObjectDef.kind", "value": "user_group"},
            {"members": "ObjectDef.members", "from": "m"},
        ],
        negation=None,
    ),
    m(
        id="v/admin",
        entity={"type": "LocalUser", "key": "{u}"},
        match="admin <STR:u> remote-group <STR:g>",
        effect={
            "ref": "AuthPolicy.login_methods",
            "from": "g",
            "target": "user_group",
            "expand": True,
            "take": "expanded",
        },
        negation=None,
    ),
]


@pytest.mark.parametrize(
    ("members", "state", "value"),
    [
        ("T1", FactState.EXPLICIT, {"tacacs"}),  # the group resolves to its servers' kind
        ("T1 bob", FactState.UNKNOWN, None),  # a local user isn't a server: can't say
    ],
)
def test_a_user_group_expands_to_the_kinds_of_its_servers(
    members: str, state: FactState, value: set[str] | None
) -> None:
    r = run(f"tacacs T1\nuser-group G {members}\nadmin a remote-group G\n", USER_GROUPS)
    methods = entity(r, "AuthPolicy", "auth-policy").login_methods  # type: ignore[attr-defined]
    assert (methods.state, methods.value) == (state, value)


NAMED_LIST = m(
    id="v/vty-list",
    context=["line vty <INT:a> <INT:b>"],
    entity={"type": "MgmtSession", "key": "vty {a}-{b}"},
    match="login authentication <STR:n>",
    effect=[
        {"set": "MgmtSession.auth_method", "from": "n"},
        {
            "unknown": "AuthPolicy.login_methods",
            "from": "n",
            "unless": ["default"],
            "why": "a named list isn't resolved",
        },
    ],
    negation=None,
)


@pytest.mark.parametrize(
    ("name", "state"), [("default", FactState.EXPLICIT), ("VTY", FactState.UNKNOWN)]
)
def test_an_unknown_effect_marks_the_fact_unless_the_value_is_read_elsewhere(
    name: str, state: FactState
) -> None:
    r = run(
        f"login group TG\ngroup tacacs TG\nline vty 0 4\n login authentication {name}\n",
        [*LOGIN, NAMED_LIST],
    )
    assert entity(r, "AuthPolicy", "auth-policy").login_methods.state is state  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="go together"):
        m(
            id="v/x",
            match="x <STR:n>",
            effect={
                "unknown": "AuthPolicy.login_methods",
                "unless": ["a"],
                "why": "not read at all",
            },
        )
