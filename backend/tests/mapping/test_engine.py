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
