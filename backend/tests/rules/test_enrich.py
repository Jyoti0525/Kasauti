"""Inferences, exposure-based severity and the reference resolver (TODO M2.22, M2.23, M2.49)."""

from __future__ import annotations

from typing import Any

import pytest

from kasauti.mapping.engine import apply_mappings
from kasauti.mapping.model import Mapping
from kasauti.packs.model import DefaultEntry
from kasauti.rules.enrich import (
    Exposure,
    Inference,
    adjust_severity,
    apply_default_role,
    apply_inferences,
)
from kasauti.rules.evaluate import Evaluator
from kasauti.rules.model import Severity
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.sbm.entities import Device, Interface
from kasauti.sbm.facts import Evidence, Fact, FactState
from kasauti.shape.model import ShapeFamily
from kasauti.shape.parse import parse_text

EV = Evidence(
    file="r.cfg",
    line_start=4,
    line_end=4,
    raw="description WAN uplink",
    mapping_id="v/desc",
    mapping_version=1,
    approved_by=("a",),
)

UNTRUSTED = Inference(
    id="interface.role.untrusted_by_description",
    version=1,
    description="WAN-facing interfaces are untrusted",
    for_each="Interface",
    when="exists(description) and description matches '(?i)wan'",
    set={"role": "untrusted"},
)


def test_inference_fills_absent_facts_with_relabelled_evidence() -> None:
    sbm = SecurityBaselineModel(
        entities=(
            Interface(key="Gi1", description=Fact.explicit("WAN uplink", EV)),
            Interface(key="Gi2", description=Fact.explicit("LAN", EV)),
        )
    )
    out = apply_inferences(sbm, [UNTRUSTED], [])
    gi1, gi2 = out.entities
    assert gi1.role.value == "untrusted"  # type: ignore[attr-defined]
    assert gi1.role.evidence[0].mapping_ref == (  # type: ignore[attr-defined]
        "inference/interface.role.untrusted_by_description@1"
    )
    assert gi2.role.state is FactState.ABSENT  # type: ignore[attr-defined]


def test_inference_never_overrides_what_is_known() -> None:
    admin_set = Fact.explicit("trusted", EV)
    sbm = SecurityBaselineModel(
        entities=(
            Interface(key="Gi1", description=Fact.explicit("WAN uplink", EV), role=admin_set),
        )
    )
    (gi1,) = apply_inferences(sbm, [UNTRUSTED], []).entities
    assert gi1.role.value == "trusted"  # type: ignore[attr-defined]


def test_default_role_only_when_nothing_else_decided() -> None:
    sbm = apply_default_role(SecurityBaselineModel(), "firewall", "p/pack.yaml#default_role")
    assert sbm.device.role.state is FactState.VENDOR_DEFAULT
    inferred = SecurityBaselineModel(device=Device(role=Fact.explicit("switch", EV)))
    assert apply_default_role(inferred, "firewall", "x").device.role.value == "switch"


def _exposure(direction: str, when: str) -> Exposure:
    return Exposure(
        id="x",
        direction=direction,
        scopes=("Device",),
        when=when,  # type: ignore[arg-type]
        explain="because",
    )


@pytest.mark.parametrize(
    ("direction", "when", "expected", "text"),
    [
        ("raise", "true", Severity.CRITICAL, "High (base) → Critical: because"),
        ("lower", "true", Severity.MEDIUM, "High (base) → Medium: compensating: because"),
        ("raise", "false", Severity.HIGH, "High (base)"),
        # A missing fact never moves severity: absence is not evidence either way.
        ("raise", "any(Interface: exists(role))", Severity.HIGH, "High (base)"),
    ],
)
def test_exposure_moves_severity_one_level_and_explains(
    direction: str, when: str, expected: Severity, text: str
) -> None:
    sbm = SecurityBaselineModel()
    ev = Evaluator(sbm, use_defaults=True)
    sev, reason, _ = adjust_severity(Severity.HIGH, [_exposure(direction, when)], ev, sbm.device)
    assert (sev, reason) == (expected, text)


def test_severity_is_capped() -> None:
    sbm = SecurityBaselineModel()
    ev = Evaluator(sbm, use_defaults=True)
    sev, _, _ = adjust_severity(Severity.CRITICAL, [_exposure("raise", "true")], ev, sbm.device)
    assert sev is Severity.CRITICAL


# --- resolver -----------------------------------------------------------------------------------

PROV = {"version": 1, "proposed_by": "t", "approved_by": ["a"]}


def _m(**fields: Any) -> Mapping:
    fields.setdefault("vendor", "v")
    fields.setdefault("provenance", PROV)
    return Mapping.model_validate(fields)


MAPPINGS = [
    _m(
        id="v/acl",
        entity={"type": "ObjectDef", "key": "acl:{acl}"},
        match="ip access-list standard <STR:acl>",
        effect={"assert": "ObjectDef.kind", "value": "acl"},
        negation=None,
    ),
    _m(
        id="v/ace",
        context=["ip access-list standard <STR:acl>"],
        entity={"type": "FilterRule", "key": "{acl}:{seq}"},
        match="<INT:seq> <STR:action> <LIST:src>",
        effect=[
            {"set": "FilterRule.ruleset", "from": "acl"},
            {
                "set": "FilterRule.action",
                "from": "action",
                "map": {"permit": "permit", "deny": "deny"},
            },
            {"members": "FilterRule.src", "from": "src"},
            {"assert": "FilterRule.service", "value": ["ip"]},  # a standard ACL: all of IP
            {"assert": "FilterRule.dst", "value": ["any"]},
        ],
        negation=None,
    ),
    _m(
        id="v/vty",
        entity={"type": "MgmtSession", "key": "vty"},
        match="line vty <INT> <INT>",
        effect={"assert": "MgmtSession.kind", "value": "vty"},
    ),
    _m(
        id="v/ac",
        context=["line vty <INT> <INT>"],
        entity={"type": "MgmtSession", "key": "vty"},
        match="access-class <STR:acl> in",
        effect={"ref": "MgmtSession.access_filter", "from": "acl", "target": "acl"},
    ),
    _m(
        id="v/grp",
        entity={"type": "ObjectDef", "key": "address_group:{g}"},
        match="object-group <STR:g> <LIST:members>",
        effect={"members": "ObjectDef.members", "from": "members"},
        negation=None,
    ),
    _m(
        id="v/obj",
        entity={"type": "ObjectDef", "key": "address:{a}"},
        match="object <STR:a>",
        effect={"assert": "ObjectDef.kind", "value": "address"},
        negation=None,
    ),
]


def _default(attr: str, value: str) -> DefaultEntry:
    return DefaultEntry.model_validate(
        {
            "id": attr.lower().replace(".", "-"),
            "attr": attr,
            "value": value,
            "source": "vendor_doc",
            "reference": "quoted in the vendor's ACL guide",
        }
    )


QUOTED = (_default("Ruleset.unmatched", "deny"), _default("Ruleset.when_empty", "permit"))
"""What a vendor pack quotes about its ACLs (Cisco: implicit deny; an empty list permits all)."""


def _resolve(config: str, defaults: tuple[DefaultEntry, ...] = QUOTED) -> SecurityBaselineModel:
    tree = parse_text(config, source_file="r.cfg", family=ShapeFamily.INDENT, fallback=False)
    return apply_mappings(
        tree, MAPPINGS, negation_words=("no",), defaults=defaults, os_version=None
    ).sbm


def _ref(sbm: SecurityBaselineModel) -> Any:
    return next(e for e in sbm.entities if e.type == "Reference")


@pytest.mark.parametrize(
    ("acl", "resolved", "permits_any"),
    [
        ("ip access-list standard M\n 10 permit 10.0.0.0\n 20 deny any\n", True, False),
        ("ip access-list standard M\n 10 permit any\n", True, True),
        ("", False, None),
    ],
)
def test_reference_chain_vty_to_acl_to_sources(
    acl: str, resolved: bool, permits_any: bool | None
) -> None:
    ref = _ref(_resolve(f"{acl}line vty 0 4\n access-class M in\n"))
    assert ref.key == "MgmtSession[vty].access_filter -> M"
    assert ref.resolved.value is resolved
    assert ref.permits_any.value is permits_any
    assert ref.evidence[0].line_start == (len(acl.splitlines()) + 2)


@pytest.mark.parametrize(
    ("acl", "permits_any"),
    [
        (" 10 deny any\n 20 permit any\n", False),  # first match: the deny decides
        (" 10 permit 10.0.0.0\n", False),  # the implicit deny at the end
        ("", True),  # "an empty access list ... permits all traffic"
    ],
)
def test_the_first_matching_entry_decides_and_the_quoted_end_applies(
    acl: str, permits_any: bool
) -> None:
    ref = _ref(_resolve(f"ip access-list standard M\n{acl}line vty 0 4\n access-class M in\n"))
    assert ref.permits_any.value is permits_any


def test_without_a_quoted_implicit_action_nothing_is_assumed() -> None:
    sbm = _resolve(
        "ip access-list standard M\n 10 permit 10.0.0.0\nline vty 0 4\n access-class M in\n",
        defaults=(),
    )
    assert _ref(sbm).permits_any.state is FactState.UNKNOWN


def test_permit_entries_with_unread_sources_leave_permits_any_unknown() -> None:
    sbm = _resolve("ip access-list standard M\n 10 permit\nline vty 0 4\n access-class M in\n")
    assert _ref(sbm).permits_any.state is FactState.UNKNOWN


def test_groups_expand_recursively_and_cycles_are_unknown() -> None:
    sbm = _resolve(
        "object web1\nobject web2\nobject-group WEB web1 INNER\n"
        "object-group INNER web2\nobject-group LOOP LOOP2\nobject-group LOOP2 LOOP\n"
    )
    groups = {e.key: e for e in sbm.entities if e.type == "ObjectDef"}
    assert groups["address_group:WEB"].expanded.value == {"web1", "web2"}  # type: ignore[attr-defined]
    assert groups["address_group:LOOP"].expanded.state is FactState.UNKNOWN  # type: ignore[attr-defined]


def test_a_group_naming_a_missing_object_is_unknown() -> None:
    sbm = _resolve("object web1\nobject-group WEB web1 ghost\n")
    grp = next(e for e in sbm.entities if e.key == "address_group:WEB")
    assert grp.expanded.state is FactState.UNKNOWN  # type: ignore[attr-defined]
