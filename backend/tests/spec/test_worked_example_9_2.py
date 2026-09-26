"""PLAN §9.2 as an executable spec: one property (Telnet), eight platforms, six primitives.

Part 1: every mapping is valid in the mapping language.
Part 2: the engine turns each config snippet, in its own shape family, into exactly the
expected facts (written in M0 as the contract for M1, TODO M0.19, and green since M1.05).

Defaults here are illustrative (they test the mechanism); real defaults are curated from
vendor documentation with the seed packs (TODO M2.26–M2.32).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

from kasauti.mapping.engine import apply_mappings
from kasauti.mapping.model import Mapping
from kasauti.packs.loader import load_ruleset
from kasauti.packs.model import DefaultEntry
from kasauti.rules.evaluate import with_derived
from kasauti.shape.model import ShapeFamily
from kasauti.shape.parse import parse_text

PACKS = Path(__file__).resolve().parents[3] / "packs"
DERIVATIONS = load_ruleset(PACKS / "rules", PACKS / "derivations").derivations

PROV = "provenance: {version: 1, proposed_by: 'spec:plan-9.2'}"


@dataclass(frozen=True)
class Case:
    name: str
    family: ShapeFamily
    negation_words: tuple[str, ...]
    mappings: str
    config: str
    expect: tuple[tuple[str, str, str, Any, str], ...]
    """(entity type, key, attribute, value, state)"""
    derived: dict[str, bool] = field(default_factory=dict)
    defaults: tuple[dict[str, Any], ...] = ()
    os_version: str | None = None


CASES = [
    Case(
        "cisco_ios_xe: entity + members",
        ShapeFamily.INDENT,
        ("no",),
        f"""
- id: cisco_ios_xe/line-vty
  vendor: cisco_ios_xe
  entity: {{type: MgmtSession, key: "vty {{first}}-{{last}}"}}
  match: "line vty <INT:first> <INT:last>"
  effect: {{assert: MgmtSession.kind, value: vty}}
  {PROV}
- id: cisco_ios_xe/vty-transport-input
  vendor: cisco_ios_xe
  context: ["line vty <INT:first> <INT:last>"]
  entity: {{type: MgmtSession, key: "vty {{first}}-{{last}}"}}
  match: "transport input <LIST:protocols>"
  effect: {{members: MgmtSession.transport, from: protocols}}
  {PROV}
""",
        "line vty 0 4\n transport input ssh telnet\n",
        (("MgmtSession", "vty 0-4", "transport", {"ssh", "telnet"}, "explicit"),),
        derived={"management.telnet_reachable": True},
    ),
    Case(
        "juniper_junos: assert (presence)",
        ShapeFamily.BRACE,
        ("delete",),
        f"""
- id: juniper_junos/services-telnet
  vendor: juniper_junos
  context: ["system", "services"]
  entity: {{type: MgmtService, key: telnet}}
  match: "telnet"
  effect: {{assert: MgmtService.enabled, value: true}}
  {PROV}
""",
        "system {\n    services {\n        telnet;\n    }\n}\n",
        (("MgmtService", "telnet", "enabled", True, "explicit"),),
    ),
    Case(
        "fortinet_fortios: entity + members (with value map)",
        ShapeFamily.BLOCK_EDIT,
        ("unset",),
        f"""
- id: fortinet_fortios/interface-allowaccess
  vendor: fortinet_fortios
  os_versions: ">=6.0"
  context: ["config system interface", "edit <STR:ifname>"]
  entity: {{type: Interface, key: "{{ifname}}"}}
  match: "set allowaccess <LIST:protocols>"
  effect: {{members: Interface.mgmt_protocols, from: protocols,
           map: {{ping: icmp, https: https, http: http, ssh: ssh, telnet: telnet, snmp: snmp}}}}
  negation: "unset allowaccess"
  {PROV}
""",
        'config system interface\n    edit "wan1"\n        set allowaccess ping https telnet\n'
        "    next\nend\n",
        (("Interface", "wan1", "mgmt_protocols", {"icmp", "https", "telnet"}, "explicit"),),
        os_version="7.2.8",
    ),
    Case(
        "paloalto_panos: set + inversion",
        ShapeFamily.XML,
        (),
        f"""
- id: paloalto_panos/disable-telnet
  vendor: paloalto_panos
  context: ["deviceconfig", "system", "service"]
  entity: {{type: MgmtService, key: telnet}}
  match: "disable-telnet <STR:v>"
  effect: {{set: MgmtService.enabled, from: v, map: {{"yes": true, "no": false}},
           transform: [invert]}}
  negation: null
  {PROV}
""",
        '<config><devices><entry name="localhost.localdomain"><deviceconfig><system><service>'
        "<disable-telnet>no</disable-telnet></service></system></deviceconfig></entry></devices>"
        "</config>\n",
        (("MgmtService", "telnet", "enabled", True, "explicit"),),
    ),
    Case(
        "huawei_vrp: assert + negation(undo), enabled",
        ShapeFamily.INDENT,
        ("undo",),
        f"""
- id: huawei_vrp/telnet-server
  vendor: huawei_vrp
  entity: {{type: MgmtService, key: telnet}}
  match: "telnet server enable"
  effect: {{assert: MgmtService.enabled, value: true}}
  {PROV}
""",
        "telnet server enable\n",
        (("MgmtService", "telnet", "enabled", True, "explicit"),),
    ),
    Case(
        "huawei_vrp: assert + negation(undo), disabled",
        ShapeFamily.INDENT,
        ("undo",),
        f"""
- id: huawei_vrp/telnet-server
  vendor: huawei_vrp
  entity: {{type: MgmtService, key: telnet}}
  match: "telnet server enable"
  effect: {{assert: MgmtService.enabled, value: true}}
  {PROV}
""",
        "undo telnet server enable\n",
        (("MgmtService", "telnet", "enabled", False, "explicit"),),
    ),
    Case(
        "mikrotik_routeros: entity + set + inversion",
        ShapeFamily.PATH_COMMAND,
        (),
        f"""
- id: mikrotik_routeros/ip-service-telnet
  vendor: mikrotik_routeros
  context: ["/ip service"]
  entity: {{type: MgmtService, key: telnet}}
  match: "set telnet disabled= <STR:v>"
  effect: {{set: MgmtService.enabled, from: v, map: {{"yes": true, "no": false}},
           transform: [invert]}}
  negation: null
  {PROV}
""",
        "/ip service\nset telnet disabled=yes\n",
        (("MgmtService", "telnet", "enabled", False, "explicit"),),
    ),
    Case(
        "sonic: default (nothing stated)",
        ShapeFamily.JSON_YAML,
        (),
        "[]",
        '{"DEVICE_METADATA": {"localhost": {"hostname": "leaf1"}}}\n',
        (("MgmtService", "telnet", "enabled", False, "vendor_default"),),
        defaults=(
            {
                "id": "telnet-not-shipped",
                "attr": "MgmtService.enabled",
                "entity_key": "telnet",
                "value": False,
                "source": "curated",
                "reference": "illustrative; curated from SONiC docs in TODO M2.32",
            },
        ),
    ),
    Case(
        "cisco_ios_xe: line absent, default scoped by OS version (in range)",
        ShapeFamily.INDENT,
        ("no",),
        "[]",
        "hostname R1\n",
        (("MgmtService", "telnet", "enabled", False, "vendor_default"),),
        defaults=(
            {
                "id": "telnet-default-17",
                "attr": "MgmtService.enabled",
                "entity_key": "telnet",
                "value": False,
                "os_versions": ">=17.1",
                "source": "curated",
                "reference": "illustrative; curated from Cisco docs in TODO M2.26",
            },
        ),
        os_version="17.9.4",
    ),
    Case(
        "cisco_ios_xe: line absent, no default for this release -> absent (REVIEW)",
        ShapeFamily.INDENT,
        ("no",),
        "[]",
        "hostname R1\n",
        (("MgmtService", "telnet", "enabled", None, "absent"),),
        defaults=(
            {
                "id": "telnet-default-17",
                "attr": "MgmtService.enabled",
                "entity_key": "telnet",
                "value": False,
                "os_versions": ">=17.1",
                "source": "curated",
                "reference": "illustrative; curated from Cisco docs in TODO M2.26",
            },
        ),
        os_version="15.2.7",
    ),
]

IDS = [c.name for c in CASES]


def _mappings(case: Case) -> list[Mapping]:
    return [Mapping.model_validate(m) for m in yaml.safe_load(case.mappings)]


@pytest.mark.spec
@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_mappings_are_valid_in_the_frozen_language(case: Case) -> None:
    _mappings(case)
    for d in case.defaults:
        DefaultEntry.model_validate(d)


def test_the_example_covers_all_six_primitives_and_eight_platforms() -> None:
    text = "\n".join(c.mappings for c in CASES)
    for primitive in ("entity:", "set:", "assert:", "members:", "negation:"):
        assert primitive in text
    assert any(c.defaults for c in CASES)  # the sixth primitive, `default`
    platforms = {c.name.split(":")[0] for c in CASES}
    assert len(platforms) == 7  # 8 rows in §9.2; Cisco appears twice (present and absent)


@pytest.mark.spec
@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_engine_produces_the_expected_facts(case: Case) -> None:
    tree = parse_text(case.config, family=case.family, source_file="spec.cfg")
    assert tree.family is case.family, tree.warnings
    result = apply_mappings(
        tree,
        _mappings(case),
        negation_words=case.negation_words,
        defaults=[DefaultEntry.model_validate(d) for d in case.defaults],
        os_version=case.os_version,
    )
    sbm = with_derived(result.sbm, DERIVATIONS)
    for etype, key, attr, value, state in case.expect:
        entity = next((e for e in sbm.all_entities() if e.type == etype and e.key == key), None)
        if entity is None:
            # "absent" can also mean the entity was never mentioned at all.
            assert (value, state) == (None, "absent"), f"{etype}[{key}] missing"
            continue
        fact = getattr(entity, attr)
        assert fact.state == state
        got = set(fact.value) if isinstance(fact.value, frozenset) else fact.value
        assert got == value
        if state == "explicit":
            assert fact.evidence, "explicit facts carry their source line"
            assert all(ev.mapping_id for ev in fact.evidence)
    for fact_id, value in case.derived.items():
        assert sbm.derived[fact_id].value is value
