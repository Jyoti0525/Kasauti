from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from kasauti.mapping.model import Mapping, Slot, Word, parse_pattern

# PLAN §9.3, verbatim.
PLAN_9_3 = """
id: fortinet_fortios/interface-allowaccess
vendor: fortinet_fortios
os_versions: ">=6.0"
context: ["config system interface", "edit <STR:ifname>"]
entity: {type: Interface, key: ifname}
match: "set allowaccess <LIST:protocols>"
effect: {members: Interface.mgmt_protocols, from: protocols,
         map: {ping: icmp, https: https, http: http, ssh: ssh, telnet: telnet, snmp: snmp}}
negation: "unset allowaccess"
provenance: {version: 3, proposed_by: trainer:asha, approved_by: [approver:ravi], signals: [S3, S5]}
"""


def _mapping(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(PLAN_9_3)
    data["entity"]["key"] = "{ifname}"
    data.update(overrides)
    return data


def test_plan_stored_form_validates() -> None:
    m = Mapping.model_validate(_mapping())
    assert m.effects[0].attr == "Interface.mgmt_protocols"


def test_plan_shorthand_key_gets_a_clear_error() -> None:
    # The §9.3 listing writes `key: ifname`. Stored literally, that would make every interface
    # the same entity, so the schema refuses it and says how to write the slot.
    with pytest.raises(ValidationError, match=r"write it as '\{ifname\}'"):
        Mapping.model_validate(yaml.safe_load(PLAN_9_3))


def test_pattern_parsing() -> None:
    assert parse_pattern("exec-timeout <INT:min> <INT:sec>") == (
        Word("exec-timeout"),
        Slot("INT", "min"),
        Slot("INT", "sec"),
    )
    with pytest.raises(ValueError, match="last token"):
        parse_pattern("set <LIST:a> b")
    with pytest.raises(ValueError, match="bad slot"):
        parse_pattern("set <FLOAT:x>")
    with pytest.raises(ValueError, match="used twice"):
        parse_pattern("<STR:a> <STR:a>")


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"vendor": "cisco_ios_xe"}, "must start with the vendor"),
        ({"match": "set allowaccess <LIST:protos>"}, "not captured"),
        ({"effect": {"members": "Interface.mgmt_protocolz", "from": "protocols"}}, "no such SBM"),
        ({"effect": {"set": "Interface.mgmt_protocols", "from": "protocols"}}, "use `members`"),
        (
            {"effect": {"members": "MgmtSession.transport", "from": "protocols"}},
            "need an `entity:`",
        ),
        ({"os_versions": "~6"}, "bad version clause"),
        ({"entity": None, "effect": None}, "must open an entity"),
        ({"provenance": {"version": 1, "proposed_by": "x", "signals": ["S9"]}}, "unknown signals"),
    ],
)
def test_invalid_mappings(overrides: dict[str, Any], error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        Mapping.model_validate(_mapping(**overrides))


def test_weighted_sum_for_unit_normalisation() -> None:
    m = Mapping.model_validate(
        {
            "id": "cisco_ios_xe/vty-exec-timeout",
            "vendor": "cisco_ios_xe",
            "context": ["line vty <INT:first> <INT:last>"],
            "entity": {"type": "MgmtSession", "key": "vty {first}-{last}"},
            "match": "exec-timeout <INT:min> <INT:sec>",
            "effect": {"set": "MgmtSession.idle_timeout_s", "from": {"min": 60, "sec": 1}},
            "provenance": {"version": 1, "proposed_by": "seed"},
        }
    )
    assert m.effects[0].slots() == {"min", "sec"}
