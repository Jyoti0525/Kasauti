from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from kasauti.rules.derivation import Derivation, DerivationError, order_and_check
from kasauti.rules.model import OnMissing, Rule

# PLAN §12.1, verbatim apart from filling the CIS placeholders and adding `domain`.
PLAN_12_1 = """
id: MGMT-TELNET-01
title: Clear-text Telnet management is not reachable
intent: Credentials must never cross the network in clear text.
domain: management_plane
for_each: Device
assert: not management.telnet_reachable
on_absent: resolve_default
on_unknown: review
severity: {base: high}
exposure: [telnet_on_untrusted_interface]
fix_intent: {make: management.telnet_reachable, equal: false}
refs:
  nist_800_53r5: [CM-7, AC-17(2), SC-8]
  disa_stig: auto
  cis: {}
  iso_27001_2022: derived
fixtures:
  pass: [cisco_ios_xe/telnet_off.cfg, junos/no_telnet.conf]
  fail: [cisco_ios_xe/telnet_vty.cfg, fortios/wan_telnet.conf]
"""

TIMEOUT = {
    "id": "MGMT-SESSION-TIMEOUT-01",
    "title": "Management sessions time out when idle",
    "intent": "Abandoned admin sessions must not stay open for someone else to use.",
    "domain": "management_plane",
    "for_each": "MgmtSession where kind in [console, vty, web]",
    "assert": "idle_timeout_s > 0 and idle_timeout_s <= 600",
    "severity": {"base": "medium"},
    "refs": {"nist_800_53r5": ["AC-12", "SC-10"]},
}

TELNET_REACHABLE = Derivation(
    id="management.telnet_reachable",
    version=1,
    type="bool",
    description="Telnet is reachable through any service, session or interface.",
    expr=(
        "any(MgmtService where key == 'telnet': enabled)"
        " or any(MgmtSession where kind == 'vty': transport contains 'telnet')"
        " or any(Interface: mgmt_protocols contains 'telnet')"
    ),
)


def test_plan_rule_validates_and_checks() -> None:
    rule = Rule.model_validate(yaml.safe_load(PLAN_12_1))
    assert rule.on_absent is OnMissing.RESOLVE_DEFAULT
    assert rule.fixtures.pass_[0] == "cisco_ios_xe/telnet_off.cfg"
    assert rule.check({"management.telnet_reachable": "bool"}) == []
    assert "unknown derived fact" in rule.check({})[0]


def test_timeout_rule_checks() -> None:
    assert Rule.model_validate(TIMEOUT).check({}) == []


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"id": "mgmt-timeout-1"}, "String should match pattern"),
        ({"for_each": "Router"}, "unknown entity type"),
        ({"assert": "idle_timeout_s >"}, "expected"),
        ({"on_unknown": "resolve_default"}, "defaults only fill absence"),
        ({"on_absent": "pass"}, "Input should be"),
        ({"refs": {}}, "anchored to NIST"),
        ({"refs": {"nist_800_53r5": ["CM7"]}}, "String should match pattern"),
    ],
)
def test_invalid_rules(overrides: dict[str, Any], error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        Rule.model_validate({**TIMEOUT, **overrides})


def test_hardening_only_rules_need_no_nist_anchor() -> None:
    Rule.model_validate({**TIMEOUT, "refs": {}, "hardening_best_practice": True})


def test_derivations_order_by_dependency() -> None:
    exposed = Derivation(
        id="management.cleartext_reachable",
        version=1,
        type="bool",
        description="Any clear-text management protocol is reachable.",
        expr="management.telnet_reachable or any(MgmtService where key == 'http': enabled)",
    )
    ordered = order_and_check([exposed, TELNET_REACHABLE])
    assert [d.id for d in ordered] == [
        "management.telnet_reachable",
        "management.cleartext_reachable",
    ]


def test_derivation_problems_are_reported() -> None:
    a = Derivation(id="x.a", version=1, type="bool", description="cycle part a", expr="x.b")
    b = Derivation(id="x.b", version=1, type="bool", description="cycle part b", expr="x.a")
    with pytest.raises(DerivationError, match="cycle"):
        order_and_check([a, b])
    bad = Derivation(
        id="x.c",
        version=1,
        type="bool",
        description="bad attribute",
        expr="any(Interface: colour == 'red')",
    )
    with pytest.raises(DerivationError, match="no attribute 'colour'"):
        order_and_check([bad])
    with pytest.raises(ValidationError):
        Derivation(id="telnet", version=1, type="bool", description="undotted id", expr="true")
