"""Rule engine and scoring (PLAN §12.1, §12.5, §12.6; TODO M1.10, M1.12)."""

from __future__ import annotations

from typing import Any

import pytest

from kasauti.packs.loader import RuleSet
from kasauti.rules.derivation import Derivation, order_and_check
from kasauti.rules.engine import evaluate_rules
from kasauti.rules.model import Finding, Rule, Status
from kasauti.rules.scoring import ControlStatus, nist_controls, rule_status, rule_statuses, score
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.sbm.entities import Device, LockoutPolicy, MgmtSession
from kasauti.sbm.facts import Evidence, Fact

APPROVED = Evidence(
    file="r.cfg",
    line_start=5,
    line_end=5,
    raw="exec-timeout 0 0",
    mapping_id="v/t",
    mapping_version=1,
    approved_by=("a",),
)
UNAPPROVED = Evidence(
    file="r.cfg",
    line_start=5,
    line_end=5,
    raw="exec-timeout 0 0",
    mapping_id="v/t",
    mapping_version=1,
)


def rule(**fields: Any) -> Rule:
    base: dict[str, Any] = {
        "id": "MGMT-SESSION-TIMEOUT-01",
        "title": "Sessions time out",
        "intent": "No idle sessions.",
        "domain": "management_plane",
        "for_each": "MgmtSession where kind in [console, vty]",
        "assert": "idle_timeout_s > 0 and idle_timeout_s <= 600",
        "severity": {"base": "medium"},
        "refs": {"nist_800_53r5": ["AC-12"]},
    }
    base.update(fields)
    return Rule.model_validate(base)


def findings(
    model: SecurityBaselineModel, *rules: Rule, derivations: tuple[Derivation, ...] = ()
) -> list[Finding]:
    return list(evaluate_rules(model, RuleSet(tuple(rules), tuple(order_and_check(derivations)))))


def vty(key: str, timeout: Fact[int] | None = None) -> MgmtSession:
    return MgmtSession(
        key=key,
        kind=Fact.explicit("vty", APPROVED),
        idle_timeout_s=timeout or Fact.absent(),
        evidence=(APPROVED,),
    )


def test_true_false_and_per_entity_findings() -> None:
    model = SecurityBaselineModel(
        entities=(
            vty("vty 0-4", Fact.explicit(600, APPROVED)),
            vty("vty 5-15", Fact.explicit(0, APPROVED)),
        )
    )
    out = findings(model, rule())
    assert [(f.entity_id, f.status) for f in out] == [
        ("MgmtSession[vty 0-4]", Status.PASS),
        ("MgmtSession[vty 5-15]", Status.FAIL),
    ]
    assert out[1].severity == "medium"
    assert out[1].severity_reason == "Medium (base)"
    assert out[1].evidence
    assert out[1].actual == (
        "MgmtSession[vty 5-15].kind = vty",
        "MgmtSession[vty 5-15].idle_timeout_s = 0",
    )


@pytest.mark.parametrize(
    ("on_absent", "status"),
    [
        ("review", Status.REVIEW),
        ("fail", Status.FAIL),
        ("not_applicable", Status.NOT_APPLICABLE),
        ("resolve_default", Status.REVIEW),
    ],
)
def test_absent_facts_follow_on_absent_and_never_pass(on_absent: str, status: Status) -> None:
    model = SecurityBaselineModel(entities=(vty("vty 0-4"),))
    (f,) = findings(model, rule(on_absent=on_absent))
    assert f.status is status


def test_resolve_default_uses_the_vendor_default_and_says_so() -> None:
    model = SecurityBaselineModel(
        entities=(vty("vty 0-4", Fact.vendor_default(600, "v/defaults.yaml#t")),)
    )
    (resolved,) = findings(model, rule(on_absent="resolve_default"))
    (strict,) = findings(model, rule(on_absent="review"))
    assert resolved.status is Status.PASS
    assert resolved.defaults_used == ("v/defaults.yaml#t",)
    assert strict.status is Status.REVIEW  # the author asked not to trust defaults


def test_on_no_default_decides_only_when_no_default_is_known() -> None:
    absent = SecurityBaselineModel(entities=(vty("vty 0-4"),))
    defaulted = SecurityBaselineModel(
        entities=(vty("vty 0-4", Fact.vendor_default(600, "v/defaults.yaml#t")),)
    )
    strict = rule(on_absent="resolve_default", on_no_default="fail")
    assert findings(absent, strict)[0].status is Status.FAIL
    assert findings(defaulted, strict)[0].status is Status.PASS


def test_on_no_default_needs_resolve_default() -> None:
    with pytest.raises(ValueError, match="on_no_default applies only"):
        rule(on_absent="review", on_no_default="fail")


def test_unknown_facts_follow_on_unknown() -> None:
    model = SecurityBaselineModel(entities=(vty("vty 0-4", Fact.unknown(APPROVED)),))
    (f,) = findings(model, rule(on_unknown="fail"))
    assert f.status is Status.FAIL
    (g,) = findings(model, rule(on_unknown="review"))
    assert g.status is Status.REVIEW
    assert "not understood" in g.reason


def test_unapproved_mappings_turn_verdicts_into_review() -> None:
    session = MgmtSession(
        key="vty 0-4",
        kind=Fact.explicit("vty", APPROVED),
        idle_timeout_s=Fact.explicit(0, UNAPPROVED),
    )
    (f,) = findings(SecurityBaselineModel(entities=(session,)), rule())
    assert f.status is Status.REVIEW
    assert "not yet approved" in f.reason
    assert "v/t@1" in f.reason


def test_nothing_in_scope_is_not_applicable_unless_statements_were_unread() -> None:
    (na,) = findings(SecurityBaselineModel(), rule())
    assert na.status is Status.NOT_APPLICABLE
    unread = SecurityBaselineModel(unread={"MgmtSession": (APPROVED,)})
    (review,) = findings(unread, rule())
    assert review.status is Status.REVIEW
    assert review.evidence == (APPROVED,)


def test_singletons_always_exist_so_absence_is_judged() -> None:
    lockout = rule(
        id="AAA-LOCKOUT-01",
        for_each="LockoutPolicy",
        **{"assert": "max_attempts > 0 and max_attempts <= 5"},
        on_absent="fail",
    )
    (f,) = findings(SecurityBaselineModel(), lockout)
    assert f.status is Status.FAIL
    assert f.entity_id == "LockoutPolicy[lockout-policy]"
    ok = SecurityBaselineModel(entities=(LockoutPolicy(max_attempts=Fact.explicit(3, APPROVED)),))
    assert findings(ok, lockout)[0].status is Status.PASS


def test_rules_that_do_not_apply_to_the_role_are_not_applicable() -> None:
    model = SecurityBaselineModel(device=Device(role=Fact.explicit("switch", APPROVED)))
    (f,) = findings(model, rule(applies_to=["firewall"]))
    assert f.status is Status.NOT_APPLICABLE
    assert "switch" in f.reason


# --- scoring -------------------------------------------------------------------------------


def test_rule_status_is_the_worst_finding() -> None:
    def f(s: Status) -> Finding:
        return Finding(rule_id="R-01", entity_id="x", status=s, reason="r")

    assert rule_status([f(Status.PASS), f(Status.REVIEW)]) is Status.REVIEW
    assert rule_status([f(Status.REVIEW), f(Status.FAIL)]) is Status.FAIL
    assert rule_status([]) is Status.NOT_APPLICABLE


def test_compliance_and_coverage_are_reported_together() -> None:
    s = score([Status.PASS, Status.PASS, Status.FAIL, Status.REVIEW, Status.NOT_APPLICABLE])
    assert (s.applicable, s.compliance_pct, s.coverage_pct) == (4, 66.7, 75.0)
    empty = score([Status.NOT_APPLICABLE])
    assert (empty.compliance_pct, empty.coverage_pct) == (None, None)


def test_nist_controls_roll_up_from_their_rules() -> None:
    a = rule(id="A-01", refs={"nist_800_53r5": ["AC-2", "AC-17(2)"]})
    b = rule(id="B-01", refs={"nist_800_53r5": ["AC-2"]})
    c = rule(id="C-01", refs={"nist_800_53r5": ["AC-17"]})
    statuses = {"A-01": Status.PASS, "B-01": Status.FAIL, "C-01": Status.REVIEW}
    rolled = nist_controls([a, b, c], statuses)
    assert list(rolled) == ["AC-2", "AC-17", "AC-17(2)"]
    assert rolled["AC-2"][0] is ControlStatus.PARTIALLY_SATISFIED
    assert rolled["AC-17"][0] is ControlStatus.UNDETERMINED
    assert rolled["AC-17(2)"][0] is ControlStatus.SATISFIED
    assert rule_statuses([a], []) == {"A-01": Status.NOT_APPLICABLE}
