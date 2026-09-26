"""Four-valued evaluation (docs/spec/rule-language.md §3; TODO M1.08, M1.10)."""

from __future__ import annotations

import itertools

import pytest

from kasauti.rules import expr as ex
from kasauti.rules.derivation import Derivation, order_and_check
from kasauti.rules.evaluate import (
    Evaluator,
    Known,
    Missing,
    Val,
    derive,
    kleene_and,
    kleene_not,
    kleene_or,
    with_derived,
)
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.sbm.entities import Interface, MgmtService, MgmtSession, SnmpCommunity
from kasauti.sbm.facts import Evidence, Fact

EV = Evidence(
    file="r.cfg",
    line_start=3,
    line_end=3,
    raw="x",
    mapping_id="v/x",
    mapping_version=1,
    approved_by=("a",),
)
T, F = Known(True), Known(False)
A, U = Missing("absent"), Missing("unknown")


def _kind(v: Val) -> object:
    return v.value if isinstance(v, Known) else v.kind


@pytest.mark.parametrize(("a", "b"), list(itertools.product([T, F, A, U], repeat=2)))
def test_kleene_tables(a: Val, b: Val) -> None:
    got_and, got_or = _kind(kleene_and([a, b])), _kind(kleene_or([a, b]))
    ka, kb = _kind(a), _kind(b)
    # and = the "lowest" value, or = the "highest"; UNKNOWN beats ABSENT between the two.
    if False in (ka, kb):
        assert got_and is False
    elif ka is True and kb is True:
        assert got_and is True
    else:
        assert got_and == ("unknown" if "unknown" in (ka, kb) else "absent")
    if True in (ka, kb):
        assert got_or is True
    elif ka is False and kb is False:
        assert got_or is False
    else:
        assert got_or == ("unknown" if "unknown" in (ka, kb) else "absent")
    assert _kind(kleene_not(a)) == ({True: False, False: True}.get(ka, ka))  # type: ignore[arg-type]


def sbm(*entities: object, **extra: object) -> SecurityBaselineModel:
    return SecurityBaselineModel(entities=entities, **extra)  # type: ignore[arg-type]


def ev(
    model: SecurityBaselineModel, source: str, *, scope: object = None, defaults: bool = False
) -> Val:
    return Evaluator(model, use_defaults=defaults).eval(ex.parse(source), scope)  # type: ignore[arg-type]


def test_empty_quantifier_is_absent_never_false() -> None:
    """The false-PASS path M0 closed: "understood nothing about telnet" != "telnet is off"."""
    model = sbm()
    assert _kind(ev(model, "any(MgmtService where key == 'telnet': enabled)")) == "absent"
    assert _kind(ev(model, "not any(MgmtService: enabled)")) == "absent"
    assert _kind(ev(model, "count(MgmtService) == 0")) == "absent"


def test_known_empty_only_counts_in_the_defaults_view() -> None:
    model = sbm(known_empty={"SnmpCommunity": "v/defaults.yaml#none"})
    assert isinstance(ev(model, "none(SnmpCommunity: access == 'rw')"), Missing)
    val = ev(model, "none(SnmpCommunity: access == 'rw')", defaults=True)
    assert isinstance(val, Known)
    assert val.value is True
    assert val.why[0].default_source == "v/defaults.yaml#none"
    assert _kind(ev(model, "count(SnmpCommunity)", defaults=True)) == 0


def test_unread_statements_block_universal_conclusions_but_not_witnesses() -> None:
    good = SnmpCommunity(key="community-1", access=Fact.explicit("ro", EV))
    bad = SnmpCommunity(key="community-2", access=Fact.explicit("rw", EV))
    unread = {"SnmpCommunity": (EV,)}
    assert _kind(ev(sbm(good, unread=unread), "none(SnmpCommunity: access == 'rw')")) == "unknown"
    assert _kind(ev(sbm(good, bad, unread=unread), "none(SnmpCommunity: access == 'rw')")) is False
    assert _kind(ev(sbm(good, bad, unread=unread), "any(SnmpCommunity: access == 'rw')")) is True
    assert _kind(ev(sbm(unread=unread), "any(SnmpCommunity: access == 'rw')")) == "unknown"


def test_vendor_defaults_are_absent_unless_the_view_allows_them() -> None:
    session = MgmtSession(key="vty 0-4", idle_timeout_s=Fact.vendor_default(600, "v#t"))
    assert _kind(ev(sbm(session), "idle_timeout_s <= 600", scope=session)) == "absent"
    assert _kind(ev(sbm(session), "idle_timeout_s <= 600", scope=session, defaults=True)) is True


def test_unknown_facts_propagate_as_unknown() -> None:
    session = MgmtSession(key="vty 0-4", idle_timeout_s=Fact.unknown(EV))
    assert (
        _kind(ev(sbm(session), "idle_timeout_s > 0 and idle_timeout_s <= 600", scope=session))
        == "unknown"
    )
    assert _kind(ev(sbm(session), "exists(idle_timeout_s)", scope=session)) == "unknown"
    assert _kind(ev(sbm(session), "exists(access_filter)", scope=session)) is False


def test_where_clause_that_is_missing_keeps_the_entity_in_doubt() -> None:
    unknown_kind = MgmtSession(
        key="x", kind=Fact.unknown(EV), transport=Fact.explicit(frozenset({"telnet"}), EV)
    )
    ssh_only = MgmtSession(
        key="y", kind=Fact.explicit("vty", EV), transport=Fact.explicit(frozenset({"ssh"}), EV)
    )
    source = "any(MgmtSession where kind == 'vty': transport contains 'telnet')"
    assert _kind(ev(sbm(unknown_kind, ssh_only), source)) == "unknown"


def test_witnesses_are_the_members_that_decided_it() -> None:
    telnet = MgmtSession(
        key="vty 5-15",
        kind=Fact.explicit("vty", EV),
        transport=Fact.explicit(frozenset({"telnet"}), EV),
    )
    ssh = MgmtSession(
        key="vty 0-4",
        kind=Fact.explicit("vty", EV),
        transport=Fact.explicit(frozenset({"ssh"}), EV),
    )
    val = ev(sbm(ssh, telnet), "any(MgmtSession where kind == 'vty': transport contains 'telnet')")
    subjects = {o.subject for o in val.why}
    assert "MgmtSession[vty 5-15].transport" in subjects
    assert "MgmtSession[vty 0-4].transport" not in subjects


def test_matches_uses_re2() -> None:
    iface = Interface(key="GigabitEthernet1", zone=Fact.explicit("untrust-wan", EV))
    assert _kind(ev(sbm(iface), "zone matches '^untrust'", scope=iface)) is True
    assert _kind(ev(sbm(iface), "zone matches '(a+)+$'", scope=iface)) is False  # linear time


TELNET = Derivation(
    id="management.telnet_reachable",
    version=1,
    type="bool",
    description="Telnet reachable anywhere",
    expr="any(MgmtService where key == 'telnet': enabled)"
    " or any(MgmtSession where kind == 'vty': transport contains 'telnet')",
)


def test_derivations_and_stored_facts() -> None:
    session = MgmtSession(
        key="vty 0-4",
        kind=Fact.explicit("vty", EV),
        transport=Fact.explicit(frozenset({"telnet"}), EV),
    )
    ordered = order_and_check([TELNET])
    vals = derive(sbm(session), ordered, use_defaults=False)
    assert _kind(vals["management.telnet_reachable"]) is True
    stored = with_derived(sbm(session), ordered).derived["management.telnet_reachable"]
    assert stored.value is True
    assert stored.evidence

    default_only = sbm(
        MgmtService(key="telnet", enabled=Fact.vendor_default(False, "v#telnet")),
        MgmtSession(
            key="vty 0-4",
            kind=Fact.explicit("vty", EV),
            transport=Fact.explicit(frozenset({"ssh"}), EV),
        ),
    )
    fact = with_derived(default_only, ordered).derived["management.telnet_reachable"]
    assert fact.value is False
    assert fact.state == "vendor_default"
    assert fact.default_source == "v#telnet"
