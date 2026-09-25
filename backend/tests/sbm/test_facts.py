import json

import pytest
from pydantic import ValidationError

from kasauti.sbm import Evidence, Fact, FactState, StrSet, union_evidence

EV = Evidence(
    file="r1.cfg",
    line_start=10,
    line_end=10,
    raw=" transport input ssh telnet",
    mapping_id="cisco_ios_xe/vty-transport",
    mapping_version=2,
    approved_by=("approver:a",),
)


def test_explicit_needs_value_and_evidence() -> None:
    fact = Fact[bool].explicit(True, EV)
    assert fact.state is FactState.EXPLICIT
    assert fact.is_known
    with pytest.raises(ValidationError, match="explicit"):
        Fact[bool](value=True, state=FactState.EXPLICIT)


def test_vendor_default_needs_source() -> None:
    fact = Fact[bool].vendor_default(False, "cisco_ios_xe/defaults.yaml#telnet")
    assert fact.is_known
    with pytest.raises(ValidationError, match="default_source"):
        Fact[bool](value=False, state=FactState.VENDOR_DEFAULT)


def test_absent_carries_nothing() -> None:
    assert not Fact[int].absent().is_known
    with pytest.raises(ValidationError):
        Fact[int](value=3, state=FactState.ABSENT)
    with pytest.raises(ValidationError):
        Fact[int](state=FactState.ABSENT, evidence=(EV,))


def test_unknown_points_at_unread_lines() -> None:
    fact = Fact[int].unknown(EV)
    assert not fact.is_known
    with pytest.raises(ValidationError, match="unread"):
        Fact[int](state=FactState.UNKNOWN)


def test_evidence_validation() -> None:
    with pytest.raises(ValidationError, match="line_end"):
        Evidence(file="a", line_start=5, line_end=4, raw="x")
    with pytest.raises(ValidationError, match="together"):
        Evidence(file="a", line_start=1, line_end=1, raw="x", mapping_id="v/m")
    assert EV.mapping_ref == "cisco_ios_xe/vty-transport@2"


def test_sets_serialise_sorted_for_determinism() -> None:
    fact = Fact[StrSet].explicit(frozenset({"telnet", "ssh", "https"}), EV)
    assert json.loads(fact.model_dump_json())["value"] == ["https", "ssh", "telnet"]


def test_union_evidence_dedupes_and_sorts() -> None:
    other = EV.model_copy(update={"line_start": 2, "line_end": 2})
    merged = union_evidence(Fact[bool].explicit(True, EV, other), Fact[bool].explicit(True, EV))
    assert [e.line_start for e in merged] == [2, 10]
