import contextlib
import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kasauti.rules import expr as ex

TELNET_REACHABLE = (
    "any(MgmtService where key == 'telnet': enabled)"
    " or any(MgmtSession where kind == 'vty': transport contains 'telnet')"
    " or any(Interface: mgmt_protocols ∋ 'telnet')"
)


def test_parses_plan_examples() -> None:
    assert ex.parse("not management.telnet_reachable") == ex.Not(
        ex.Ref(("management", "telnet_reachable"))
    )
    node = ex.parse("idle_timeout_s > 0 and idle_timeout_s <= 600")
    assert isinstance(node, ex.BoolOp)
    assert node.op == "and"
    assert len(node.operands) == 2


def test_precedence_not_and_or() -> None:
    node = ex.parse("not a or b and c")
    assert node == ex.BoolOp(
        "or",
        (
            ex.Not(ex.Ref(("a",))),
            ex.BoolOp("and", (ex.Ref(("b",)), ex.Ref(("c",)))),
        ),
    )


def test_scope_with_bare_word_list() -> None:
    entity, where = ex.parse_scope("MgmtSession where kind in [console, vty, web]")
    assert entity == "MgmtSession"
    assert where == ex.Compare("in", ex.Ref(("kind",)), ex.ListLit(("console", "vty", "web")))


def test_contains_alias() -> None:
    assert ex.parse("x ∋ 'a'") == ex.parse("x contains 'a'")


@pytest.mark.parametrize(
    ("source", "fragment"),
    [
        ("a ==", "expected"),
        ("any(MgmtService", "expected ')'"),
        ("a $ b", "unexpected character"),
        ("(a", "expected ')'"),
        ("a b", "unexpected 'b'"),
    ],
)
def test_errors_point_at_a_column(source: str, fragment: str) -> None:
    with pytest.raises(ex.ExprError, match=re.escape(fragment)) as err:
        ex.parse(source)
    assert "column" in str(err.value)


def test_derivation_type_checks() -> None:
    assert ex.check(ex.parse(TELNET_REACHABLE), scope=None) == []


@pytest.mark.parametrize(
    ("source", "scope", "error"),
    [
        ("idle_timeout_z > 0", "MgmtSession", "no attribute 'idle_timeout_z'"),
        ("idle_timeout_s > 'x'", "MgmtSession", "needs int operands"),
        ("transport == 'ssh'", "MgmtSession", "cannot compare set == str"),
        ("kind contains 'vty'", "MgmtSession", "'contains' needs a set"),
        ("enabled", None, "need an entity in scope"),
        ("any(Nope: x)", None, "unknown entity type"),
        ("all(Interface)", None, "needs a ':' test"),
        ("count(Interface)", None, "type int, expected bool"),
        ("security.unknown_fact", None, "unknown derived fact"),
        ("Device.colour == 'red'", None, "Device has no attribute"),
        ("kind matches kind", "MgmtSession", "quoted pattern"),
    ],
)
def test_type_errors(source: str, scope: str | None, error: str) -> None:
    errors = ex.check(ex.parse(source), scope=scope)
    assert any(error in e for e in errors), errors


def test_count_compares_as_int() -> None:
    assert ex.check(ex.parse("count(LogTarget) >= 1"), scope=None) == []


def test_derived_facts_resolve_with_registry() -> None:
    assert (
        ex.check(
            ex.parse("not management.telnet_reachable"),
            scope="Device",
            derived={"management.telnet_reachable": "bool"},
        )
        == []
    )


@given(st.text(max_size=60))
def test_parser_never_crashes_on_garbage(source: str) -> None:
    with contextlib.suppress(ex.ExprError):
        ex.parse(source)
