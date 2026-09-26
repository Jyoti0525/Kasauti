from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

import kasauti.sbm
from kasauti.sbm import ENTITY_TYPES, SecurityBaselineModel, attribute_names
from kasauti.sbm.document import SBM_VERSION
from kasauti.sbm.entities import Interface, LoggingPolicy, MgmtService, MgmtSession
from kasauti.sbm.facts import Evidence, Fact
from kasauti.sbm.migrations import MigrationError, migrate

# Every entity named in PLAN §8.1, plus the two documented additions.
PLAN_8_1 = {
    "Device",
    "MgmtService",
    "MgmtSession",
    "Interface",
    "LocalUser",
    "AuthServer",
    "LogTarget",
    "TimeSource",
    "SnmpCommunity",
    "SnmpUser",
    "CryptoProfile",
    "FilterRule",
    "Banner",
    "PasswordPolicy",
    "LockoutPolicy",
    "RoutingAuth",
    "L2Port",
    "Tunnel",
}
ADDITIONS = {"LoggingPolicy", "ObjectDef", "TimePolicy", "Reference", "AuthPolicy", "Ruleset"}


def test_every_plan_entity_exists() -> None:
    assert set(ENTITY_TYPES) == PLAN_8_1 | ADDITIONS


def test_plan_attributes_present() -> None:
    assert set(attribute_names("MgmtService")) >= {"enabled", "version", "ciphers", "macs", "kex"}
    assert set(attribute_names("MgmtSession")) >= {
        "kind",
        "range",
        "transport",
        "access_filter",
        "idle_timeout_s",
        "auth_method",
    }
    assert set(attribute_names("Interface")) >= {
        "zone",
        "role",
        "admin_up",
        "mgmt_protocols",
        "filters_in",
        "filters_out",
    }
    assert set(attribute_names("FilterRule")) >= {
        "position",
        "src",
        "dst",
        "service",
        "action",
        "log",
        "enabled",
        "zone_from",
        "zone_to",
        "name",
    }
    assert set(attribute_names("Device")) >= {
        "hostname",
        "vendor",
        "os_family",
        "os_version",
        "model",
        "serial",
        "hardware",
        "role",
    }


def test_openconfig_alignment_covers_every_attribute_exactly_once() -> None:
    path = Path(kasauti.sbm.__file__).parent / "openconfig.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapped, extension = set(data["openconfig"]), set(data["x-sbm"])
    assert not mapped & extension
    every = {f"{t}.{a}" for t in ENTITY_TYPES for a in attribute_names(t)}
    assert every == mapped | extension, (every - mapped - extension, (mapped | extension) - every)


def _ev(line: int) -> Evidence:
    return Evidence(file="r.cfg", line_start=line, line_end=line, raw="x")


ENTITIES = [
    MgmtService(key="telnet", enabled=Fact[bool].explicit(True, _ev(3))),
    MgmtSession(key="vty 0-4", kind=Fact[str].explicit("vty", _ev(9))),
    Interface(key="GigabitEthernet0/1"),
    LoggingPolicy(),
]


@given(st.permutations(ENTITIES))
def test_serialisation_is_order_independent(order: list[object]) -> None:
    a = SecurityBaselineModel(entities=tuple(ENTITIES))
    b = SecurityBaselineModel(entities=tuple(order))  # type: ignore[arg-type]
    assert a.canonical_json() == b.canonical_json()


def test_round_trip_through_json() -> None:
    sbm = SecurityBaselineModel(entities=tuple(ENTITIES))
    again = SecurityBaselineModel.model_validate_json(sbm.canonical_json())
    assert again == sbm
    assert again.of_type(MgmtService)[0].enabled.value is True


def test_duplicates_and_singletons_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate"):
        SecurityBaselineModel(entities=(Interface(key="a"), Interface(key="a")))
    with pytest.raises(ValidationError, match="singleton"):
        SecurityBaselineModel(entities=(LoggingPolicy(), LoggingPolicy(key="other")))


def test_old_versions_must_be_migrated() -> None:
    with pytest.raises(ValidationError, match="migrations"):
        SecurityBaselineModel(sbm_version="0.0")


def test_migration_chain() -> None:
    registry = {
        "0.0": ("0.05", lambda d: {"renamed": d.pop("old", None), **d}),
        "0.05": ("0.1", lambda d: d),
    }
    out = migrate({"sbm_version": "0.0", "old": 1}, target="0.1", registry=registry)
    assert out == {"sbm_version": "0.1", "renamed": 1}
    with pytest.raises(MigrationError, match="no migration"):
        migrate({"sbm_version": "9.9"}, registry=registry)
    with pytest.raises(MigrationError, match="loop"):
        migrate({"sbm_version": "a"}, target="z", registry={"a": ("b", dict), "b": ("a", dict)})


def test_real_migration_0_1_to_0_2_keeps_content() -> None:
    """TODO M2.25: a stored 0.1 document loads as the current version with nothing lost."""
    v01 = {
        "sbm_version": "0.1",
        "device": {"type": "Device", "key": "device"},
        "entities": [
            {
                "type": "TimeSource",
                "key": "10.0.0.1",
                "authenticated": {
                    "value": True,
                    "state": "explicit",
                    "evidence": [{"file": "r.cfg", "line_start": 3, "line_end": 3, "raw": "x"}],
                },
            }
        ],
        "derived": {},
    }
    sbm = SecurityBaselineModel.model_validate(migrate(v01))
    assert sbm.sbm_version == SBM_VERSION
    (ts,) = sbm.entities
    assert ts.authenticated.value is True  # type: ignore[union-attr]
    assert sbm.known_empty == {}
    assert sbm.unread == {}
