"""Companion files: serials and hardware from command outputs (PLAN §5.1, §7; TODO M2.05)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kasauti.audit import AuditResult, KnowledgeBase, audit, load_kb
from kasauti.identity.companion import classify, recognise
from kasauti.identity.detect import choose, detect_vendor
from kasauti.ingest.model import Artifact
from kasauti.ingest.read import decode
from kasauti.packs.model import IdentitySpec
from kasauti.report.pdf import _cover, _Styles

REPO = Path(__file__).resolve().parents[3]
AUTHORED = REPO / "datasets" / "authored"

CONFIGS = {
    "cisco_ios_xe": "hardened.cfg",
    "arista_eos": "hardened.cfg",
    "juniper_junos": "hardened.conf",
    "fortinet_fortios": "hardened.conf",
    "paloalto_panos": "hardened.xml",
}
COMPANIONS = {
    "cisco_ios_xe": {"show_version.txt": "show_version", "show_inventory.txt": "show_inventory"},
    "arista_eos": {"show_version.txt": "show_version"},
    "juniper_junos": {
        "show_version.txt": "show_version",
        "show_chassis_hardware.txt": "show_chassis_hardware",
    },
    "fortinet_fortios": {"get_system_status.txt": "get_system_status"},
    "paloalto_panos": {"show_system_info.txt": "show_system_info"},
}


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def _read(vendor: str, name: str) -> Artifact:
    folder = AUTHORED / vendor if name in CONFIGS.values() else AUTHORED / vendor / "companions"
    return decode((folder / name).read_bytes(), name)


def _audit(kb: KnowledgeBase, vendor: str, *companions: Artifact) -> AuditResult:
    return audit(_read(vendor, CONFIGS[vendor]), kb, companions=companions)


# -- recognising -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vendor", "name", "kind"),
    [(v, n, k) for v, files in COMPANIONS.items() for n, k in files.items()],
)
def test_each_output_is_recognised_for_its_own_vendor_only(
    kb: KnowledgeBase, vendor: str, name: str, kind: str
) -> None:
    text = _read(vendor, name).text
    found = classify(text, list(kb.vendor_packs.values()))
    assert found is not None
    pack, detection = found
    assert (pack.manifest.id, detection.pack_id) == (vendor, kind)
    for other_id, other in kb.vendor_packs.items():
        if other_id != vendor:
            assert recognise(text, other) is None, other_id
    # Nor is it mistaken for a configuration to audit.
    assert choose(detect_vendor(text, list(kb.vendor_packs.values()))) is None


@pytest.mark.parametrize("vendor", CONFIGS)
def test_a_configuration_is_never_taken_for_a_companion(kb: KnowledgeBase, vendor: str) -> None:
    for name in ("hardened", "weak"):
        (path,) = (AUTHORED / vendor).glob(f"{name}.*")
        assert classify(path.read_text(encoding="utf-8"), list(kb.vendor_packs.values())) is None


# -- identity ----------------------------------------------------------------------------------

EXPECTED: dict[str, dict[str, tuple[str, str]]] = {
    "cisco_ios_xe": {
        "hostname": ("EDGE-R1", "`show version` (show_version.txt line 9)"),
        "os_version": ("17.09.04a", "`show version` (show_version.txt line 2)"),
        "model": ("C8000V", "`show inventory` (show_inventory.txt line 3)"),
        "serial": ("9KXQ2TGA7LM", "`show inventory` (show_inventory.txt line 3)"),
        "hardware": ("C8000V", "`show version` (show_version.txt line 15)"),
    },
    "arista_eos": {
        "hostname": ("LEAF-1", "config line 15"),
        "os_version": ("4.30.1F", "`show version` (show_version.txt line 7)"),
        "model": ("DCS-7050SX3-48YC8", "`show version` (show_version.txt line 2)"),
        "serial": ("JPE21420377", "`show version` (show_version.txt line 4)"),
        "hardware": ("11.02", "`show version` (show_version.txt line 3)"),
    },
    "juniper_junos": {
        "hostname": ("BR-SRX1", "`show version` (show_version.txt line 2)"),
        "os_version": ("23.4R1.9", "`show version` (show_version.txt line 4)"),
        "model": ("srx345", "`show version` (show_version.txt line 3)"),
        "serial": ("CY4217AF0381", "`show chassis hardware` (show_chassis_hardware.txt line 4)"),
        "hardware": ("SRX345", "`show chassis hardware` (show_chassis_hardware.txt line 4)"),
    },
    "fortinet_fortios": {
        "hostname": ("FGT-EDGE", "`get system status` (get_system_status.txt line 10)"),
        "os_version": ("7.4.8", "`get system status` (get_system_status.txt line 2)"),
        "model": ("FortiGate-60F", "`get system status` (get_system_status.txt line 2)"),
        "serial": ("FGT60FTK24031795", "`get system status` (get_system_status.txt line 7)"),
    },
    "paloalto_panos": {
        "hostname": ("PA-EDGE", "`show system info` (show_system_info.txt line 3)"),
        "os_version": ("11.1.2", "`show system info` (show_system_info.txt line 13)"),
        "model": ("PA-440", "`show system info` (show_system_info.txt line 11)"),
        "serial": ("024101004173", "`show system info` (show_system_info.txt line 12)"),
    },
}


@pytest.mark.parametrize("vendor", CONFIGS)
def test_serial_and_hardware_come_from_the_companions_with_their_source(
    kb: KnowledgeBase, vendor: str
) -> None:
    without = _audit(kb, vendor)
    assert without.identity["serial"].value is None
    assert "not present in supplied artefacts; upload" in without.identity["serial"].source
    companions = [_read(vendor, name) for name in COMPANIONS[vendor]]
    result = _audit(kb, vendor, *companions)
    got = {f: (v.value, v.source) for f, v in result.identity.items() if f in EXPECTED[vendor]}
    assert got == EXPECTED[vendor]
    assert all(c.used for c in result.companions)
    # Serials are identity, not configuration: verdicts don't move.
    assert [r.status for r in result.rules] == [r.status for r in without.rules]


def test_the_hardware_inventory_lists_every_component_with_a_serial(kb: KnowledgeBase) -> None:
    cisco = _audit(kb, "cisco_ios_xe", _read("cisco_ios_xe", "show_inventory.txt"))
    assert [(i.name, i.part, i.version, i.serial) for i in cisco.inventory] == [
        ("Chassis", "C8000V", "V00", "9KXQ2TGA7LM"),
        ("module R0", "C8000V", "V00", "JAB2411K0QZ"),  # module F0 has no serial: left out
    ]
    assert cisco.inventory[0].source == "`show inventory` (show_inventory.txt line 2)"
    junos = _audit(kb, "juniper_junos", _read("juniper_junos", "show_chassis_hardware.txt"))
    assert [(i.name, i.version, i.part, i.serial, i.description) for i in junos.inventory] == [
        ("Chassis", None, None, "CY4217AF0381", "SRX345"),
        ("Routing Engine", "REV 0x10", "650-066041", "CY4217AF0381", "RE-SRX345"),
        ("FPC 0", "REV 07", "650-066041", "CY4217AF0381", "FPC"),
        # PIC 0 says BUILTIN where a serial would be; the fan tray has none.
        ("Power Supply 0", "REV 03", "740-058054", "1GC24170126", "PS 100W AC"),
    ]


# -- refusing what doesn't belong ----------------------------------------------------------------


def _art(name: str, text: str) -> Artifact:
    return decode(text.encode(), name)


def test_output_from_another_host_is_refused_not_mixed_in(kb: KnowledgeBase) -> None:
    mine = _read("cisco_ios_xe", "show_version.txt").text
    other = mine.replace("EDGE-R1 uptime", "CORE-9 uptime")
    result = _audit(kb, "cisco_ios_xe", _art("core9.txt", other))
    (info,) = result.companions
    assert (info.used, info.command) == (False, "show_version")
    assert info.note == "`show version` output from host CORE-9, not EDGE-R1"
    assert result.identity["serial"].value is None
    assert "core9.txt: `show version` output from host CORE-9, not EDGE-R1; not used" in (
        result.warnings
    )


def test_another_vendor_s_output_and_unknown_text_are_refused(kb: KnowledgeBase) -> None:
    junos = _read("juniper_junos", "show_version.txt")
    notes = _audit(kb, "cisco_ios_xe", junos, _art("notes.txt", "call the NOC first\n"))
    assert [(c.file, c.command, c.used, c.note) for c in notes.companions] == [
        ("notes.txt", None, False, notes.companions[0].note),
        (
            "show_version.txt",
            None,
            False,
            "looks like `show version` output from a Juniper Junos OS device, not Cisco IOS XE",
        ),
    ]
    assert notes.companions[0].note == (
        "not the output of a command Cisco IOS XE identity is read from"
        " (`show version`, `show inventory`)"
    )


def test_a_second_output_of_the_same_command_is_refused(kb: KnowledgeBase) -> None:
    first = _read("cisco_ios_xe", "show_version.txt")
    second = _art("again.txt", first.text.replace("9KXQ2TGA7LM", "9KXQ2TGA7LX"))
    result = _audit(kb, "cisco_ios_xe", second, first)
    assert [(c.file, c.used, c.note) for c in result.companions] == [
        ("again.txt", True, None),
        ("show_version.txt", False, "a second `show version`; again.txt is used"),
    ]


def test_companions_are_part_of_the_audit_s_identity_but_not_their_order(
    kb: KnowledgeBase,
) -> None:
    version = _read("cisco_ios_xe", "show_version.txt")
    inventory = _read("cisco_ios_xe", "show_inventory.txt")
    alone = _audit(kb, "cisco_ios_xe")
    one = _audit(kb, "cisco_ios_xe", version, inventory)
    two = _audit(kb, "cisco_ios_xe", inventory, version)
    assert one.canonical_json() == two.canonical_json()
    assert one.audit_id != alone.audit_id


# -- the report --------------------------------------------------------------------------------


def _texts(flowables: list[Any]) -> list[str]:
    out: list[str] = []
    for f in flowables:
        if hasattr(f, "_cellvalues"):
            out += [c.text for row in f._cellvalues for c in row if hasattr(c, "text")]
        elif hasattr(f, "text"):
            out.append(f.text)
    return out


def test_the_report_s_device_profile_lists_the_inventory(kb: KnowledgeBase) -> None:
    result = _audit(
        kb,
        "juniper_junos",
        _read("juniper_junos", "show_version.txt"),
        _read("juniper_junos", "show_chassis_hardware.txt"),
    )
    texts = _texts(_cover(result, _Styles(), "2026-09-27"))
    assert "Hardware inventory" in texts
    assert "1GC24170126" in texts
    assert "REV 03 740-058054" not in texts
    assert "740-058054 REV 03" in texts
    assert any("show_chassis_hardware.txt (show_chassis_hardware)" in t for t in texts)
    assert "Hardware inventory" not in _texts(_cover(_audit(kb, "juniper_junos"), _Styles(), ""))


# -- the pack format -----------------------------------------------------------------------------


_SEEN = {
    "show_inventory": {
        "signatures": [{"id": "sn", "kind": "contains", "pattern": "SN", "weight": 1}],
    }
}


@pytest.mark.parametrize(
    ("spec", "problem"),
    [
        (
            {"fields": {"serial": [{"source": "show_version", "pattern": "SN <STR:value>"}]}},
            "`companions` needs signatures for show_version",
        ),
        (
            {
                "fields": {},
                "companions": _SEEN,
                "inventory": [{"source": "show_inventory", "record": r"(?P<name>\w+)"}],
            },
            "needs named groups",
        ),
        (
            {
                "fields": {},
                "companions": _SEEN,
                "inventory": [
                    {
                        "source": "show_inventory",
                        "record": r"(?P<name>\w+) (?P<serial>\w+) (?P<owner>\w+)",
                    }
                ],
            },
            "unknown inventory group",
        ),
    ],
)
def test_a_pack_cant_read_what_it_can_t_recognise(spec: dict[str, Any], problem: str) -> None:
    with pytest.raises(ValidationError, match=problem):
        IdentitySpec.model_validate(spec)
