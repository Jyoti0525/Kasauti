"""Vendor fingerprinting and device identity (PLAN §7; TODO M1.04, M2.18-M2.20)."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from kasauti.identity import detect
from kasauti.identity.detect import Detection, choose, detect_vendor
from kasauti.identity.resolve import resolve_identity
from kasauti.packs.loader import VendorPack, load_vendor_pack, load_vendor_packs
from kasauti.packs.model import DetectSpec, Signature
from kasauti.shape.model import ConfigTree
from kasauti.shape.parse import parse_text

REPO = Path(__file__).resolve().parents[3]
AUTHORED = REPO / "datasets" / "authored"


@pytest.fixture(scope="module")
def cisco() -> VendorPack:
    return load_vendor_pack(REPO / "packs" / "vendors" / "cisco_ios_xe")


def test_cisco_configs_are_fingerprinted(cisco: VendorPack) -> None:
    for name in ("weak.cfg", "hardened.cfg"):
        text = (AUTHORED / "cisco_ios_xe" / name).read_text(encoding="utf-8")
        chosen = choose(detect_vendor(text, [cisco]))
        assert chosen is not None
        assert chosen.pack_id == "cisco_ios_xe"


def test_other_vendors_are_not_mistaken_for_cisco(cisco: VendorPack) -> None:
    junos = (AUTHORED / "juniper_junos" / "hardened.conf").read_text(encoding="utf-8")
    assert choose(detect_vendor(junos, [cisco])) is None
    nxos_like = "version 9.3(8)\nfeature ssh\nline vty\n  exec-timeout 10\n!\n"
    assert choose(detect_vendor(nxos_like, [cisco])) is None


# The start of the running configuration printed in Cisco's 900 Series ISR Software
# Configuration Guide, "Basic Router Configuration": classic IOS 15.8.
CLASSIC_IOS = """\
Building configuration...

Current configuration : 1087 bytes
!
! No configuration change since last restart
! NVRAM config last updated at 06:11:03 UTC Mon Sep 17 2018
!
version 15.8
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname Router
!
boot-start-marker
boot-end-marker
!
ip cef
!
interface GigabitEthernet0/0
 no ip address
!
line vty 0 4
 login
!
end
"""

# The header of the NX-OS output in Cisco's Nexus 3600 Label Switching Configuration Guide,
# 9.3(x), followed by lines IOS XE also has.
NXOS = """\
!Command: show running-config segment-routing mpls
!Time: Fri June 21 11:22:53 2019

version 9.3(1)
service timestamps log datetime msec
ip domain-lookup
interface Vlan1
!
"""


def test_nxos_and_classic_ios_are_ruled_out_of_ios_xe(cisco: VendorPack) -> None:
    """M2.26: no seed pack reads NX-OS or classic IOS, and classic IOS 15 carries every IOS XE
    signature. The pack's `excludes` keep it from claiming either; IOS XE 17 is still claimed
    (test_cisco_configs_are_fingerprinted)."""
    classic = detect_vendor(CLASSIC_IOS, [cisco])[0]
    assert classic.score >= classic.min_score
    assert [e[0] for e in classic.excluded] == ["release-15-or-earlier"]
    assert choose([classic]) is None
    nxos = detect_vendor(NXOS, [cisco])[0]
    assert [(e[0], e[1]) for e in nxos.excluded] == [("nxos-version", 4), ("nxos-header", 1)]
    note = nxos.exclusion_note()
    assert note is not None
    assert note.startswith("This looks like a Cisco NX-OS configuration")
    assert note.endswith("(line 4)")
    for newer in ("version 16.12\n", "version 17.9\n", "version 26.1\n"):
        assert not detect_vendor(newer, [cisco])[0].excluded, newer


def test_a_pack_ruled_out_never_wins_or_ties() -> None:
    ruled_out = Detection("a", 2.0, 0.5, (("s", 1),), (("x", 1, "another OS"),))
    other = Detection("b", 1.0, 0.5, (("s", 1),))
    assert not ruled_out.confident
    assert choose([other, ruled_out]) is other
    level = Detection("a", 1.0, 0.5, (("s", 1),), (("x", 1, "another OS"),))
    assert choose([other, level]) is other
    assert choose([ruled_out]) is None
    assert other.exclusion_note() is None


def test_ruled_out_packs_sort_last(cisco: VendorPack) -> None:
    arista = load_vendor_pack(REPO / "packs" / "vendors" / "arista_eos")
    found = detect_vendor(NXOS, [cisco, arista])
    assert [d.pack_id for d in found] == ["arista_eos", "cisco_ios_xe"]


ALL_PACKS = load_vendor_packs(REPO / "packs")
SAMPLES = sorted(
    p for p in AUTHORED.rglob("*") if p.is_file() and p.parent.name in {*ALL_PACKS, "companions"}
) + sorted(p for p in AUTHORED.glob("*/fixtures/*") if p.is_file())


def test_the_sample_walk_finds_the_corpus() -> None:
    assert len(SAMPLES) >= 26, "fewer samples than in v5.1.26: has the corpus moved?"


def _vendor(path: Path) -> str:
    return next(part for part in path.relative_to(AUTHORED).parts if part in ALL_PACKS)


@pytest.mark.parametrize("path", SAMPLES, ids=[p.relative_to(AUTHORED).as_posix() for p in SAMPLES])
def test_every_sample_against_every_pack(path: Path) -> None:
    """TODO M2.18: each file scored against all five packs, as an upload is. A whole
    configuration is claimed by its own vendor; a fragment without the device's header lines (a
    fixture) by its own or by none, left for the operator; a command output by none. And no
    other pack is ever confident: a wrong vendor would audit with the wrong mappings."""
    text = path.read_text(encoding="utf-8")
    vendor = _vendor(path)
    found = detect_vendor(text, list(ALL_PACKS.values()))
    chosen = choose(found)
    assert not [d.pack_id for d in found if d.confident and d.pack_id != vendor]
    if "companions" in path.parts:
        assert chosen is None
    elif "fixtures" in path.parts:
        assert chosen is None or chosen.pack_id == vendor
    else:
        assert chosen is not None
        assert chosen.pack_id == vendor


def test_ties_are_never_resolved_by_guessing() -> None:
    a = Detection("a", 1.0, 0.5, (("s", 1),))
    b = Detection("b", 1.0, 0.5, (("s", 1),))
    assert choose([a, b]) is None
    assert choose([Detection("a", 0.4, 0.5, ())]) is None


def test_identity_from_config_with_sources_and_stated_gaps(cisco: VendorPack) -> None:
    text = (AUTHORED / "cisco_ios_xe" / "weak.cfg").read_text(encoding="utf-8")
    tree = parse_text(text, source_file="weak.cfg", family=cisco.manifest.shape_family)
    detection = choose(detect_vendor(text, [cisco]))
    ident = resolve_identity(tree, cisco, detection, text)
    assert ident.device.hostname.value == "EDGE-R1"
    assert ident.device.os_version.value == "17.9"
    assert ident.device.vendor.value == "Cisco"
    assert ident.sources["hostname"] == "config line 10"
    assert ident.sources["os_version"] == "config line 6"
    assert ident.missing["serial"] == (
        "Serial: not present in supplied artefacts; upload `show inventory` or `show version` "
        "to populate"
    )
    assert ident.lines == {6, 10}
    assert ident.device.hostname.evidence[0].raw == "hostname EDGE-R1"


def test_a_tree_is_parsed_only_for_a_signature_that_reads_structure(
    cisco: VendorPack, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parsing is most of an audit's cost; text signatures never need it (M2.04 follow-up)."""
    panos = load_vendor_pack(REPO / "packs" / "vendors" / "paloalto_panos")
    structural = dataclasses.replace(
        panos,
        detect=DetectSpec(
            signatures=(
                Signature(
                    id="deviceconfig-path",
                    kind="xml_path",
                    pattern="devices/entry/deviceconfig",
                    weight=1,
                ),
            ),
            min_score=1,
        ),
    )
    parsed: list[str] = []

    def counting(text: str, **kw: Any) -> ConfigTree:
        parsed.append(kw["family"])
        return parse_text(text, **kw)

    monkeypatch.setattr(detect, "parse_text", counting)
    xml = (AUTHORED / "paloalto_panos" / "weak.xml").read_text(encoding="utf-8")
    detect_vendor(xml, [cisco, panos])
    assert parsed == []
    chosen = choose(detect_vendor(xml, [cisco, structural]))
    assert chosen is not None
    assert chosen.pack_id == "paloalto_panos"
    assert parsed == ["xml"]
