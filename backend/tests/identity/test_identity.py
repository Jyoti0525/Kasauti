"""Vendor fingerprinting and device identity (PLAN §7; TODO M1.04, M2.18-M2.20)."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from kasauti.identity import detect
from kasauti.identity.detect import Detection, choose, detect_vendor
from kasauti.identity.resolve import resolve_identity
from kasauti.packs.loader import VendorPack, load_vendor_pack
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
