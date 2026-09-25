from itertools import pairwise

import pytest

from kasauti.packs.versions import Version, VersionRange


@pytest.mark.parametrize(
    "ordered",
    [
        ["16.9.1", "17.3.4", "17.3.4a", "17.12.1"],  # Cisco IOS-XE
        ["20.4R3", "21.4R3", "21.4R3-S2", "22.1R1"],  # Junos
        ["10.2.9", "10.2.9-h1", "10.2.10", "11.0.0"],  # PAN-OS
        ["6.4.9", "7.0.0", "7.2.8", "7.4.1"],  # FortiOS
        ["4.25.1F", "4.30.0F", "4.32.2F"],  # Arista EOS
    ],
)
def test_natural_ordering(ordered: list[str]) -> None:
    versions = [Version.parse(v) for v in ordered]
    assert all(a < b for a, b in pairwise(versions))


def test_ranges() -> None:
    r = VersionRange.parse(">=16.9,<17.3")
    assert r.contains("16.12.4")
    assert not r.contains("17.3.1")
    assert VersionRange.parse("*").contains("anything-1")
    assert VersionRange.parse("==21.4R3-S2").contains("21.4r3-s2")
    assert VersionRange.parse("!=7.0.0").contains("7.0.1")


@pytest.mark.parametrize("bad", [">= ", "~>1.0", ">=1.0;<2", "=>1"])
def test_bad_ranges_rejected(bad: str) -> None:
    with pytest.raises(ValueError, match="bad version clause"):
        VersionRange.parse(bad)
