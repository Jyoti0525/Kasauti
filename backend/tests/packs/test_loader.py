from pathlib import Path

import pytest

from kasauti.cli.main import main
from kasauti.packs.loader import PackError, load_ruleset, load_vendor_pack

REPO = Path(__file__).resolve().parents[3]

MANIFEST = """format_version: 1
id: acme_os
name: Acme OS
vendor: Acme
os_family: acme_os
shape_family: indent
pack_version: 1
negation_words: ["no"]
comment_markers: ["!"]
"""
DETECT = """signatures:
  - {id: banner, kind: contains, pattern: "Acme OS", weight: 0.9}
"""
IDENTITY = """fields:
  hostname:
    - {source: config, pattern: "hostname <STR:value>"}
"""
MAPPINGS = """mappings:
  - id: acme_os/telnet-server
    vendor: acme_os
    entity: {type: MgmtService, key: telnet}
    match: "telnet server enable"
    effect: {assert: MgmtService.enabled, value: true}
    provenance: {version: 1, proposed_by: seed}
"""
DEFAULTS = """defaults:
  - id: telnet-off
    attr: MgmtService.enabled
    entity_key: telnet
    value: false
    os_versions: ">=2.0"
    source: vendor_doc
    reference: "Acme OS 2.0 admin guide, section 4.1"
"""


def _pack(tmp_path: Path, **files: str) -> Path:
    root = tmp_path / "acme_os"
    root.mkdir(parents=True)
    base = {
        "pack.yaml": MANIFEST,
        "detect.yaml": DETECT,
        "identity.yaml": IDENTITY,
        "mappings/core.yaml": MAPPINGS,
        "defaults.yaml": DEFAULTS,
    }
    for name, text in {**base, **files}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_valid_pack_loads(tmp_path: Path) -> None:
    pack = load_vendor_pack(_pack(tmp_path))
    assert pack.manifest.id == "acme_os"
    assert pack.mappings[0].id == "acme_os/telnet-server"
    assert pack.defaults.defaults[0].os_versions == ">=2.0"


def test_code_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PackError, match="not allowed in a pack"):
        load_vendor_pack(_pack(tmp_path, **{"mappings/evil.py": "import os"}))


def test_only_an_empty_gitkeep_is_tolerated(tmp_path: Path) -> None:
    load_vendor_pack(_pack(tmp_path, **{"recipes/.gitkeep": ""}))
    with pytest.raises(PackError, match="not allowed in a pack"):
        load_vendor_pack(_pack(tmp_path / "x", **{"recipes/.gitkeep": "payload"}))


def test_problems_are_collected_not_first_only(tmp_path: Path) -> None:
    root = _pack(tmp_path, **{"detect.yaml": "signatures: []", "identity.yaml": "fields: 3"})
    with pytest.raises(PackError) as err:
        load_vendor_pack(root)
    assert len(err.value.problems) >= 2


def test_foreign_mapping_rejected(tmp_path: Path) -> None:
    other = MAPPINGS.replace("acme_os/", "other_os/").replace("vendor: acme_os", "vendor: other_os")
    with pytest.raises(PackError, match="is not this pack"):
        load_vendor_pack(_pack(tmp_path, **{"mappings/core.yaml": other}))


def test_rules_are_checked_against_derivations(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    (tmp_path / "derivations").mkdir()
    (tmp_path / "rules" / "r.yaml").write_text(
        """rules:
  - id: MGMT-TELNET-01
    title: Telnet not reachable
    intent: No clear-text credentials.
    domain: management_plane
    for_each: Device
    assert: not management.telnet_reachable
    severity: {base: high}
    fix_intent: {make: management.telnet_reachable, equal: false}
    refs: {nist_800_53r5: [CM-7]}
""",
        encoding="utf-8",
    )
    with pytest.raises(PackError, match="unknown derived fact"):
        load_ruleset(tmp_path / "rules", tmp_path / "derivations")


def test_repository_packs_are_valid(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["packs", "validate", str(REPO / "packs")]) == 0
    assert "FAIL" not in capsys.readouterr().out
