import json
from pathlib import Path

import pytest

import import_oscal
from kasauti.packs.loader import load_framework_pack

REPO = Path(__file__).resolve().parents[2]

MINI = {
    "catalog": {
        "metadata": {"version": "5.2.0"},
        "groups": [
            {
                "id": "ac",
                "controls": [
                    {
                        "id": "ac-17",
                        "title": "Remote Access",
                        "controls": [
                            {"id": "ac-17.2", "title": "Protection of Confidentiality"},
                            {
                                "id": "ac-17.5",
                                "title": "Monitoring",
                                "props": [{"name": "status", "value": "withdrawn"}],
                                "links": [{"href": "#si-4", "rel": "incorporated-into"}],
                            },
                        ],
                    },
                    {"id": "ac-2", "title": "Account Management"},
                ],
            }
        ],
    }
}


@pytest.mark.parametrize(
    ("oscal", "ours"), [("ac-2", "AC-2"), ("ac-17.2", "AC-17(2)"), ("sc-45.1", "SC-45(1)")]
)
def test_control_ids(oscal: str, ours: str) -> None:
    assert import_oscal.control_id(oscal) == ours


def test_extract_orders_controls_and_drops_withdrawn() -> None:
    version, controls, withdrawn = import_oscal.extract(MINI)
    assert version == "5.2.0"
    assert [c["id"] for c in controls] == ["AC-2", "AC-17", "AC-17(2)"]
    # Kept only as NIST's pointer to where the withdrawn control went, never as a citable ID.
    assert withdrawn == {"AC-17(5)": ["SI-4"]}


def test_import_from_a_local_file_writes_a_valid_framework_pack(tmp_path: Path) -> None:
    src = tmp_path / "catalog.json"
    src.write_text(json.dumps(MINI), encoding="utf-8")
    out = tmp_path / "fw" / "nist_800_53r5" / "catalog.json"
    assert (
        import_oscal.main(["--file", str(src), "--retrieved", "2026-09-26", "--out", str(out)]) == 0
    )
    pack = load_framework_pack(out.parent)
    assert pack.catalog.source_sha256
    assert len(pack.catalog.controls) == 3


def test_the_committed_catalog_is_the_pinned_official_one() -> None:
    pack = load_framework_pack(REPO / "packs" / "frameworks" / "nist_800_53r5")
    assert import_oscal.COMMIT in pack.catalog.source_url
    assert pack.catalog.version == "5.2.0"
    assert len(pack.catalog.controls) > 1000
