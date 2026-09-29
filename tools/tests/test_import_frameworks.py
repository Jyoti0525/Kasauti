"""tools/import_stig.py and tools/import_olir.py on small stand-ins for DISA's and NIST's files."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

import import_olir
import import_stig
from kasauti.packs.loader import load_framework_pack

XCCDF = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Test_NDM_STIG">
  <title>Test NDM Security Technical Implementation Guide</title>
  <plain-text id="release-info">Release: 7 Benchmark Date: 01 Apr 2026</plain-text>
  <version>3</version>
  <Group id="V-1"><title>SRG</title>
    <Rule id="SV-1r1_rule" severity="high">
      <version>TEST-ND-000010</version>
      <title>The device must not run Telnet.</title>
      <ident system="http://cyber.mil/cci">CCI-000381</ident>
      <fixtext>no telnet</fixtext>
    </Rule>
  </Group>
  <Group id="V-2"><title>SRG</title>
    <Rule id="SV-2r1_rule" severity="medium">
      <version>TEST-ND-000020</version>
      <title>The device must synchronise its clock.</title>
      <ident system="http://cyber.mil/cci">CCI-001893</ident>
    </Rule>
  </Group>
</Benchmark>"""

CCI = """<?xml version="1.0"?>
<cci_list xmlns="http://iase.disa.mil/cci"><cci_items>
  <cci_item id="CCI-000381"><references>
    <reference version="4" index="CM-7 a" /><reference version="5" index="CM-7 a" />
  </references></cci_item>
  <cci_item id="CCI-001893"><references>
    <reference version="4" index="AU-8 (2)" />
  </references></cci_item>
</cci_items></cci_list>"""


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


@pytest.mark.parametrize(
    ("index", "ours"),
    [("AC-2 (4)", "AC-2(4)"), ("AU-9 (2) (a)", "AU-9(2)"), ("AC-7 a", "AC-7"), ("x", None)],
)
def test_nist_ids_from_the_cci_list(index: str, ours: str | None) -> None:
    assert import_stig.nist_id(index) == ours


def test_a_rev4_only_cci_follows_nists_own_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stig = import_stig.Stig("U_Test_STIG.zip", ("_NDM_",), ("cisco_ios_xe",))
    monkeypatch.setattr(import_stig, "STIGS", (stig,))
    monkeypatch.setattr(
        import_stig, "rev5", lambda: ({"CM-7", "SC-45(2)"}, {"AU-8(2)": ["SC-45(2)"]})
    )
    (tmp_path / "U_Test_STIG.zip").write_bytes(_zip({"x/U_Test_NDM_STIG-xccdf.xml": XCCDF}))
    (tmp_path / "U_CCI_List.zip").write_bytes(_zip({"U_CCI_List.xml": CCI}))
    doc, notes = import_stig.build(tmp_path, "2026-09-29")
    (bench,) = doc["benchmarks"]
    assert (bench["id"], bench["version"], bench["released"]) == (
        "Test_NDM_STIG",
        "V3R7",
        "01 Apr 2026",
    )
    assert (
        bench["source"]["sha256"]
        == hashlib.sha256((tmp_path / "U_Test_STIG.zip").read_bytes()).hexdigest()
    )
    telnet, clock = doc["controls"]
    assert (telnet["id"], telnet["severity"], telnet["vuln_id"], telnet["nist"]) == (
        "TEST-ND-000010",
        "high",
        "V-1",
        ["CM-7"],
    )
    # AU-8(2) was withdrawn in Rev. 5 and moved to SC-45(2); the note says so.
    assert clock["nist"] == ["SC-45(2)"]
    assert any("CCI-001893" in n and "SC-45(2)" in n for n in notes)

    out = tmp_path / "fw" / "disa_stig" / "catalog.json"
    out.parent.mkdir(parents=True)
    out.write_text(json.dumps(doc), encoding="utf-8")
    assert load_framework_pack(out.parent).catalog.benchmarks_for("cisco_ios_xe")


def _xlsx(rows: list[list[str]]) -> bytes:
    shared = sorted({v for r in rows for v in r})
    index = {v: i for i, v in enumerate(shared)}
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    cells = "".join(
        f'<row r="{i + 1}">'
        + "".join(f'<c r="{"ABCD"[j]}{i + 1}" t="s"><v>{index[v]}</v></c>' for j, v in enumerate(r))
        + "</row>"
        for i, r in enumerate(rows)
    )
    return _zip(
        {
            "xl/workbook.xml": f'<workbook xmlns="{main}" xmlns:r="{rel}"><sheets>'
            '<sheet name="AC" r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": '<Relationships><Relationship Id="rId1" '
            'Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{main}"><sheetData>{cells}'
            "</sheetData></worksheet>",
            "xl/sharedStrings.xml": f'<sst xmlns="{main}">'
            + "".join(f"<si><t>{v}</t></si>" for v in shared)
            + "</sst>",
        }
    )


def test_olir_rows_become_annex_a_relations(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _xlsx(
        [
            ["Focal Document Element", "Description", "Baseline", "Reference Document Element"],
            ["AC-03", "text", "Low", "A.5.15"],
            ["AC-17", "text", "Low", "A.8.20"],
            ["AC-17", "text", "Low", "5.2"],  # an ISMS clause, not Annex A
        ]
    )
    monkeypatch.setattr(import_olir, "SHA256", hashlib.sha256(data).hexdigest())
    doc = import_olir.build(data, "2026-09-29")
    by_id = {c["id"]: c for c in doc["controls"]}
    assert len(by_id) == 93
    assert by_id["A.5.15"]["nist"] == ["AC-3"]
    assert by_id["A.8.20"]["nist"] == ["AC-17"]
    assert by_id["A.5.1"]["nist"] == []


def test_olir_refuses_a_workbook_that_isnt_nists() -> None:
    with pytest.raises(ValueError, match="differs from NIST"):
        import_olir.build(_xlsx([["AC-03", "x", "Low", "A.5.15"]]), "2026-09-29")
