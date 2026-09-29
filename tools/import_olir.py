"""Import ISO/IEC 27001:2022 Annex A control numbers and NIST's official bridge to them, NIST OLIR
#155 (SP 800-53 Rev. 5 -> ISO/IEC 27001:2022), into
``packs/frameworks/iso_27001_2022/catalog.json`` (PLAN §12.4, §20.1; TODO M2.53, M2.55).

ISO/IEC 27001 is a copyrighted standard: we keep Annex A control *numbers* only, each with a
short description written by us (``WORDING``), never ISO's text. NIST publishes OLIR #155 as an
informative reference: its relationships are not equivalences, so a rule's ISO controls are
derived from its NIST anchors and then reviewed (the crosswalk); the lint only lets a rule cite
an ISO control that OLIR #155 relates to one of its anchors.

OLIR #155 relates base controls, not enhancements (``AC-17(2)`` has no row of its own). A rule
anchored to an enhancement is related through its base control, the one the enhancement
strengthens; the crosswalk lint applies the same step.

The workbook is read with the standard library (an .xlsx is a zip of XML), so no spreadsheet
dependency is added.

Usage::

    uv run python tools/import_olir.py --retrieved 2026-09-29
    uv run python tools/import_olir.py --file olir155.xlsx --retrieved 2026-09-29
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import fromstring

URL = (
    "https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/"
    "sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx"
)
SHA256 = "e631de234a1fac057991773f015c221226940540f5602e1b70a3768eaff5cbd9"
"""As NIST's OLIR catalog lists it for reference #155, v1.0.0 (posted 2023-11-13)."""
OUT = Path(__file__).resolve().parents[1] / "packs/frameworks/iso_27001_2022/catalog.json"
MAX_BYTES = 16 * 1024 * 1024
_M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_FOCAL = re.compile(r"^([A-Z]{2})-(\d{1,2})(?:\((\d{1,2})\))?$")
_ANNEX = re.compile(r"^A\.([5-8])\.(\d{1,2})$")
ANNEX_A = {5: 37, 6: 8, 7: 14, 8: 34}
"""Annex A of ISO/IEC 27001:2022: themes 5-8 and how many controls each holds (93)."""

WORDING = {
    # Our own short descriptions, only for the controls our rules are mapped to. Not ISO text.
    "A.5.15": "Who may reach which systems and information is decided and enforced",
    "A.5.16": "Every person and system that logs in has a managed identity",
    "A.5.17": "Passwords, keys and other secrets are set, stored and handled safely",
    "A.5.18": "Access rights are granted, reviewed and removed through a defined process",
    "A.8.2": "Administrative (privileged) access is limited and controlled",
    "A.8.5": "The login process itself resists misuse",
    "A.8.9": "Device settings are defined, documented and kept under control",
    "A.8.15": "Security-relevant activity is recorded and the records are protected",
    "A.8.17": "Device clocks follow an agreed time source",
    "A.8.19": "What runs on live systems is controlled; nothing unneeded is enabled",
    "A.8.20": "Networks and network devices are secured and managed",
    "A.8.22": "Networks are split into zones and traffic between them is controlled",
    "A.8.24": "Cryptography is used, and used correctly, where it is required",
    "A.8.32": "Changes to systems follow a controlled process",
}


def focal_id(text: str) -> str | None:
    """``AC-02(01)`` -> ``AC-2(1)``."""
    m = _FOCAL.match(text.strip())
    if m is None:
        return None
    family, number, enh = m.groups()
    return f"{family}-{int(number)}" + (f"({int(enh)})" if enh else "")


def annex_order(cid: str) -> tuple[int, int]:
    m = _ANNEX.match(cid)
    if m is None:
        raise ValueError(f"not an Annex A control: {cid!r}")
    return int(m.group(1)), int(m.group(2))


def rows(data: bytes) -> list[list[str]]:
    """Every row of every sheet, as text."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        shared = [
            "".join(t.text or "" for t in si.iter(f"{_M}t"))
            for si in fromstring(z.read("xl/sharedStrings.xml")).findall(f"{_M}si")
        ]
        rels = {
            r.get("Id"): r.get("Target", "")
            for r in fromstring(z.read("xl/_rels/workbook.xml.rels"))
        }
        out: list[list[str]] = []
        sheets = fromstring(z.read("xl/workbook.xml")).find(f"{_M}sheets")
        for sheet in [] if sheets is None else list(sheets):
            target = rels[sheet.get(f"{_R}id")].lstrip("/").removeprefix("xl/")
            for row in fromstring(z.read(f"xl/{target}")).iter(f"{_M}row"):
                cells: dict[int, str] = {}
                for c in row.findall(f"{_M}c"):
                    v = c.find(f"{_M}v")
                    if v is None or v.text is None:
                        continue
                    col = 0
                    for ch in re.match(r"[A-Z]+", c.get("r", "A")).group():  # type: ignore[union-attr]
                        col = col * 26 + ord(ch) - 64
                    cells[col - 1] = shared[int(v.text)] if c.get("t") == "s" else v.text
                if cells:
                    out.append([cells.get(i, "") for i in range(max(cells) + 1)])
    return out


def relationships(data: bytes) -> dict[str, set[str]]:
    """Annex A control -> the NIST SP 800-53 Rev. 5 controls OLIR #155 relates to it."""
    out: dict[str, set[str]] = defaultdict(set)
    for row in rows(data):
        if len(row) < 4:
            continue
        nist, ref = focal_id(row[0]), row[3].strip()
        if nist is not None and _ANNEX.match(ref):
            out[ref].add(nist)
    return out


def _nist_order(cid: str) -> tuple[str, int, int]:
    family, _, rest = cid.partition("-")
    number, _, enh = rest.partition("(")
    return family, int(number), int(enh.rstrip(")") or 0)


def build(data: bytes, retrieved: str) -> dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError(f"OLIR #155 workbook hash {digest} differs from NIST's {SHA256}")
    related = relationships(data)
    ids = [f"A.{theme}.{n}" for theme, count in ANNEX_A.items() for n in range(1, count + 1)]
    stray = sorted(set(related) - set(ids))
    if stray:
        raise ValueError(f"OLIR #155 cites controls outside Annex A: {stray}")
    unknown = sorted(set(WORDING) - set(ids))
    if unknown:
        raise ValueError(f"wording for unknown controls: {unknown}")
    return {
        "format_version": 1,
        "framework": "iso_27001_2022",
        "title": "ISO/IEC 27001:2022 Annex A",
        "version": "2022",
        "source_url": URL,
        "source_sha256": digest,
        "licence": (
            "Annex A control numbers only; descriptions are our own wording, not ISO text "
            "(ISO/IEC 27001 is copyrighted). Relationships: NIST OLIR #155, a public NIST "
            "informative reference"
        ),
        "retrieved": retrieved,
        "bridge": {
            "title": "NIST OLIR #155: SP 800-53 Rev. 5 to ISO/IEC 27001:2022",
            "version": "1.0.0",
            "url": URL,
            "sha256": digest,
            "released": "2023-11-13",
        },
        "controls": [
            {
                "id": cid,
                "title": WORDING.get(cid, ""),
                "nist": sorted(related.get(cid, ()), key=_nist_order),
            }
            for cid in sorted(ids, key=annex_order)
        ],
    }


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("only https sources are accepted")
    request = urllib.request.Request(url, headers={"User-Agent": "kasauti-import"})  # noqa: S310
    # The scheme is checked to be https just above, so file:// and custom schemes can't reach here.
    with urllib.request.urlopen(request, timeout=60) as resp:  # noqa: S310  # nosec B310
        data: bytes = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("workbook larger than expected; refusing")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--file", type=Path, help="use a local copy instead of downloading")
    parser.add_argument("--retrieved", required=True, help="date retrieved, YYYY-MM-DD")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)

    doc = build(args.file.read_bytes() if args.file else fetch(URL), args.retrieved)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    args.out.write_bytes(text.encode("utf-8"))  # LF on every OS
    related = sum(1 for c in doc["controls"] if c["nist"])
    print(
        f"wrote {len(doc['controls'])} Annex A controls ({related} related to NIST by OLIR #155) "
        f"to {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
