"""Import DISA STIGs for the seed vendors into ``packs/frameworks/disa_stig/catalog.json``
(PLAN §12.4, §20.1; TODO M2.51, M2.52).

For every STIG rule we keep what DISA publishes as a US Government work (public domain): the
STIG ID (``CISC-ND-000010``), the Vulnerability ID, the title, the category (CAT I/II/III), the
CCIs and the fix text. Each rule's NIST SP 800-53 Rev. 5 controls come from DISA's own CCI list,
which carries Rev. 5 references for most CCIs. A CCI with only a Rev. 4 reference is translated
through the imported Rev. 5 catalog: a control still active keeps its ID, a withdrawn one follows
NIST's own "moved to" / "incorporated into" link. Every translation is reported; nothing is
guessed. The crosswalk lint uses these to
check that a rule mapped to a STIG shares a NIST control with it.

Every source zip's SHA-256 is recorded, so the import can be re-run and compared.

Usage::

    uv run python tools/import_stig.py --dir <folder with the zips> --retrieved 2026-09-29
    uv run python tools/import_stig.py --retrieved 2026-09-29     # downloads from DISA
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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defusedxml.ElementTree import fromstring

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element  # nosec B405  (types only; parsing uses defusedxml)

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
PACKS = Path(__file__).resolve().parents[1] / "packs"
OUT = PACKS / "frameworks/disa_stig/catalog.json"
MAX_BYTES = 64 * 1024 * 1024
XCCDF = "{http://checklists.nist.gov/xccdf/1.1}"
CCI_NS = "{http://iase.disa.mil/cci}"


@dataclass(frozen=True)
class Stig:
    zip: str
    parts: tuple[str, ...]
    """Which of the zip's benchmarks to keep, by a word in the XCCDF file name."""
    vendors: tuple[str, ...]
    sunset: bool = False


STIGS = (
    # Device management (NDM) for every vendor, plus the traffic-side STIG our filtering and
    # service rules fall under. Layer-2, IDPS and VPN benchmarks aren't imported: no rule of ours
    # judges what they cover.
    Stig("U_Cisco_IOS-XE_Router_Y26M04_STIG.zip", ("_NDM_", "_RTR_"), ("cisco_ios_xe",)),
    Stig("U_Arista_MLS_EOS_4-X_Y25M07_STIG.zip", ("_NDM_", "_Router_"), ("arista_eos",)),
    # The Junos pack's reference devices are SRX gateways, so the SRX STIG applies.
    Stig("U_Juniper_SRX_SG_Y25M01_STIG.zip", ("_NDM_", "_ALG_"), ("juniper_junos",)),
    Stig(
        "U_FN_FortiGate_Firewall_Y26M01_STIG.zip", ("_NDM_", "Firewall_STIG"), ("fortinet_fortios",)
    ),
    # DISA sunset the Palo Alto STIG on 2026-07-10 with no successor; it is still the published
    # DoD baseline for PAN-OS, so it is kept and marked.
    Stig("U_PAN_Y26M07_STIG.zip", ("_NDM_", "_ALG_"), ("paloalto_panos",), sunset=True),
)
CCI_ZIP = "U_CCI_List.zip"
_NIST = re.compile(r"^([A-Z]{2})-(\d{1,2})(?:\s*\((\d{1,2})\))?")
_SEVERITY = {"high", "medium", "low"}


def nist_id(index: str) -> str | None:
    """``AC-2 (4)`` / ``AU-9 (2) (a)`` / ``AC-7 a`` -> ``AC-2(4)`` / ``AU-9(2)`` / ``AC-7``."""
    m = _NIST.match(index.strip())
    if m is None:
        return None
    family, number, enh = m.groups()
    return f"{family}-{int(number)}" + (f"({int(enh)})" if enh else "")


def cci_to_nist(data: bytes) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    """CCI id -> its NIST SP 800-53 controls as DISA's CCI list gives them: (Rev. 5, Rev. 4)."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next(n for n in z.namelist() if n.lower().endswith("u_cci_list.xml"))
        root = fromstring(z.read(name))
    rev5: dict[str, tuple[str, ...]] = {}
    rev4: dict[str, tuple[str, ...]] = {}
    for item in root.iter(f"{CCI_NS}cci_item"):
        for rev, out in (("5", rev5), ("4", rev4)):
            refs = {
                nid
                for ref in item.iter(f"{CCI_NS}reference")
                if ref.get("version") == rev and (nid := nist_id(ref.get("index", ""))) is not None
            }
            out[item.get("id", "")] = tuple(sorted(refs))
    return rev5, rev4


def rev5() -> tuple[set[str], dict[str, list[str]]]:
    """The imported Rev. 5 catalog: active control IDs, and where withdrawn ones went."""
    catalog = json.loads((PACKS / "frameworks/nist_800_53r5/catalog.json").read_text("utf-8"))
    return {c["id"] for c in catalog["controls"]}, catalog.get("withdrawn", {})


def _text(el: Element | None) -> str:
    return "" if el is None or el.text is None else el.text.strip()


def translate(
    rev5: dict[str, tuple[str, ...]],
    rev4: dict[str, tuple[str, ...]],
    active: set[str],
    withdrawn: dict[str, list[str]],
) -> tuple[dict[str, tuple[str, ...]], list[str]]:
    """Each CCI's Rev. 5 controls. A Rev. 4-only CCI keeps each control still active in Rev. 5
    and follows NIST's link for a withdrawn one. Returns a note on every CCI that needed it."""
    out = dict(rev5)
    notes: list[str] = []
    for cci, ids in rev4.items():
        if rev5.get(cci):
            continue
        kept = sorted(
            {i for i in ids if i in active}
            | {t for i in ids if i not in active for t in withdrawn.get(i, ()) if t in active}
        )
        out[cci] = tuple(kept)
        how = ", ".join(
            i
            if i in active
            else f"{i} (withdrawn, now {', '.join(withdrawn.get(i, ())) or 'nowhere'})"
            for i in ids
        )
        notes.append(
            f"{cci}: no Rev. 5 reference; Rev. 4 {how or 'none'} -> {', '.join(kept) or 'unmapped'}"
        )
    return out, notes


def benchmark(
    xml: bytes, stig: Stig, source: dict[str, Any], cci: dict[str, tuple[str, ...]]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    root = fromstring(xml)
    bid = root.get("id", "")
    release = _text(root.find(f"{XCCDF}plain-text[@id='release-info']"))
    m = re.search(r"Release:\s*(\d+)\s+Benchmark Date:\s*(.+)$", release)
    if m is None:
        raise ValueError(f"{bid}: unexpected release-info {release!r}")
    version = f"V{_text(root.find(f'{XCCDF}version'))}R{m.group(1)}"
    bench = {
        "id": bid,
        "title": _text(root.find(f"{XCCDF}title")),
        "version": version,
        "released": m.group(2).strip(),
        "vendors": list(stig.vendors),
        "source": source,
        "sunset": stig.sunset,
    }
    controls: list[dict[str, Any]] = []
    gaps: list[str] = []
    for group in root.iter(f"{XCCDF}Group"):
        rule = group.find(f"{XCCDF}Rule")
        if rule is None:
            continue
        stig_id = _text(rule.find(f"{XCCDF}version"))
        severity = rule.get("severity", "")
        if severity not in _SEVERITY:
            raise ValueError(f"{bid} {stig_id}: unexpected severity {severity!r}")
        ccis = sorted(
            _text(i)
            for i in rule.iter(f"{XCCDF}ident")
            if i.get("system") == "http://cyber.mil/cci"
        )
        nist = sorted({n for c in ccis for n in cci.get(c, ())})
        gaps += [f"{stig_id}: {c} maps to no active Rev. 5 control" for c in ccis if not cci.get(c)]
        controls.append(
            {
                "id": stig_id,
                "title": _text(rule.find(f"{XCCDF}title")),
                "benchmark": bid,
                "severity": severity,
                "vuln_id": group.get("id"),
                "ccis": ccis,
                "nist": nist,
                "fix": _text(rule.find(f"{XCCDF}fixtext")) or None,
            }
        )
    return bench, controls, gaps


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("only https sources are accepted")
    request = urllib.request.Request(url, headers={"User-Agent": "kasauti-import"})  # noqa: S310
    # The scheme is checked to be https just above, so file:// and custom schemes can't reach here.
    with urllib.request.urlopen(request, timeout=120) as resp:  # noqa: S310  # nosec B310
        data: bytes = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url} larger than expected; refusing")
    return data


def _load(name: str, folder: Path | None) -> bytes:
    return (folder / name).read_bytes() if folder else fetch(BASE + name)


def build(folder: Path | None, retrieved: str) -> tuple[dict[str, Any], list[str]]:
    cci_zip = _load(CCI_ZIP, folder)
    cci, notes = translate(*cci_to_nist(cci_zip), *rev5())
    benchmarks: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    gaps: list[str] = []
    for stig in STIGS:
        data = _load(stig.zip, folder)
        source = {
            "title": stig.zip.removesuffix(".zip"),
            "version": stig.zip.removesuffix("_STIG.zip").rsplit("_", 1)[-1],
            "url": BASE + stig.zip,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = sorted(
                n
                for n in z.namelist()
                if n.endswith("-xccdf.xml") and any(p in n for p in stig.parts)
            )
            if len(names) != len(stig.parts):
                raise ValueError(
                    f"{stig.zip}: expected {len(stig.parts)} benchmarks, found {names}"
                )
            for name in names:
                bench, found, missing = benchmark(z.read(name), stig, source, cci)
                benchmarks.append(bench)
                controls += found
                gaps += missing
    used = {c for control in controls for c in control["ccis"]}
    gaps = [n for n in notes if n.split(":")[0] in used] + gaps
    doc = {
        "format_version": 1,
        "framework": "disa_stig",
        "title": "DISA Security Technical Implementation Guides",
        "version": max(s.zip.removesuffix("_STIG.zip").rsplit("_", 1)[-1] for s in STIGS),
        "source_url": "https://www.cyber.mil/stigs/downloads",
        "source_sha256": None,
        "licence": (
            "US Government work (DISA), public domain; IDs, titles, categories, CCIs and fix text"
        ),
        "retrieved": retrieved,
        "benchmarks": benchmarks,
        "bridge": {
            "title": "DISA Control Correlation Identifier (CCI) list",
            "version": "NIST SP 800-53 Rev. 5 references",
            "url": BASE + CCI_ZIP,
            "sha256": hashlib.sha256(cci_zip).hexdigest(),
        },
        "controls": sorted(controls, key=lambda c: (c["benchmark"], c["id"])),
    }
    return doc, gaps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, help="folder holding the DISA zips (else download)")
    parser.add_argument("--retrieved", required=True, help="date retrieved, YYYY-MM-DD")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)

    doc, gaps = build(args.dir, args.retrieved)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    args.out.write_bytes(text.encode("utf-8"))  # LF on every OS
    for gap in gaps:
        print(f"note: {gap}")
    print(
        f"wrote {len(doc['controls'])} STIG rules from {len(doc['benchmarks'])} benchmarks "
        f"to {args.out} ({len(gaps)} notes on the Rev. 4 -> Rev. 5 bridge)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
