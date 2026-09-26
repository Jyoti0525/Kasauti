"""Import NIST SP 800-53 Rev. 5 control IDs and titles from NIST's official OSCAL catalog
(PLAN §12.4, §20.1; TODO M2.50, pulled into M1 because the crosswalk lint needs it).

The catalog is public domain (a US Government work). We keep only IDs and titles: enough for
the crosswalk lint (S.06: no rule may cite an ID that isn't in the official catalog) and for
report labels. Withdrawn controls are left out, so citing one fails the lint.

The source is pinned to a commit of github.com/usnistgov/oscal-content and its SHA-256 is
recorded in the output, so anyone can re-run the import and get the same file.

Usage::

    uv run python tools/import_oscal.py --retrieved 2026-09-26
    uv run python tools/import_oscal.py --file NIST_SP-800-53_rev5_catalog.json --retrieved …
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

COMMIT = "78650f02ad9321bb7b817846f8fbd4f2bcd620de"
"""usnistgov/oscal-content, last change to the Rev. 5 JSON catalog (2026-05-13)."""
URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/{commit}/nist.gov/SP800-53/rev5/"
    "json/NIST_SP-800-53_rev5_catalog.json"
)
OUT = Path(__file__).resolve().parents[1] / "packs/frameworks/nist_800_53r5/catalog.json"
MAX_BYTES = 64 * 1024 * 1024
_ID = re.compile(r"^([a-z]{2})-(\d{1,2})(?:\.(\d{1,2}))?$")


def control_id(oscal: str) -> str:
    """``ac-17.2`` -> ``AC-17(2)``; ``ac-2`` -> ``AC-2``."""
    m = _ID.match(oscal)
    if m is None:
        raise ValueError(f"unexpected OSCAL control id {oscal!r}")
    family, number, enhancement = m.groups()
    return f"{family.upper()}-{int(number)}" + (f"({int(enhancement)})" if enhancement else "")


def _withdrawn(control: dict[str, Any]) -> bool:
    return any(
        p.get("name") == "status" and p.get("value") == "withdrawn"
        for p in control.get("props", [])
    )


def _walk(controls: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for control in controls:
        yield control
        yield from _walk(control.get("controls", []))


def extract(catalog: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    body = catalog["catalog"]
    version = str(body["metadata"]["version"])
    out = [
        {"id": control_id(c["id"]), "title": c["title"]}
        for group in body["groups"]
        for c in _walk(group.get("controls", []))
        if not _withdrawn(c)
    ]
    return version, sorted(out, key=lambda c: _order(c["id"]))


def _order(cid: str) -> tuple[str, int, int]:
    family, _, rest = cid.partition("-")
    number, _, enh = rest.partition("(")
    return family, int(number), int(enh.rstrip(")") or 0)


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("only https sources are accepted")
    # The scheme is checked to be https just above, so file:// and custom schemes can't reach here.
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310  # nosec B310
        data: bytes = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("catalog larger than expected; refusing")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--commit", default=COMMIT)
    parser.add_argument("--file", type=Path, help="use a local copy instead of downloading")
    parser.add_argument("--retrieved", required=True, help="date retrieved, YYYY-MM-DD")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)

    url = URL.format(commit=args.commit)
    data = args.file.read_bytes() if args.file else fetch(url)
    version, controls = extract(json.loads(data))
    doc = {
        "format_version": 1,
        "framework": "nist_800_53r5",
        "title": "NIST SP 800-53 Rev. 5: Security and Privacy Controls",
        "version": version,
        "source_url": url,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "licence": "Public domain (US Government work, 17 U.S.C. 105); IDs and titles only",
        "retrieved": args.retrieved,
        "controls": controls,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    args.out.write_bytes(text.encode("utf-8"))  # LF on every OS
    print(f"wrote {len(controls)} controls (catalog {version}) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
