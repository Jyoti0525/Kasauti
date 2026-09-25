"""CI licence gate over every installed distribution (docs/TODO.md M0.07, PLAN §19.5, §28).

Reads each package's metadata (License-Expression, classifiers, License) and fails on:

* a licence family we don't accept (GPL/AGPL/SSPL/RSAL/BUSL/non-commercial);
* a package on the rejected list from PLAN §19.5;
* LGPL in a *runtime* dependency, except those the plan accepts unmodified (psycopg, paramiko);
* a licence we can't determine and haven't verified by hand (``VERIFIED`` below).

Runtime dependencies (everything reachable from ``kasauti``'s own requirements) ship to users,
so they get the strict policy. Dev-only tools (test runners, scanners) are never distributed;
for them unmodified LGPL/MPL is acceptable, but GPL/AGPL and the rejected list still fail.

Usage: ``uv run python tools/check_licences.py``
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata

from packaging.requirements import Requirement

ALLOWED = re.compile(
    r"\b(MIT|BSD|Apache|PSF|Python Software Foundation|ISC|MPL[- ]?2\.0"
    r"|Mozilla Public License 2\.0|Unlicense|CC0|Zlib|0BSD|HPND|Public Domain)\b",
    re.IGNORECASE,
)
DENIED = re.compile(
    r"\b(A?GPL|General Public License|SSPL|RSAL|BUSL|Commons Clause|NonCommercial|CC[- ]BY[- ]NC)",
    re.IGNORECASE,
)
LESSER = re.compile(r"\bLGPL|Lesser General Public", re.IGNORECASE)

REJECTED_PACKAGES = frozenset(
    {"ciscoconfparse", "ciscoconfparse2", "pymupdf", "redis", "weasyprint"}
)
LGPL_ACCEPTED = frozenset({"psycopg", "psycopg-binary", "psycopg-c", "paramiko"})

# Packages whose metadata doesn't state a licence clearly, verified by hand at the source.
# Format: normalised name -> (licence, where it was verified). Keep this short and reviewed.
VERIFIED: dict[str, tuple[str, str]] = {}


@dataclass(frozen=True)
class Verdict:
    name: str
    version: str
    licence: str
    ok: bool
    why: str
    runtime: bool


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def licence_text(dist: metadata.Distribution) -> str:
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return str(expr)
    classifiers = [
        c.split("::")[-1].strip()
        for c in md.get_all("Classifier") or []
        if c.startswith("License ::")
    ]
    if classifiers:
        return " / ".join(classifiers)
    raw = (md.get("License") or "").strip()
    # Some packages paste the whole licence text into this field; its first line names it.
    return raw.splitlines()[0][:120] if raw else ""


def runtime_closure(root: str, dists: dict[str, metadata.Distribution]) -> set[str]:
    """Names reachable from ``root``'s requirements, skipping extras and inapplicable markers."""
    seen: set[str] = set()
    stack = [_norm(root)]
    while stack:
        name = stack.pop()
        if name in seen or name not in dists:
            continue
        seen.add(name)
        for raw in dists[name].requires or []:
            req = Requirement(raw)
            if req.marker is not None and not req.marker.evaluate({"extra": ""}):
                continue
            stack.append(_norm(req.name))
    return seen


def judge(name: str, version: str, text: str, *, runtime: bool) -> Verdict:
    key = _norm(name)

    def verdict(ok: bool, why: str, lic: str = text) -> Verdict:
        return Verdict(name, version, lic or "?", ok, why, runtime)

    if key in REJECTED_PACKAGES:
        return verdict(False, "rejected in PLAN §19.5")
    if key in VERIFIED:
        lic, where = VERIFIED[key]
        return verdict(True, f"verified by hand: {where}", lic)
    if LESSER.search(text):
        if key in LGPL_ACCEPTED:
            return verdict(True, "LGPL, accepted unmodified")
        if not runtime:
            return verdict(True, "LGPL, dev-only tool (not distributed)")
        return verdict(False, "LGPL runtime dependency not on the accepted list")
    # Dual licences such as "MIT OR GPL-2.0" are fine: we take the permissive option.
    if ALLOWED.search(text):
        return verdict(True, "permissive")
    if DENIED.search(text):
        return verdict(False, "licence family not accepted")
    return verdict(False, "licence unknown: verify at the source and add to VERIFIED")


def evaluate() -> list[Verdict]:
    dists = {_norm(d.metadata["Name"]): d for d in metadata.distributions()}
    runtime = runtime_closure("kasauti", dists)
    return sorted(
        (
            judge(d.metadata["Name"], d.version, licence_text(d), runtime=key in runtime)
            for key, d in dists.items()
            if key != "kasauti"
        ),
        key=lambda v: (not v.runtime, v.name.lower()),
    )


def _print(verdicts: Iterable[Verdict]) -> None:
    for v in verdicts:
        mark = "ok  " if v.ok else "FAIL"
        scope = "runtime" if v.runtime else "dev"
        print(f"{mark} {scope:<7} {v.name:<28} {v.version:<12} {v.licence[:44]:<44} {v.why}")


def main() -> int:
    verdicts = evaluate()
    _print(verdicts)
    bad = [v for v in verdicts if not v.ok]
    n_runtime = sum(v.runtime for v in verdicts)
    print(
        f"\n{n_runtime} runtime + {len(verdicts) - n_runtime} dev-only distributions; "
        f"{len(bad)} unacceptable"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
