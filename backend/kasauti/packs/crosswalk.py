"""The crosswalk hub (PLAN §12.4): which framework controls each rule meets on a given device.

NIST SP 800-53 Rev. 5 is the hub: every rule carries its own NIST anchors. Every other framework
maps rules to its controls in its pack's ``crosswalk.yaml``, per vendor where the framework is
(DISA STIG: one benchmark per platform). Each framework control carries the official bridge back
to NIST (a STIG rule's CCIs, NIST OLIR #155 for ISO/IEC 27001), and :func:`bridge_problems`
checks every mapping against it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from kasauti.rules.model import Rule
from kasauti.rules.scoring import NIST, Cited, Coverage, control_sort_key, nist_citations

if TYPE_CHECKING:
    from collections.abc import Callable

    from kasauti.packs.loader import FrameworkPack


def base(control: str) -> str:
    """``AC-17(2)`` -> ``AC-17``: the control an enhancement strengthens."""
    return control.split("(", 1)[0]


def bridged(anchors: Sequence[str], nist: Sequence[str]) -> bool:
    """Do a rule's NIST anchors and a framework control's official NIST bridge share a base
    control? OLIR #155 maps base controls only, and DISA's CCIs name enhancements inconsistently,
    so the comparison is at base-control level."""
    return bool({base(a) for a in anchors} & {base(n) for n in nist})


def covered(fw: FrameworkPack, vendor: str) -> bool:
    """Does the framework say anything about this vendor's devices? A STIG does only for the
    platforms it has a benchmark for."""
    return not fw.catalog.benchmarks or bool(fw.catalog.benchmarks_for(vendor))


def citations(
    framework: str, fw: FrameworkPack | None, rules: Sequence[Rule], vendor: str
) -> dict[str, tuple[Cited, ...]]:
    """Rule id -> the framework's controls it is mapped to on a ``vendor`` device."""
    if framework == NIST:
        return nist_citations(rules)
    out: dict[str, list[Cited]] = {r.id: [] for r in rules}
    if fw is None or fw.crosswalk is None or not covered(fw, vendor):
        return dict.fromkeys(out, ())
    for entry in fw.crosswalk.entries:
        if entry.rule in out and entry.vendor in (None, vendor):
            out[entry.rule] += [Cited(c, Coverage(entry.covers)) for c in entry.controls]
    return {k: tuple(dict.fromkeys(v)) for k, v in out.items()}


def order(framework: str, fw: FrameworkPack | None) -> Callable[[str], object]:
    """Controls in the catalog's own order (NIST by family and number, STIG by benchmark and ID,
    ISO by Annex A number)."""
    if framework == NIST or fw is None:
        return control_sort_key
    position = {c.id: i for i, c in enumerate(fw.catalog.controls)}
    return lambda cid: position.get(cid, len(position))


def bridge_problems(fw: FrameworkPack, rules: Sequence[Rule]) -> list[str]:
    """Every crosswalk mapping checked against the framework's catalog and its NIST bridge."""
    name = fw.catalog.framework
    if fw.crosswalk is None:
        return []
    by_id = {r.id: r for r in rules}
    controls = {c.id: c for c in fw.catalog.controls}
    benchmarks = {b.id: b for b in fw.catalog.benchmarks}
    problems: list[str] = []
    seen: set[tuple[str, str | None, str]] = set()
    for e in fw.crosswalk.entries:
        where = f"{name} crosswalk: {e.rule}" + (f" ({e.vendor})" if e.vendor else "")
        rule = by_id.get(e.rule)
        if rule is None:
            problems.append(f"{where}: unknown rule")
            continue
        if benchmarks and e.vendor is None:
            problems.append(f"{where}: {name} is per vendor, so each mapping names its vendor")
        if not benchmarks and e.vendor is not None:
            problems.append(f"{where}: {name} is the same for every vendor; drop `vendor`")
        needs_note = False
        for cid in e.controls:
            key = (e.rule, e.vendor, cid)
            if key in seen:
                problems.append(f"{where}: {cid} mapped twice")
            seen.add(key)
            control = controls.get(cid)
            if control is None:
                problems.append(f"{where}: {cid} is not in the {name} catalog")
                continue
            bench = benchmarks.get(control.benchmark or "")
            if bench is not None and e.vendor not in bench.vendors:
                problems.append(f"{where}: {cid} is in {bench.title}, not a {e.vendor} benchmark")
            if not bridged(rule.refs.nist_800_53r5, control.nist):
                needs_note = True
                if not e.bridge_note:
                    problems.append(
                        f"{where}: {cid} shares no NIST base control with the rule "
                        f"({', '.join(control.nist) or 'no official bridge'} vs "
                        f"{', '.join(rule.refs.nist_800_53r5)}); explain it in `bridge_note` "
                        "or drop the mapping"
                    )
        if e.bridge_note and not needs_note:
            problems.append(f"{where}: `bridge_note` given but every control is bridged; drop it")
    return problems
