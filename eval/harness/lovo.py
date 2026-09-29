"""Leave-one-vendor-out evaluation of the Studio's suggestions (PLAN §21.2, §21.3; TODO M3.11,
M3.30; the PS hint "NLP to identify keywords the system has not been pre-trained on").

**The question.** A vendor Kasauti has never seen sends a line. Before anyone teaches it
anything about that vendor, does the Studio suggest the right meaning?

**The set.** Every approved seed mapping that is an example of a Studio meaning
(:func:`kasauti.semantic.index.label`): its words are the line, its block is the block. For each
vendor in turn, that vendor's own examples are hidden from the few-shot memory, and each of its
lines is ranked against what the *other* vendors taught.

**The methods.**
- ``lexicon``: S1 + S4 as the Studio ranked before S5 (shared words, block kind). Its word lists
  were written by people who had read every seed vendor, so its score here is optimistic.
- ``semantic``: S5 + S6 alone (the embedding model and the other vendors' approved lines).
- ``fused``: the Studio's ranking now, both together.

Recall@k: the right meaning is among the first k suggestions. No suggestion is a miss.
"""

from __future__ import annotations

import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

from kasauti.audit import load_kb
from kasauti.ingest.read import read_file
from kasauti.mapping.model import Mapping, Slot, pattern_variants
from kasauti.semantic.embed import shared
from kasauti.semantic.index import SemanticIndex, block_words, keywords, label, line_words
from kasauti.studio.meanings import Meaning, load_meanings
from kasauti.studio.workspace import Studio, suggest

PACKS = Path(__file__).resolve().parents[2] / "packs"
METHODS = ("lexicon", "semantic", "fused")


@dataclass(frozen=True, slots=True)
class Case:
    vendor: str
    mapping: str
    meaning: str
    tokens: tuple[tuple[str, str | None], ...]
    block: str | None


def _tokens(pattern: str) -> tuple[tuple[str, str | None], ...]:
    variants = pattern_variants(pattern)
    if not variants:
        return ()
    return tuple(
        (f"<{t.type}>", f"<{t.type}>") if isinstance(t, Slot) else (t.text, None)
        for t in variants[0]
    )


def cases(mappings: list[Mapping], *, negatives: bool = False) -> list[Case]:
    """Lines with a meaning; with ``negatives``, the lines no meaning fits instead (for those
    the right answer is "no suggestion")."""
    meanings = load_meanings()
    out = []
    for mp in mappings:
        m = label(mp, meanings)
        if (m is None) != negatives or not keywords(mp.match):
            continue
        block = " ".join(c or t for t, c in _tokens(mp.context[-1])) if mp.context else None
        out.append(Case(mp.vendor, mp.id, m or "", _tokens(mp.match), block))
    return out


@dataclass(frozen=True, slots=True)
class Score:
    n: int
    at1: int
    at3: int
    offered: int
    """Lines with at least one suggestion (the rest: "no suggestion", never a guess)."""

    @property
    def r1(self) -> float:
        return self.at1 / self.n if self.n else 0.0

    @property
    def r3(self) -> float:
        return self.at3 / self.n if self.n else 0.0

    @property
    def precision(self) -> float:
        """Right first time, among the lines it made a suggestion for."""
        return self.at1 / self.offered if self.offered else 0.0

    @property
    def abstained(self) -> float:
        return 1 - self.offered / self.n if self.n else 0.0


@dataclass(frozen=True, slots=True)
class Results:
    scores: dict[str, dict[str, Score]]
    """method -> vendor (and ``all``) -> Score, on lines that have a meaning."""
    false_offers: dict[str, tuple[int, int]]
    """method -> (lines no meaning fits, of which it suggested something anyway)."""


def _ranked(
    case: Case, index: SemanticIndex, meanings: dict[str, Meaning], negation: tuple[str, ...]
) -> dict[str, list[str]]:
    return {
        "lexicon": [
            s.meaning for s in suggest(case.tokens, case.block, meanings, negation=negation)
        ],
        "semantic": [
            n.meaning
            for n in index.rank(
                line_words(case.tokens), block_words(case.block), exclude_vendor=case.vendor
            )[:3]
        ],
        "fused": [
            s.meaning
            for s in suggest(
                case.tokens,
                case.block,
                meanings,
                index=index,
                exclude_vendor=case.vendor,
                negation=negation,
            )
        ],
    }


def run() -> Results:
    kb = load_kb(PACKS)
    mappings = [m for p in kb.vendor_packs.values() for m in p.mappings]
    embedder = shared()
    if embedder is None:
        raise SystemExit("the embedding model isn't installed: run `kasauti models fetch`")
    meanings = load_meanings()
    index = SemanticIndex(embedder, meanings, mappings)
    negation = {v: p.manifest.negation_words for v, p in kb.vendor_packs.items()}
    tally: dict[str, dict[str, list[int]]] = {m: defaultdict(lambda: [0, 0, 0, 0]) for m in METHODS}
    for case in cases(mappings):
        for method, got in _ranked(case, index, meanings, negation[case.vendor]).items():
            for key in (case.vendor, "all"):
                t = tally[method][key]
                t[0] += 1
                t[1] += got[:1] == [case.meaning]
                t[2] += case.meaning in got[:3]
                t[3] += bool(got)
    false: dict[str, list[int]] = {m: [0, 0] for m in METHODS if m != "semantic"}
    for case in cases(mappings, negatives=True):
        for method, got in _ranked(case, index, meanings, negation[case.vendor]).items():
            if method in false:
                false[method][0] += 1
                false[method][1] += bool(got)
    return Results(
        {method: {k: Score(*v) for k, v in sorted(by.items())} for method, by in tally.items()},
        {m: (n, offered) for m, (n, offered) in false.items()},
    )


def report(results: Results) -> str:
    scores = results.scores
    vendors = [k for k in scores["fused"] if k != "all"] + ["all"]
    lines = [
        "| Vendor held out | Lines | " + " | ".join(f"{m} R@1 / R@3" for m in METHODS) + " |",
        "|---|---:|" + "---:|" * len(METHODS),
    ]
    for v in vendors:
        n = scores["fused"][v].n
        cells = [f"{scores[m][v].r1:.0%} / {scores[m][v].r3:.0%}" for m in METHODS]
        name = "**all**" if v == "all" else v
        lines.append(f"| {name} | {n} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "| Method | Right first, when it suggests | No suggestion | "
        "Suggests something for a line no meaning fits |",
        "|---|---:|---:|---:|",
    ]
    for m in ("lexicon", "fused"):
        a = scores[m]["all"]
        n, offered = results.false_offers[m]
        share = f"{offered / n:.0%} ({offered} of {n})"
        lines.append(f"| {m} | {a.precision:.0%} | {a.abstained:.0%} | {share} |")
    return "\n".join(lines)


# --- Huawei: the held-out vendor --------------------------------------------------------------

HUAWEI = PACKS.parent / "datasets" / "authored" / "huawei_vrp"
HUAWEI_TRUTH = Path(__file__).with_name("huawei_truth.yaml")


@dataclass(frozen=True, slots=True)
class HeldOut:
    method: str
    with_meaning: int
    right_first: int
    offered: int
    without_meaning: int
    false_offers: int
    unlabelled: tuple[str, ...]


def huawei() -> list[HeldOut]:
    """The Studio's own queue for the two Huawei samples (a vendor in no seed pack), scored
    against ``huawei_truth.yaml``: with the model (the Studio as shipped) and without it."""
    kb = load_kb(PACKS)
    truth = {
        (t["pattern"], t["block"]): t["meaning"]
        for t in yaml.safe_load(HUAWEI_TRUTH.read_text(encoding="utf-8"))["lines"]
    }
    with tempfile.TemporaryDirectory() as tmp:
        studio = Studio(Path(tmp) / "learned", Path(tmp) / "record.json")
        for name in ("weak.cfg", "hardened.cfg"):
            studio.add(read_file(HUAWEI / name), kb, "huawei_vrp")
        queue = studio.queue(kb, "huawei_vrp")
    meanings = load_meanings()
    negation = kb.vendor_packs["huawei_vrp"].manifest.negation_words
    out = []
    for method in ("lexicon", "fused"):
        t = [0, 0, 0, 0, 0]
        unlabelled = []
        for p in queue:
            key = (p.pattern, p.block or "")
            if key not in truth:
                unlabelled.append(" / ".join(k for k in key if k))
                continue
            got = (
                [s.meaning for s in p.suggestions]
                if method == "fused"
                else [s.meaning for s in suggest(p.tokens, p.block, meanings, negation=negation)]
            )
            want = truth[key]
            if want is None:
                t[3] += 1
                t[4] += bool(got)
            else:
                t[0] += 1
                t[1] += got[:1] == [want]
                t[2] += bool(got)
        out.append(HeldOut(method, t[0], t[1], t[2], t[3], t[4], tuple(unlabelled)))
    return out


def huawei_report(rows: list[HeldOut]) -> str:
    lines = [
        "| Method | Lines with a meaning: right first | Right when it suggests | "
        "Lines no meaning fits: suggested anyway |",
        "|---|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r.method} | {r.right_first / r.with_meaning:.0%} "
            f"({r.right_first} of {r.with_meaning}) | "
            f"{r.right_first / r.offered if r.offered else 0:.0%} | "
            f"{r.false_offers / r.without_meaning:.0%} "
            f"({r.false_offers} of {r.without_meaning}) |"
        )
    return "\n".join(lines)


REPORT = Path(__file__).resolve().parents[1] / "reports" / "lovo.md"


def markdown(results: Results, huawei_rows: list[HeldOut]) -> str:
    """``eval/reports/lovo.md``, as committed: a test checks it matches a fresh run."""
    return LOVO_REPORT.format(
        vendors=report(results),
        huawei=huawei_report(huawei_rows),
        left_out="\n".join(f"- `{u}`" for u in huawei_rows[0].unlabelled) or "- none",
    )


LOVO_REPORT = """# Training Studio suggestions on vendors it has never seen

Generated by `uv run python -m harness lovo` (eval/harness/lovo.py); do not edit by hand.

The Studio suggests what an unread line means. These tables measure those suggestions
before anyone has taught Kasauti anything about the vendor in question.

- **lexicon**: signals S1 + S4 (shared words, block kind), what the Studio did before S5.
- **semantic**: S5 + S6 alone: the embedding model (potion-base-8M) and the lines other
  vendors already have approved.
- **fused**: the Studio as shipped: all of them, with "no suggestion" when unsure.

## Leave one vendor out

Each seed vendor in turn is hidden: its approved lines leave the few-shot memory, and each
line is ranked using only what the other vendors taught. R@k: the right meaning is among the
first k suggestions ("no suggestion" is a miss). The lexicon's word lists were written by
people who had read every seed vendor, so its column is optimistic. The fused weights and
thresholds were chosen on this set (a small grid), so Huawei below is the independent check.

{vendors}

The last column counts the seed lines no Studio meaning fits (AAA, ACL bodies, addresses):
for them the right answer is "no suggestion".

## Huawei VRP, a vendor in no seed pack

The Studio's own queue for `datasets/authored/huawei_vrp/{{weak,hardened}}.cfg`, against
meanings written by hand in `eval/harness/huawei_truth.yaml`. The lexicon already lists
Huawei's words (`info-center`, `stelnet`, `snmp-agent`), so it is strong here by design.

{huawei}

Left out as open to two readings:

{left_out}
"""
