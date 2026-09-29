"""Signals S5 (embeddings) and S6 (few-shot memory): what an unread line most likely means,
judged by how close it sits to the meanings and to lines other vendors already have approved
(PLAN §10.2, §10.5; TODO M3.05, M3.12, M3.14, M3.17).

**The memory is the knowledge base.** Every approved mapping, whether it came with a seed pack
or was taught in the Studio, is an example of a meaning once its effects are recognised as that
meaning's (:func:`label`): ``service timestamps log datetime`` on Cisco and
``info-center timestamp log date`` taught for Huawei both set ``LoggingPolicy.timestamps``. An
approval reloads the knowledge base, so the very next queue is ranked with it: learning in
seconds, with no training step (§10.5 "instant").

**Suggestions, never verdicts.** A score here only orders the Studio's suggestions and explains
them (the nearest approved lines, with their vendor). Nothing reaches a verdict until a person
approves it (§11.4); an unapproved suggestion is REVIEW like any unread line.
"""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from typing import Any

import numpy as np
import numpy.typing as npt

from kasauti.mapping.model import AssertEffect, Mapping, Word, pattern_variants
from kasauti.semantic.embed import Embedder, Vector
from kasauti.studio.meanings import Meaning


def _rarity(embedder: Embedder, lines: Iterable[str]) -> npt.NDArray[np.float32]:
    """Inverse document frequency of every word piece over the approved lines (smoothed, so a
    piece no line has weighs the most, and none weighs nothing)."""
    docs = [set(embedder.pieces(line)) for line in lines]
    df = np.zeros(embedder.vectors.shape[0], dtype=np.float32)
    for d in docs:
        for i in d:
            df[i] += 1
    return (np.log((len(docs) + 1) / (df + 1)) + 1).astype(np.float32)


# --- which meaning an approved mapping is an example of -----------------------------------------

_KINDS = ("assert", "set", "members", "ref")


def _meaning_effects(m: Meaning) -> dict[str, Any]:
    """Attribute -> the constant the meaning asserts (``None``: any value it reads)."""
    out: dict[str, Any] = {}
    for eff in m.effects:
        attr = next(eff[k] for k in _KINDS if k in eff)
        value = eff.get("value") if "assert" in eff else None
        out[attr] = None if isinstance(value, str) and "{" in value else value
    return out


def _mapping_effects(mp: Mapping) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for eff in mp.effects:
        value = None
        if isinstance(eff, AssertEffect) and not isinstance(eff.value, tuple):
            value = None if isinstance(eff.value, str) and "{" in eff.value else eff.value
        out.setdefault(eff.attr, value)
    return out


def label(mp: Mapping, meanings: MappingABC[str, Meaning]) -> str | None:
    """The one meaning ``mp`` is an example of, or None (none fits, or two fit equally).

    A meaning fits when the mapping opens the same kind of entity (or sits in a block, for a
    meaning that lives ``under`` one) and has every effect the meaning has, with the same
    constant where the meaning asserts one. A meaning that only opens an entity (``interface``)
    fits a block line that sets nothing else a meaning names.
    """
    have = _mapping_effects(mp)
    best: list[tuple[int, str]] = []
    for m in meanings.values():
        want = _meaning_effects(m)
        if m.entity is not None:
            if mp.entity is None or mp.entity.type != m.entity.type:
                continue
        elif m.under is not None and (
            not mp.context or not all(a.startswith(m.under + ".") for a in want)
        ):
            continue
        ok = True
        for attr, value in want.items():
            if attr not in have or (value is not None and have[attr] != value):
                ok = False
                break
        if not ok:
            continue
        if not want and mp.context:
            continue  # an entity-only meaning is a block's own line
        best.append((len(want) + (1 if m.entity is not None else 0), m.id))
    if not best:
        return None
    best.sort(reverse=True)
    if len(best) > 1 and best[0][0] == best[1][0]:
        return None
    return best[0][1]


# --- text of a line, as the model reads it -------------------------------------------------------


def keywords(pattern: str) -> str:
    """A match pattern's literal words (values dropped): ``interface <IFNAME:name>`` ->
    ``interface``. The first spelling, when a pattern has alternatives."""
    variants = pattern_variants(pattern)
    if not variants:
        return ""
    return " ".join(t.text for t in variants[0] if isinstance(t, Word))


def line_words(tokens: Iterable[tuple[str, str | None]]) -> str:
    """A queue pattern's literal words (tokens with no value type)."""
    return " ".join(w for w, cls in tokens if cls is None)


def block_words(block: str | None) -> str:
    return " ".join(w for w in (block or "").split() if not (w.startswith("<") and w.endswith(">")))


@dataclass(frozen=True, slots=True)
class Example:
    vendor: str
    meaning: str
    line: str
    block: str
    mapping: str
    vline: Vector
    vblock: Vector | None


@dataclass(frozen=True, slots=True)
class Near:
    """Why a meaning ranks where it does."""

    meaning: str
    score: float
    described: float
    """Closeness to the meaning's own description."""
    examples: tuple[Example, ...]
    """The nearest approved lines of that meaning, best first."""


BLOCK_WEIGHT = 0.25
"""How much agreeing blocks add: ``idle-timeout`` inside ``user-interface vty`` is closer to
Cisco's ``exec-timeout`` inside ``line vty`` than to the same word at the top level."""
DESCRIBED_WEIGHT = 0.8
"""A description is prose, a line is CLI jargon: likeness to an approved line counts more."""


class SemanticIndex:
    """Meanings and their approved examples, embedded once per knowledge base."""

    def __init__(
        self,
        embedder: Embedder,
        meanings: MappingABC[str, Meaning],
        mappings: Iterable[Mapping],
    ) -> None:
        self.embedder = embedder
        self.meanings = dict(meanings)
        mappings = list(mappings)
        self.weights = _rarity(embedder, (keywords(mp.match) for mp in mappings))
        self._cache: dict[str, Vector] = {}
        embed = self.embed
        self.described: dict[str, Vector] = {
            m.id: embed(f"{m.label}. {m.explain} {' '.join(m.words)}")
            for m in self.meanings.values()
        }
        examples: list[Example] = []
        for mp in mappings:
            meaning = label(mp, self.meanings)
            if meaning is None:
                continue
            line = keywords(mp.match)
            if not line:
                continue
            block = keywords(mp.context[-1]) if mp.context else ""
            examples.append(
                Example(
                    mp.vendor,
                    meaning,
                    line,
                    block,
                    mp.id,
                    embed(line),
                    embed(block) if block else None,
                )
            )
        self.examples = tuple(examples)
        self._lines = (
            np.stack([e.vline for e in examples])
            if examples
            else np.zeros((0, embedder.dim), dtype=np.float32)
        )

    def embed(self, text: str) -> Vector:
        """The text's vector, each word piece weighted by how rare it is among configuration
        lines: ``ip`` or ``set`` open half of all lines and say little about what one means."""
        hit = self._cache.get(text)
        if hit is None:
            hit = self.embedder.pool(self.embedder.pieces(text), self.weights)
            self._cache[text] = hit
        return hit

    def rank(
        self,
        line: str,
        block: str = "",
        *,
        exclude_vendor: str | None = None,
        near: int = 3,
    ) -> list[Near]:
        """Every meaning, most likely first. ``exclude_vendor`` leaves that vendor's own
        examples out (the leave-one-vendor-out evaluation asks: could it have known?)."""
        vline = self.embed(line)
        vblock = self.embed(block) if block else None
        sims = self._lines @ vline if len(self.examples) else np.zeros(0, dtype=np.float32)
        per: dict[str, list[tuple[float, Example]]] = {m: [] for m in self.meanings}
        for i, ex in enumerate(self.examples):
            if ex.vendor == exclude_vendor:
                continue
            s = float(sims[i])
            if vblock is not None and ex.vblock is not None:
                s += BLOCK_WEIGHT * float(ex.vblock @ vblock)
            elif (vblock is None) != (ex.vblock is None):
                s -= BLOCK_WEIGHT / 2  # one sits in a block, the other doesn't
            per[ex.meaning].append((s, ex))
        out: list[Near] = []
        for mid in self.meanings:
            described = DESCRIBED_WEIGHT * float(self.described[mid] @ vline)
            found = sorted(per[mid], key=lambda t: -t[0])
            best = found[0][0] if found else float("-inf")
            out.append(
                Near(
                    mid,
                    round(max(best, described), 4),
                    round(described, 4),
                    tuple(ex for _, ex in found[:near]),
                )
            )
        return sorted(out, key=lambda n: (-n.score, n.meaning))
