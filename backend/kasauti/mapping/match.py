"""Matching statements against mapping patterns (PLAN §9, docs/spec/mapping-language.md §2).

Pure functions over tokens. A pattern matches a statement only if every token matches: literal
words case-sensitively, and typed slots by their recogniser. A ``LIST`` slot takes the rest
of the line (at least one item).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property

from kasauti.mapping.model import (
    Mapping,
    PatternToken,
    Slot,
    Word,
    parse_pattern,
    pattern_variants,
)
from kasauti.shape.tokens import tokenize, unquote
from kasauti.shape.values import is_ifname, is_int, is_ip

SlotValue = int | str | tuple[str, ...]
Captures = dict[str, SlotValue]
"""Named slot -> typed value. ``_raw:<name>`` holds the slot's text before typing (used for
value maps, whose keys are the vendor's words)."""


def match_tokens(pattern: tuple[PatternToken, ...], tokens: tuple[str, ...]) -> Captures | None:
    caps: Captures = {}
    for i, part in enumerate(pattern):
        if isinstance(part, Slot) and part.type == "LIST":
            rest = tokens[i:]
            if not rest:
                return None
            if part.name:
                caps[part.name] = tuple(unquote(t) for t in rest)
            return caps
        if i >= len(tokens):
            return None
        token = tokens[i]
        if isinstance(part, Word):
            if token != part.text:
                return None
            continue
        value = _slot_value(part, token)
        if value is None:
            return None
        if part.name:
            caps[part.name] = value
            caps[f"_raw:{part.name}"] = unquote(token)
    return caps if len(tokens) == len(pattern) else None


def _slot_value(slot: Slot, token: str) -> SlotValue | None:
    text = unquote(token)
    match slot.type:
        case "INT":
            return int(text) if is_int(text) else None
        case "IP":
            return text if is_ip(text) else None
        case "IFNAME":
            return text if is_ifname(text) else None
        case "STR":
            return text
    return None  # pragma: no cover - LIST handled by the caller


def literal_prefix(pattern: tuple[PatternToken, ...]) -> tuple[str, ...]:
    """The keywords before the first slot, e.g. ``("exec-timeout",)``."""
    out: list[str] = []
    for part in pattern:
        if not isinstance(part, Word):
            break
        out.append(part.text)
    return tuple(out)


@dataclass(frozen=True)
class Compiled:
    """A mapping with its patterns parsed once."""

    mapping: Mapping
    order: int

    @cached_property
    def variants(self) -> tuple[tuple[PatternToken, ...], ...]:
        """The concrete forms of ``match`` (optional groups expanded), longest first."""
        return pattern_variants(self.mapping.match)

    @cached_property
    def pattern(self) -> tuple[PatternToken, ...]:
        """The longest form: the one shown to people."""
        return self.variants[0]

    @cached_property
    def context(self) -> tuple[tuple[PatternToken, ...], ...]:
        return tuple(parse_pattern(c) for c in self.mapping.context)

    @cached_property
    def negation(self) -> tuple[tuple[PatternToken, ...], ...] | None:
        neg = self.mapping.negation
        return None if neg in (None, "auto") else pattern_variants(str(neg))

    @cached_property
    def prefix(self) -> tuple[str, ...]:
        """Keywords every form starts with (the shortest literal prefix across forms)."""
        return min((literal_prefix(v) for v in self.variants), key=len)

    @cached_property
    def _context_words(self) -> int:
        return sum(1 for c in self.context for p in c if isinstance(p, Word))

    def specificity(self, variant: tuple[PatternToken, ...]) -> tuple[int, int]:
        """More literal words wins; then more tokens. Used when several mappings match."""
        words = sum(1 for p in variant if isinstance(p, Word))
        return (words + self._context_words, len(variant))

    def match(self, tokens: tuple[str, ...]) -> tuple[Captures, tuple[int, int]] | None:
        """Captures and specificity of the first (longest) form that matches."""
        return _first(self.variants, tokens, self.specificity)

    def match_negation(self, tokens: tuple[str, ...]) -> tuple[Captures, tuple[int, int]] | None:
        return _first(self.negation or (), tokens, self.specificity)

    def partial(self, tokens: tuple[str, ...]) -> tuple[int, Captures]:
        """The best partial match over all forms (for near-miss detection)."""
        return max((partial_match(v, tokens) for v in self.variants), key=lambda r: r[0])

    def match_context(self, path: tuple[tuple[str, ...], ...]) -> Captures | None:
        """Suffix match of the context against the statement's (tokenised) block path.
        An empty context means top level only."""
        if not self.context:
            return {} if not path else None
        if len(self.context) > len(path):
            return None
        caps: Captures = {}
        for pattern, block in zip(self.context, path[-len(self.context) :], strict=True):
            got = match_tokens(pattern, block)
            if got is None:
                return None
            caps.update(got)
        return caps


def _first(
    variants: tuple[tuple[PatternToken, ...], ...],
    tokens: tuple[str, ...],
    specificity: Callable[[tuple[PatternToken, ...]], tuple[int, int]],
) -> tuple[Captures, tuple[int, int]] | None:
    for variant in variants:
        caps = match_tokens(variant, tokens)
        if caps is not None:
            return caps, specificity(variant)
    return None


def partial_match(
    pattern: tuple[PatternToken, ...], tokens: tuple[str, ...]
) -> tuple[int, Captures]:
    """How many leading tokens match, and the slots captured up to the first mismatch."""
    caps: Captures = {}
    for i, part in enumerate(pattern):
        if i >= len(tokens):
            return i, caps
        if isinstance(part, Slot) and part.type == "LIST":
            if part.name:
                caps[part.name] = tuple(unquote(t) for t in tokens[i:])
            return len(tokens), caps
        if isinstance(part, Word):
            if tokens[i] != part.text:
                return i, caps
            continue
        value = _slot_value(part, tokens[i])
        if value is None:
            return i, caps
        if part.name:
            caps[part.name] = value
            caps[f"_raw:{part.name}"] = unquote(tokens[i])
    return len(pattern), caps


def tokenize_path(path: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return tuple(tokenize(block) for block in path)
