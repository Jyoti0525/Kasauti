"""Matching statements against mapping patterns (PLAN §9, docs/spec/mapping-language.md §2).

Pure functions over tokens. A pattern matches a statement only if every token matches: literal
words case-sensitively, and typed slots by their recogniser. A ``LIST`` slot takes the rest
of the line (at least one item).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from kasauti.mapping.model import Mapping, PatternToken, Slot, Word, parse_pattern
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
    def pattern(self) -> tuple[PatternToken, ...]:
        return parse_pattern(self.mapping.match)

    @cached_property
    def context(self) -> tuple[tuple[PatternToken, ...], ...]:
        return tuple(parse_pattern(c) for c in self.mapping.context)

    @cached_property
    def negation(self) -> tuple[PatternToken, ...] | None:
        neg = self.mapping.negation
        return None if neg in (None, "auto") else parse_pattern(str(neg))

    @cached_property
    def prefix(self) -> tuple[str, ...]:
        return literal_prefix(self.pattern)

    @cached_property
    def specificity(self) -> tuple[int, int]:
        """More literal words wins; then more tokens. Used when several mappings match."""
        words = sum(1 for p in self.pattern if isinstance(p, Word))
        context_words = sum(1 for c in self.context for p in c if isinstance(p, Word))
        return (words + context_words, len(self.pattern))

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
