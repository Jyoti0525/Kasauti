"""Junos configuration files in any form the CLI writes, rebuilt into the brace tree (M2.28).

Junos ``show configuration | display set`` prints each statement on a line of its own: the full
path from the top of the hierarchy, as a ``set`` command. Files carry more of the CLI than that
(commands at an edit level, ``insert``, ``rename``, a terminal capture with its ``[edit …]``
banners): :mod:`kasauti.mapping.commands` replays them into the statements they leave, each a
path of words from the top. The brace form of the same configuration nests those words in
blocks, and a pack's mappings are written for blocks (``context: [system, services]``,
``match: telnet``). A line doesn't say where its blocks end: ``set system ntp server 10.0.0.1
key 1`` is one statement in ``system ntp``, while ``set system syslog host 10.0.0.2 any notice``
is a statement in the block ``host 10.0.0.2``. Only the vendor's schema knows, and the pack
already records what it needs of it: its mappings' contexts are blocks, their patterns
statements. So each statement is split where the mappings expect:

1. If the rest of the line is a statement a mapping reads at this point of the path, it is
   that statement (``route 0.0.0.0/0 next-hop 198.51.100.1`` in ``static``, the way Junos
   prints it in braces).
2. Otherwise the next words are a block, if a mapping reads them here with more words after
   them (``http`` in ``web-management``, a block in braces when it has settings, and a
   statement mappings read there too), or if a context names them. A block that continues a
   context the path already follows comes first (``filter`` in an interface's ``family
   inet``), then one a context starts with (``filter PROTECT-RE`` in ``firewall family inet``).
3. A word no context names is a block of its own if a context starts later in the line
   (``routing-options`` before ``static``). Otherwise the rest of the line is one statement,
   read by no mapping, as it would be in braces.

Every block is also a statement, given once, at the first line that opens it, as the brace
parser gives it. Statements that came from braces keep the blocks the braces gave them.

A set of values is one statement per value, in either form: "To specify a set, include the
values in brackets" (``application [ junos-ssh junos-telnet ]``), and a ``set`` command adds one
value at the end of the list. Only the statements the pack reads as an ordered list
(``set_form.leaf_lists``) are given back as one ``[ … ]`` list, their values in order.

A file whose paths start below the top of the hierarchy (``show | display set relative``, or
braces shown from ``[edit system]``) is read at the level its banner names. Without a banner,
the level is the one the pack's mappings allow for every first word, if exactly one does. Either
way the file holds only part of a configuration, and the tree says so (``ConfigTree.partial``).
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass

from kasauti.mapping.commands import (
    BANNER,
    CHANGE,
    MOVE,
    PROMPT,
    Entry,
    Replay,
    Replayed,
    Words,
    brace_view,
    normal_words,
)
from kasauti.mapping.match import Compiled, match_tokens
from kasauti.mapping.model import Mapping, PatternToken, Slot, Word, parse_pattern
from kasauti.packs.loader import VendorPack
from kasauti.shape import brace
from kasauti.shape.base import ParseError, RawStatement, check_depth
from kasauti.shape.lines import logical_lines, parse_flat
from kasauti.shape.model import ConfigTree, ShapeFamily
from kasauti.shape.parse import build_tree, parse_text
from kasauti.shape.tokens import split_lines, tokenize

Block = tuple[PatternToken, ...]

TOP_LEVEL = frozenset(
    {
        # "Table 2: Configuration Mode Top-Level Statements", CLI User Guide, CLI Configuration
        # Mode Overview (juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/
        # cli-configuration.html).
        "access",
        "accounting-options",
        "chassis",
        "class-of-service",
        "firewall",
        "forwarding-options",
        "groups",
        "interfaces",
        "policy-options",
        "protocols",
        "routing-instances",
        "routing-options",
        "security",
        "snmp",
        "system",
        # The `set ?` completions at [edit] in "How to Add Configuration Statements and
        # Identifiers" (…/cli/topics/topic-map/modifying-configuration.html).
        "apply-groups",
        # The export's first statement (docs/reviews/juniper_junos.md, fingerprint).
        "version",
    }
)
"""Statements Juniper documents at the top of the hierarchy. Juniper's table isn't every one,
so a word missing from it says nothing; a word in it means the file's paths start at the top."""
_END = "\x00"
"""A word no configuration holds: after a path, it leaves every word of the path in a block."""
_START_VERBS = frozenset({*CHANGE, *MOVE, "protect", "unprotect", "annotate"})


def parse_config(
    text: str, pack: VendorPack, *, source_file: str, sha256: str | None = None
) -> ConfigTree:
    """A configuration parsed for ``pack``: in the pack's shape family, or, when the pack takes
    ``set`` commands, replayed and rebuilt into that family's tree (module docstring). A file
    that can't be read so is read line by line with the reason, as when a parser rejects one."""
    family = pack.manifest.shape_family
    form = pack.manifest.set_form
    if form is None:
        return parse_text(text, source_file=source_file, family=family, sha256=sha256)
    reader = SetFormReader(pack.mappings, form.leaf_lists)
    commands = is_set_form(text)
    try:
        replayed = reader.replay(text) if commands else reader.from_braces(text)
        raws = reader.read(replayed.entries)
    except ParseError as err:
        name = ShapeFamily.SET_PATH.value if commands else family.value
        return build_tree(
            parse_flat(text),
            ShapeFamily.FLAT,
            text=text,
            source_file=source_file,
            sha256=sha256,
            warnings=[f"not valid {name} syntax ({err}); parsed line by line instead"],
        )
    rebuilt = any(e.path is None for e in replayed.entries)
    return build_tree(
        raws,
        family,
        text=text,
        source_file=source_file,
        sha256=sha256,
        rebuilt_from=ShapeFamily.SET_PATH if rebuilt else None,
        partial=replayed.partial,
        order=_order(raws) if replayed.reordered else None,
    )


def is_set_form(text: str) -> bool:
    """The file is CLI commands or a terminal capture, not braces: its first line that isn't
    blank or a comment is a configuration-mode command, an ``[edit …]`` banner or a prompt."""
    for _, _, line in logical_lines(text):
        if line and not line.startswith("#"):
            return _framing(line) or line.split(None, 1)[0] in _START_VERBS
    return False


def absolute_view(text: str, pack: VendorPack) -> str | None:
    """``text`` with each line that is relative to an edit level written from the top, line
    for line, or None if no line is relative. The fingerprint reads it, so a part of a
    configuration shown from ``[edit system]`` is recognised as what it is."""
    form = pack.manifest.set_form
    if form is None:
        return None
    reader = SetFormReader(pack.mappings, form.leaf_lists)
    try:
        view = reader.view(text)
    except ParseError:
        return None
    if not view:
        return None
    lines = split_lines(text)
    for number, line in view.items():
        lines[number - 1] = line
    return "\n".join(lines)


def _framing(line: str) -> bool:
    return bool(BANNER.fullmatch(line) or PROMPT.fullmatch(line))


def _order(raws: Sequence[RawStatement]) -> tuple[int, ...]:
    """Source lines in configuration order, each where its first statement is."""
    return tuple(dict.fromkeys(r.line_start for r in raws))


@dataclass(slots=True)
class _Out:
    path: tuple[str, ...]
    words: tuple[str, ...]
    start: int
    end: int
    block: bool
    text: str | None = None
    """The statement as braces wrote it, if it came from braces."""
    listed: bool = False
    values: list[str] | None = None
    """An ordered list's values, joined back into one statement."""

    def raw(self) -> RawStatement:
        if self.values is not None:
            text = f"{self.words[0]} [ {' '.join(self.values)} ]"
        elif self.text is not None:
            text = self.text
        else:
            text = " ".join(self.words)
        return RawStatement(self.path, text, self.start, self.end)


_PATHS_KEPT = 10_000
"""How many paths :meth:`SetFormReader._at` remembers before it starts again."""


@dataclass(frozen=True, slots=True)
class _Here:
    by_word: dict[str, list[Compiled]]
    """Mappings whose context the path ends in, by the first word of their pattern."""
    slot_first: tuple[Compiled, ...]
    """Those whose pattern can start with any word."""
    blocks: tuple[Block, ...]
    """What can open the next block, best first."""


class SetFormReader:
    """Splits statements where ``mappings`` expect blocks (see the module docstring)."""

    def __init__(self, mappings: Sequence[Mapping], leaf_lists: Collection[str] = ()) -> None:
        self._leaf_lists = frozenset(leaf_lists)
        self._compiled = tuple(Compiled(m, i) for i, m in enumerate(mappings))
        self._here: dict[tuple[frozenset[int], ...], _Here] = {}
        contexts = {tuple(parse_pattern(p) for p in m.context) for m in mappings if m.context}
        # Every block a context names, numbered: what follows a path depends only on which of
        # them each of its blocks matches, so `unit 5` and `unit 6` share one answer.
        self._patterns = tuple(sorted({b for c in contexts for b in c}, key=repr))
        self._by_first: dict[str, list[int]] = {}
        self._any_first: list[int] = []
        for n, block in enumerate(self._patterns):
            word = _first_word(block)
            if word is None:
                self._any_first.append(n)
            else:
                self._by_first.setdefault(word, []).append(n)
        self._classes: dict[tuple[str, ...], frozenset[int]] = {}
        # Sorted, so the result never depends on set order; a context with a LIST slot has no
        # fixed length, so it can't mark where a block ends.
        self._contexts = tuple(sorted((c for c in contexts if all(_fixed(b) for b in c)), key=repr))
        self._starts = tuple(sorted({c[0] for c in self._contexts if _literal(c[0])}, key=repr))
        self._start_words = frozenset(str(_first_word(b)) for b in self._starts)
        self._below = self._levels_below()

    # --- files -----------------------------------------------------------------------------

    def replay(self, text: str) -> Replayed:
        """A file of commands or a terminal capture, replayed (:mod:`commands`)."""
        return self._replay(text).run(text)

    def view(self, text: str) -> dict[int, str]:
        """Line -> the line written from the top, for lines relative to an edit level."""
        if is_set_form(text):
            words = _first_words(text)
            if words is not None and not self.infer_level(words)[0]:
                return {}  # commands from the top, no banner: every line reads as it is
            replay = self._replay(text)
            replay.run(text)
            return replay.view
        lines = [line for line in logical_lines(text) if line[2] and not line[2].startswith("#")]
        if not lines or not lines[0][2].endswith((";", "{")):
            return {}  # not braces: nothing to rebuild
        if lines[0][2].split(None, 1)[0] in TOP_LEVEL:
            return {}  # braces from the top
        raws = list(brace.parse(text))
        level, _ = self.infer_level({tokenize(r.text)[0] for r in raws if not r.path})
        return brace_view(lines, self.levels(level)) if level else {}

    def from_braces(self, text: str) -> Replayed:
        """A configuration in braces: as the braces give it, at the level it was shown from
        if its statements start below the top."""
        raws = list(brace.parse(text))
        level, why = self.infer_level({tokenize(r.text)[0] for r in raws if not r.path})
        replay = Replay(self.levels)
        replay.add_brace(raws, level)
        partial = [*replay.partial]
        if level:
            partial.append(f"its statements are from [edit {' '.join(level)}], not the top")
        if why:
            partial.append(why)
        return Replayed(tuple(replay.entries), tuple(dict.fromkeys(partial)), False, level)

    def _replay(self, text: str) -> Replay:
        level: Words = ()
        words = _first_words(text)
        if words is not None:
            level, why = self.infer_level(words)
            if why:
                replay = Replay(self.levels)
                replay.partial.append(why)
                return replay
        return Replay(self.levels, level)

    # --- levels ----------------------------------------------------------------------------

    def levels(self, words: Words) -> list[Words]:
        """The blocks a path of words passes through, every word in one: ``interfaces ge-0/0/0
        unit 0`` -> ``interfaces``, ``ge-0/0/0``, ``unit 0``."""
        if not words:
            return []
        blocks, rest = self.split((*words, _END), 0)
        return [*blocks, *((w,) for w in rest[:-1])]

    def infer_level(self, first: Collection[str]) -> tuple[Words, str | None]:
        """The edit level statements starting with ``first`` words are relative to: () when
        one of them starts at the top, or when nothing tells. The second value says why the
        file is only part of a configuration when the level can't be told."""
        if not first or any(w in TOP_LEVEL for w in first):
            return (), None
        known = [w for w in first if any(w in nxt for nxt in self._below.values())]
        if not known:
            return (), None
        fits = sorted(lvl for lvl, nxt in self._below.items() if all(w in nxt for w in known))
        if len(fits) == 1:
            return fits[0], None
        where = " or ".join(f"[edit {' '.join(f)}]" for f in fits) if fits else "a level"
        return (), (
            f"its statements start below the top of the hierarchy, at {where}, and the file "
            "doesn't say which; export it with show configuration | display set, or keep the "
            "[edit …] line the CLI prints above the prompt"
        )

    def _levels_below(self) -> dict[Words, frozenset[str]]:
        """Each level a pack's mappings name from the top, all in words (``system services``),
        with the first words of what the mappings read in it."""
        out: dict[Words, set[str]] = {}
        for c in self._compiled:
            ctx = c.context
            if not ctx or not _literal(ctx[0]) or _first_word(ctx[0]) not in TOP_LEVEL:
                continue
            for depth in range(1, len(ctx) + 1):
                if not all(isinstance(p, Word) for p in ctx[depth - 1]):
                    break
                level = tuple(p.text for b in ctx[:depth] for p in b if isinstance(p, Word))
                nxt = out.setdefault(level, set())
                if depth < len(ctx):
                    if (word := _first_word(ctx[depth])) is not None:
                        nxt.add(word)
                else:
                    nxt.update(v[0].text for v in c.variants if v and isinstance(v[0], Word))
        return {k: frozenset(v) for k, v in out.items()}

    # --- statements ------------------------------------------------------------------------

    def read(self, entries: Iterable[Entry]) -> list[RawStatement]:
        opened: set[tuple[str, ...]] = set()
        out: list[_Out] = []
        for e in entries:
            if e.path is not None and e.text is not None:
                opened.update(e.path[: k + 1] for k in range(len(e.path)))
                opened.add((*e.path, e.text))
                out.append(_Out(e.path, tokenize(e.text), e.start, e.end, False, e.text, e.listed))
                continue
            blocks, leaf = self.split(e.words, e.start)
            headers = tuple(" ".join(b) for b in blocks)
            for k in range(len(headers)):
                if headers[: k + 1] not in opened:
                    opened.add(headers[: k + 1])
                    out.append(_Out(headers[:k], blocks[k], e.start, e.end, block=True))
            out.append(_Out(headers, leaf, e.start, e.end, block=False, listed=e.listed))
        # A line that names a block other lines open (``set system services ssh`` beside
        # ``set system services ssh root-login deny``) is that block, already given; a line
        # given twice is one statement.
        seen: set[tuple[str, ...]] = set()
        kept: list[_Out] = []
        for o in out:
            key = (*o.path, " ".join(o.words))
            if key in seen or (not o.block and o.text is None and key in opened):
                continue
            seen.add(key)
            kept.append(o)
        return [o.raw() for o in self._join_lists(kept)]

    def split(
        self, words: tuple[str, ...], line: int
    ) -> tuple[list[tuple[str, ...]], tuple[str, ...]]:
        """The blocks ``words`` passes through, and the statement at the end."""
        blocks: list[tuple[str, ...]] = []
        i = 0
        while i < len(words) - 1:
            if self._is_statement(blocks, words[i:]):
                break
            size = self._block(blocks, words, i)
            if size is None:
                break
            check_depth(len(blocks) + 1, line)
            blocks.append(words[i : i + size])
            i += size
        return blocks, words[i:]

    def _is_statement(self, blocks: list[tuple[str, ...]], rest: tuple[str, ...]) -> bool:
        here = self._at(tuple(blocks))
        return any(
            c.match(rest) is not None for c in (*here.by_word.get(rest[0], ()), *here.slot_first)
        )

    def _block(self, blocks: list[tuple[str, ...]], words: tuple[str, ...], i: int) -> int | None:
        """How many words from ``i`` make the next block, or None if they make none."""
        for block in self._at(tuple(blocks)).blocks:
            if size := _fits(block, words, i):
                return size
        later = any(
            words[k] in self._start_words and any(_fits(s, words, k) for s in self._starts)
            for k in range(i + 1, len(words) - 1)
        )
        return 1 if later else None

    def _at(self, path: tuple[tuple[str, ...], ...]) -> _Here:
        """What can follow ``path``. Kept by the context blocks each of its blocks matches: the
        answer depends on nothing else, and paths that differ only in names (20,000 units)
        share it."""
        key = tuple(self._class(b) for b in path)
        here = self._here.get(key)
        if here is not None:
            return here
        if len(self._here) >= _PATHS_KEPT:
            self._here.clear()
        mappings = [c for c in self._compiled if c.match_context(path) is not None]
        by_word: dict[str, list[Compiled]] = {}
        slot_first: list[Compiled] = []
        ranked: set[tuple[int, int, str, Block]] = set()
        for c in mappings:
            for v in c.variants:
                if not v or not isinstance(v[0], Word):
                    if c not in slot_first:
                        slot_first.append(c)
                elif c not in by_word.setdefault(v[0].text, []):
                    by_word[v[0].text].append(c)
                if v and _fixed(v):
                    ranked.add((len(c.context), len(v), repr(v), v))
        for ctx in self._contexts:
            for depth in range(min(len(ctx) - 1, len(path)), -1, -1):
                if depth == 0 and not _literal(ctx[0]):
                    continue  # a context can't start with a word that could be anything
                if depth and not _follows(ctx[:depth], path[-depth:]):
                    continue
                ranked.add((depth, len(ctx[depth]), repr(ctx[depth]), ctx[depth]))
        # Best first: the most of a context it continues, then the most words.
        order = sorted(ranked, key=lambda r: (-r[0], -r[1], r[2]))
        here = _Here(by_word, tuple(slot_first), tuple(r[3] for r in order))
        self._here[key] = here
        return here

    def _class(self, block: tuple[str, ...]) -> frozenset[int]:
        """The context blocks ``block`` matches, by number."""
        found = self._classes.get(block)
        if found is None:
            if len(self._classes) >= _PATHS_KEPT:
                self._classes.clear()
            candidates = (*self._by_first.get(block[0], ()), *self._any_first) if block else ()
            found = frozenset(
                n for n in candidates if match_tokens(self._patterns[n], block) is not None
            )
            self._classes[block] = found
        return found

    def _join_lists(self, stmts: Iterable[_Out]) -> list[_Out]:
        """Values of an ordered list, wherever their lines are, as one statement where the
        first is: a ``set`` command "is placed at the end of the list"."""
        out: list[_Out] = []
        lists: dict[tuple[tuple[str, ...], str], _Out] = {}
        for s in stmts:
            if s.block or len(s.words) != 2 or s.words[0] not in self._leaf_lists:
                out.append(s)
                continue
            key = (s.path, s.words[0])
            first = lists.get(key)
            if first is None:
                lists[key] = s
                out.append(s)
                if s.listed:
                    s.values = [s.words[1]]
                continue
            if first.values is None:
                first.values = [first.words[1]]
            first.values.append(s.words[1])
            first.end = max(first.end, s.end)
        return out


def _first_words(text: str) -> set[str] | None:
    """The first word of each path the file's commands name before any command moves the
    edit level; None if the file is a capture, which names its levels itself."""
    words: set[str] = set()
    for _, _, line in logical_lines(text):
        if not line or line.startswith("#"):
            continue
        if _framing(line):
            return None
        verb, *args = normal_words(tokenize(line))
        if verb in MOVE or verb == "edit":
            break
        if verb in CHANGE and args and verb not in ("insert", "rename", "copy"):
            words.add(args[0])
    return words


def _fixed(block: Block) -> bool:
    return not any(isinstance(p, Slot) and p.type == "LIST" for p in block)


def _literal(block: Block) -> bool:
    return bool(block) and isinstance(block[0], Word)


def _first_word(block: Block) -> str | None:
    return block[0].text if block and isinstance(block[0], Word) else None


def _follows(ctx: tuple[Block, ...], blocks: Sequence[tuple[str, ...]]) -> bool:
    return all(match_tokens(p, b) is not None for p, b in zip(ctx, blocks, strict=True))


def _fits(block: Block, words: tuple[str, ...], i: int) -> int:
    """``len(block)`` if ``block`` matches the words from ``i`` and leaves at least one after
    them, else 0."""
    n = len(block)
    if i + n >= len(words) or match_tokens(block, words[i : i + n]) is None:
        return 0
    return n
