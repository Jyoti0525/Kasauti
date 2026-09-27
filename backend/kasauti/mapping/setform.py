"""``set`` commands rebuilt into the brace tree they stand for (TODO M2.28).

Junos ``show configuration | display set`` prints each statement on a line of its own: the full
path from the top of the hierarchy, as a ``set`` command. The brace form of the same
configuration nests those words in blocks, and a pack's mappings are written for blocks
(``context: [system, services]``, ``match: telnet``). A line doesn't say where its blocks end:
``set system ntp server 10.0.0.1 key 1`` is one statement in ``system ntp``, while ``set system
syslog host 10.0.0.2 any notice`` is a statement in the block ``host 10.0.0.2``. Only the
vendor's schema knows, and the pack already records what it needs of it: its mappings' contexts
are blocks, their patterns statements. So each line is split where the mappings expect:

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
parser gives it. ``deactivate`` makes a path inactive and ``delete`` removes it, so neither
leaves a statement: the device ignores inactive configuration, and the brace parser drops
``inactive:`` too. ``activate`` undoes ``deactivate``; ``protect``, ``unprotect`` and
``annotate`` change nothing the device does. Any other command (``insert``, ``rename``) changes
order or names in a way the lines alone don't show, so the file isn't read as ``set`` commands.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass

from kasauti.mapping.match import Compiled, match_tokens
from kasauti.mapping.model import Mapping, PatternToken, Slot, Word, parse_pattern
from kasauti.packs.loader import VendorPack
from kasauti.shape.base import ParseError, RawStatement, check_depth
from kasauti.shape.lines import logical_lines, parse_flat
from kasauti.shape.model import ConfigTree, ShapeFamily
from kasauti.shape.parse import build_tree, parse_text
from kasauti.shape.tokens import tokenize

SET = "set"
_NO_EFFECT = frozenset({"protect", "unprotect", "annotate"})

Block = tuple[PatternToken, ...]


def parse_config(
    text: str, pack: VendorPack, *, source_file: str, sha256: str | None = None
) -> ConfigTree:
    """A configuration parsed for ``pack``: in the pack's shape family, or, when the pack takes
    ``set`` commands and the file is made of them, rebuilt into that family's tree. A file the
    rebuild can't read is read line by line with the reason, as when a parser rejects one."""
    family = pack.manifest.shape_family
    form = pack.manifest.set_form
    if form is None or not is_set_form(text):
        return parse_text(text, source_file=source_file, family=family, sha256=sha256)
    try:
        raws = SetFormReader(pack.mappings, form.leaf_lists).read(text)
    except ParseError as err:
        return build_tree(
            parse_flat(text),
            ShapeFamily.FLAT,
            text=text,
            source_file=source_file,
            sha256=sha256,
            warnings=[f"not valid set_path syntax ({err}); parsed line by line instead"],
        )
    return build_tree(
        raws,
        family,
        text=text,
        source_file=source_file,
        sha256=sha256,
        rebuilt_from=ShapeFamily.SET_PATH,
    )


def is_set_form(text: str) -> bool:
    """The first line that isn't blank or a comment is a ``set`` command."""
    for _, _, line in logical_lines(text):
        if line and not line.startswith("#"):
            return line.split(None, 1)[0] == SET
    return False


@dataclass(frozen=True, slots=True)
class _Command:
    seq: int
    start: int
    end: int
    words: tuple[str, ...]


@dataclass(slots=True)
class _Out:
    path: tuple[str, ...]
    words: tuple[str, ...]
    start: int
    end: int
    block: bool
    values: list[str] | None = None
    """A leaf list's values, once a second line has joined the first."""

    def raw(self) -> RawStatement:
        text = (
            " ".join(self.words)
            if self.values is None
            else f"{self.words[0]} [ {' '.join(self.values)} ]"
        )
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
    """Splits ``set`` lines where ``mappings`` expect blocks (see the module docstring)."""

    def __init__(self, mappings: Sequence[Mapping], leaf_lists: Collection[str] = ()) -> None:
        self._leaf_lists = frozenset(leaf_lists)
        self._compiled = tuple(Compiled(m, i) for i, m in enumerate(mappings))
        self._here: dict[tuple[tuple[str, ...], ...], _Here] = {}
        contexts = {tuple(parse_pattern(p) for p in m.context) for m in mappings if m.context}
        # Sorted, so the result never depends on set order; a context with a LIST slot has no
        # fixed length, so it can't mark where a block ends.
        self._contexts = tuple(sorted((c for c in contexts if all(_fixed(b) for b in c)), key=repr))
        self._starts = tuple(sorted({c[0] for c in self._contexts if _literal(c[0])}, key=repr))
        self._start_words = frozenset(str(_first_word(b)) for b in self._starts)

    def read(self, text: str) -> list[RawStatement]:
        opened: set[tuple[str, ...]] = set()
        out: list[_Out] = []
        for cmd in _active(text):
            blocks, leaf = self.split(cmd.words, cmd.start)
            headers = tuple(" ".join(b) for b in blocks)
            for k in range(len(headers)):
                if headers[: k + 1] not in opened:
                    opened.add(headers[: k + 1])
                    out.append(_Out(headers[:k], blocks[k], cmd.start, cmd.end, block=True))
            out.append(_Out(headers, leaf, cmd.start, cmd.end, block=False))
        # A line that names a block other lines open (``set system services ssh`` beside
        # ``set system services ssh root-login deny``) is that block, already given; a line
        # given twice is one statement.
        seen: set[tuple[str, ...]] = set()
        kept: list[_Out] = []
        for o in out:
            key = (*o.path, " ".join(o.words))
            if not o.block and (key in opened or key in seen):
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
        """What can follow ``path``. Kept per path: the same paths come on line after line."""
        here = self._here.get(path)
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
        self._here[path] = here
        return here

    def _join_lists(self, stmts: Iterable[_Out]) -> list[_Out]:
        out: list[_Out] = []
        for s in stmts:
            prev = out[-1] if out else None
            if (
                prev is not None
                and not s.block
                and not prev.block
                and len(s.words) == 2
                and s.words[0] in self._leaf_lists
                and s.words[1] != "["
                and prev.path == s.path
                and prev.words[0] == s.words[0]
                and (prev.values is not None or len(prev.words) == 2)
                and prev.words[-1] != "]"
            ):
                if prev.values is None:
                    prev.values = [prev.words[1]]
                prev.values.append(s.words[1])
                prev.end = s.end
                continue
            out.append(s)
        return out


def _active(text: str) -> list[_Command]:
    """The ``set`` lines that are still in the configuration and active."""
    sets: list[_Command] = []
    deleted: dict[tuple[str, ...], int] = {}
    inactive: dict[tuple[str, ...], int] = {}
    seq = 0
    for start, end, line in logical_lines(text):
        if not line or line.startswith("#"):
            continue
        seq += 1
        verb, *rest = tokenize(line)
        words = tuple(rest)
        if not words:
            raise ParseError(f"{verb!r} with nothing after it", start)
        if verb == SET:
            sets.append(_Command(seq, start, end, words))
        elif verb == "delete":
            deleted[words] = seq
        elif verb == "deactivate":
            inactive[words] = seq
        elif verb == "activate":
            inactive.pop(words, None)
        elif verb not in _NO_EFFECT:
            raise ParseError(
                f"{verb!r} changes the configuration in a way its lines don't show", start
            )

    # Only the lengths a delete or deactivate has are looked up: every prefix of a line of a
    # million words would be a million tuples, each as long as it is.
    deleted_sizes = sorted({len(k) for k in deleted})
    inactive_sizes = sorted({len(k) for k in inactive})

    def removed_after(words: tuple[str, ...], seq: int) -> bool:
        return any(deleted.get(words[:n], 0) > seq for n in deleted_sizes if n <= len(words))

    def is_inactive(words: tuple[str, ...]) -> bool:
        for n in inactive_sizes:
            if n > len(words):
                break
            when = inactive.get(words[:n])
            if when is not None and not removed_after(words[:n], when):
                return True
        return False

    return [c for c in sets if not removed_after(c.words, c.seq) and not is_inactive(c.words)]


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
