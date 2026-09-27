"""Junos configuration-mode commands, replayed into the statements they leave (TODO M2.28).

A ``show configuration | display set`` export is a list of ``set`` commands from the top of the
hierarchy. Files carry more of the CLI than that, and Juniper's own examples show it:

* commands pasted at an edit level ("copy and paste the commands into the CLI at the ``[edit
  policy-options]`` hierarchy level"), so their paths start below the top;
* ``insert`` to put a term or a list value in order, ``rename`` and ``copy``;
* a terminal capture: the ``[edit …]`` banner the CLI prints above each prompt, the prompt
  (``user@host#``) with the command typed after it, and the command's output. ``show |
  display set relative`` prints paths from the edit level; ``show`` alone prints braces.

This module replays such a file the way the CLI would and returns the statements left, each as
the full path of words from the top of the hierarchy, in configuration order. Paths are words,
as the CLI takes them: ``delete P`` removes every statement whose words start with P, and
``rename``, ``copy`` and ``insert`` name *identifier1* and *identifier2* with the same number of
words (``unit 100 to unit 102``, ``tacplus after radius``). Where blocks end doesn't matter
here: :mod:`kasauti.mapping.setform` splits the result into blocks afterwards, and statements
that came from braces keep the blocks the braces gave them.

What the file can't show is said, never guessed. A capture that never shows the whole
configuration, output filtered with ``| match``, an ``ACCESS-DENIED`` placeholder, or a
``rollback`` or ``load`` whose result isn't printed afterwards: each is a reason the file holds
only part of the configuration (:attr:`Replayed.partial`), and no verdict may rest on what it
doesn't show.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field

from kasauti.shape import brace
from kasauti.shape.base import ParseError, RawStatement
from kasauti.shape.lines import logical_lines
from kasauti.shape.tokens import tokenize

Words = tuple[str, ...]
Levels = Callable[[Words], list[Words]]
"""Splits a path of words into its levels (``interfaces``, ``ge-0/0/0``, ``unit 0``)."""

BANNER = re.compile(r"(?:\{[^{}]*\})?\[edit(?: (?P<path>[^\]]*))?\]")
"""``[edit]``, ``[edit system login]``; EX Virtual Chassis prefix ``{master:0}``."""
_STATUS = re.compile(r"\{[^{}]*\}")
"""``{master:0}`` on a line of its own, above an operational-mode prompt."""
PROMPT = re.compile(r"(?:\{[^{}]*\})?[\w.-]+@[\w.:-]+(?P<mode>[#>])(?:\s(?P<cmd>.*))?")
"""``user@host# set …`` (configuration mode) or ``user@host> show configuration`` (operational)."""

CHANGE = frozenset({"set", "delete", "deactivate", "activate", "insert", "rename", "copy", "edit"})
NO_EFFECT = frozenset({"protect", "unprotect", "annotate"})
"""Edit locks and comments: the device behaves the same."""
MOVE = frozenset({"up", "top", "exit", "quit"})
_READ_ONLY = frozenset({"show", "run", "commit", "status", "help", "save", "compare", "check"})
"""Configuration-mode commands that change nothing in the candidate configuration."""
_UNSEEN = frozenset({"rollback", "load", "replace", "update", "wildcard", "extension"})
"""Commands whose result depends on something the file doesn't hold (a saved configuration,
another file, a pattern applied to names it may not all show)."""
_SCRIPT = frozenset(
    {"delete", "insert", "rename", "copy", "activate", "edit", "up", "top", "exit", "quit"}
)
"""Commands no export prints: in a file of commands they change a configuration already there."""
_FILTERS = frozenset({"match", "except", "find", "last", "trim", "resolve"})
"""Pipes that leave out or rewrite part of the output."""
_NEUTRAL = frozenset({"no-more", "hold"})
_BRACE_DISPLAY = frozenset({"inheritance", "omit", "detail", "commit-scripts"})
"""``| display`` options whose output is still the configuration in braces."""
ACCESS_DENIED = "ACCESS-DENIED"

MAX_LENGTHS = 64
"""How many different path lengths the commands may name. Each costs an index over every
statement; real files name a dozen at most."""
MAX_MOVES = 5_000_000
"""Statements that ``insert`` may move, in all. Each insert moves its statements through the
list of all of them; this bounds a file of insert after insert."""
MAX_STATEMENTS = 2_000_000
"""Statements a file may leave; ``copy`` can double them."""


@dataclass(slots=True)
class Entry:
    words: Words
    start: int
    end: int
    path: tuple[str, ...] | None = None
    """The blocks braces gave this statement, if it came from braces and no command since has
    renamed it; None: split by the pack's mappings."""
    text: str | None = None
    listed: bool = False
    """It was one value of a ``[ … ]`` list."""
    alive: bool = True


@dataclass(frozen=True, slots=True)
class Replayed:
    entries: tuple[Entry, ...]
    """The statements left, active, in configuration order."""
    partial: tuple[str, ...]
    """Why the file holds only part of a configuration, if it does."""
    reordered: bool
    """An ``insert`` moved statements, so configuration order isn't file order."""
    level: Words
    """The edit level the file's own lines are relative to, if it isn't the top."""


class _Index:
    """Items by every prefix length a command has asked about, so each command finds the
    statements under a path without looking at the others."""

    def __init__(self) -> None:
        self.words: dict[int, Words] = {}
        self._by: dict[int, dict[Words, dict[int, None]]] = {}

    def add(self, key: int, words: Words) -> None:
        self.words[key] = words
        for n, index in self._by.items():
            if n <= len(words):
                index.setdefault(words[:n], {})[key] = None

    def remove(self, key: int) -> None:
        words = self.words.pop(key)
        for n, index in self._by.items():
            if n <= len(words):
                bucket = index.get(words[:n])
                if bucket is not None:
                    bucket.pop(key, None)
                    if not bucket:
                        del index[words[:n]]

    def under(self, prefix: Words, line: int) -> list[int]:
        n = len(prefix)
        index = self._by.get(n)
        if index is None:
            if len(self._by) >= MAX_LENGTHS:
                raise ParseError(f"commands name paths of more than {MAX_LENGTHS} lengths", line)
            index = {}
            for key, words in self.words.items():
                if n <= len(words):
                    index.setdefault(words[:n], {})[key] = None
            self._by[n] = index
        return list(index.get(prefix, ()))


@dataclass(slots=True)
class _Output:
    """What the lines after a prompt are."""

    base: Words
    """The path the output's statements are relative to."""
    tail: Words
    """``show`` named a statement, not a block: its output starts with these words."""
    form: str
    """``set``, ``brace`` or ``ignore``."""
    snapshot: bool
    """The whole configuration, unfiltered."""
    why_partial: str | None
    start: int
    lines: list[tuple[int, int, str]] = field(default_factory=list)


class Replay:
    """Replays a file of commands (see the module docstring)."""

    def __init__(self, levels: Levels, level: Words = ()) -> None:
        self._levels = levels
        self.entries: list[Entry] = []
        self._exact: dict[Words, int] = {}
        self._index = _Index()
        self._marks = _Index()
        self._mark_count = 0
        self.partial: list[str] = []
        self.reordered = False
        self._moved = 0
        self.level: Words = level
        self.view: dict[int, str] = {}
        """Each command line as the CLI would print it from the top: the fingerprint reads
        this, so a file relative to an edit level is still recognised."""
        self._stack: list[Words] = []
        self._first_level: Words | None = None
        self._config_mode = True
        self._prompted = False
        self._snapshot = False
        self._unseen: tuple[int, str] | None = None
        self._script: tuple[int, str] | None = None
        """The first command that changes a configuration the file doesn't hold."""
        self._wiped = False

    # --- reading ---------------------------------------------------------------------------

    def run(self, text: str) -> Replayed:
        output: _Output | None = None
        for start, end, line in logical_lines(text):
            if not line or line.startswith("#") or _STATUS.fullmatch(line):
                continue
            if banner := BANNER.fullmatch(line):
                self._flush(output)
                output = None
                self.level = normal_words(tokenize(banner["path"] or ""))
                self._stack = []
                self._config_mode = True
                continue
            if prompt := PROMPT.fullmatch(line):
                self._flush(output)
                self._prompted = True
                output = self._prompt(prompt["mode"], prompt["cmd"] or "", start, end)
                continue
            if output is not None:
                output.lines.append((start, end, line))
                continue
            if not self._config_mode:
                raise ParseError(f"{line.split()[0]!r} after leaving configuration mode", start)
            if self._first_level is None:
                self._first_level = self.level
            self._command(normal_words(tokenize(line)), start, end, typed=False)
        self._flush(output)
        return self._result()

    def _result(self) -> Replayed:
        if self._unseen is not None:
            line, verb = self._unseen
            raise ParseError(
                f"{verb!r} changes the configuration from something the file doesn't hold, and "
                "no whole configuration is shown after it",
                line,
            )
        partial = list(self.partial)
        if self._script is not None:
            line, verb = self._script
            partial.insert(
                0,
                f"line {line}: {verb!r} changes a configuration the file doesn't hold, so the "
                "file is a change to one, not a whole configuration",
            )
        if self._prompted and not self._snapshot and not partial:
            partial.append("the capture never shows the whole configuration")
        level = self._first_level or ()
        if level and not self._prompted:
            partial.append(f"its commands are relative to [edit {' '.join(level)}]")
        inactive_sizes = sorted({len(w) for w in self._marks.words.values()})
        marks = set(self._marks.words.values())
        kept = [
            e
            for e in self.entries
            if e.alive
            and not any(e.words[:n] in marks for n in inactive_sizes if n <= len(e.words))
        ]
        return Replayed(tuple(kept), tuple(dict.fromkeys(partial)), self.reordered, level)

    def _prompt(self, mode: str, cmd: str, start: int, end: int) -> _Output | None:
        words = normal_words(tokenize(cmd))
        if not words:
            return None
        verb = words[0]
        if mode == ">":
            self._config_mode = False
            if verb in ("configure", "edit") and all(w in _CONFIGURE for w in words[1:]):
                self._config_mode = True
                self.level = ()
                self._stack = []
                return None
            if verb == "show" and len(words) > 1 and words[1] == "configuration":
                return self._show((), words[2:], start)
            return _Output((), (), "ignore", False, None, start)
        self._config_mode = True
        if verb == "show":
            return self._show(self.level, words[1:], start)
        if verb in _READ_ONLY:
            return _Output((), (), "ignore", False, None, start)
        self._command(words, start, end, typed=True)
        # What the CLI prints after a change is an error or a warning: whether the change took
        # effect as typed isn't certain.
        return _Output((), (), "answer", False, None, start)

    def _show(self, level: Words, args: Words, start: int) -> _Output:
        segments = _pipes(args)
        path = segments[0]
        form = "brace"
        relative = False
        why: str | None = None
        for seg in segments[1:]:
            if not seg or seg[0] in _NEUTRAL:
                continue
            if seg[0] == "display" and len(seg) > 1 and seg[1] == "set":
                form = "set"
                relative = "relative" in seg[2:]
            elif seg[0] == "display" and len(seg) > 1 and seg[1] in _BRACE_DISPLAY:
                continue
            elif seg[0] in _FILTERS:
                why = f"line {start}: its output is filtered (| {' '.join(seg)})"
            else:
                return _Output((), (), "ignore", False, f"line {start}: | {' '.join(seg)}", start)
        full_path = (*level, *path)
        if form == "set" and not relative:
            base: Words = ()
        else:
            base = full_path
        if why is None and full_path:
            why = f"line {start}: it shows only [edit {' '.join(full_path)}]"
        return _Output(base, path[-1:], form, why is None, why, start)

    def _flush(self, output: _Output | None) -> None:
        if output is None:
            return
        if output.form == "answer":
            if output.lines:
                first = output.lines[0]
                self.partial.append(
                    f"line {first[0]}: the CLI answered the command on line {output.start} "
                    f"({first[2][:60]!r}), so whether it took effect isn't certain"
                )
            return
        if output.form == "ignore":
            if output.why_partial and output.lines:
                self.partial.append(f"{output.why_partial}: output not in braces or set form")
            return
        if not output.lines:
            return
        if output.snapshot:
            self._reset()
            self._snapshot = True
        elif output.why_partial and not self._snapshot:
            self.partial.append(output.why_partial)
        if output.form == "set":
            self._set_output(output)
        else:
            self._brace_output(output)

    def _set_output(self, output: _Output) -> None:
        words = [(s, e, normal_words(tokenize(t))) for s, e, t in output.lines]
        base = _without_tail(output.base, output.tail, [w[1:] for _, _, w in words if w])
        saved = self.level
        self.level = base
        try:
            for s, e, w in words:
                if w and w[0] not in ("set", "deactivate", *NO_EFFECT):
                    raise ParseError(f"{w[0]!r} in the output of show | display set", s)
                self._command(w, s, e, typed=False)
        finally:
            self.level = saved

    def _brace_output(self, output: _Output) -> None:
        body = "\n".join(t for _, _, t in output.lines)
        # Lines between the output's lines (comments, a status line) were left out; renumber
        # through a map so evidence points at the file's own lines. A quoted value can span
        # lines, so a logical line stands for each of them.
        numbers = [n for s, e, _ in output.lines for n in range(s, e + 1)]
        raws = list(brace.parse(body))
        tops = [tokenize(r.text) for r in raws if not r.path]
        base = _without_tail(output.base, output.tail, tops)
        self.add_brace(raws, base, lambda n: numbers[min(n, len(numbers)) - 1])
        if base:
            self.view.update(brace_view(output.lines, self._levels(base)))

    # --- statements from braces ------------------------------------------------------------

    def add_brace(
        self, raws: Sequence[RawStatement], base: Words, line: Callable[[int], int] = int
    ) -> None:
        blocks = tuple(" ".join(b) for b in self._levels(base)) if base else ()
        for raw in raws:
            for text, listed in _expand(raw.text):
                words = (*base, *(w for p in raw.path for w in tokenize(p)), *tokenize(text))
                self._add(
                    Entry(
                        words,
                        line(raw.line_start),
                        line(raw.line_end),
                        (*blocks, *raw.path),
                        text,
                        listed,
                    ),
                    raw.line_start,
                )
            if ACCESS_DENIED in raw.text:
                self.partial.append(
                    f"line {line(raw.line_start)}: {ACCESS_DENIED} stands in for "
                    "configuration the exporting account may not view"
                )

    # --- commands --------------------------------------------------------------------------

    def _command(self, words: Words, start: int, end: int, *, typed: bool) -> None:
        verb, args = words[0], words[1:]
        if ACCESS_DENIED in args:
            self.partial.append(
                f"line {start}: {ACCESS_DENIED} stands in for configuration the exporting "
                "account may not view"
            )
        if not typed and verb in _SCRIPT:
            self._script_line(verb, args, start)
        if verb in MOVE:
            self._move(verb, args, start, end, typed=typed)
        elif verb in _UNSEEN:
            if not typed:
                raise ParseError(
                    f"{verb!r} changes the configuration from something the file doesn't hold",
                    start,
                )
            self._unseen = (start, verb)
        elif verb in CHANGE:
            self._change(verb, args, start, end)
        elif verb not in NO_EFFECT:
            raise ParseError(f"{verb!r} isn't a configuration command", start)

    def _script_line(self, verb: str, args: Words, start: int) -> None:
        """An export holds only ``set`` and ``deactivate`` lines. Any other change is made to a
        configuration already on the device, which the file doesn't hold, unless the file first
        deletes everything: ``delete`` with nothing after it at ``[edit]`` asks "Delete
        everything under this level?", and what follows is then the whole configuration."""
        if verb == "delete" and not args and not self.level:
            self._script = None
            self._wiped = True
        elif self._script is None and not self._wiped:
            self._script = (start, verb)

    def _move(self, verb: str, args: Words, start: int, end: int, *, typed: bool) -> None:
        """``up [n] [command]``, ``top [command]``, ``exit``/``quit``: "The top or up command
        followed by another configuration command … enables you to quickly move to the top of
        the hierarchy or to a level above the area you are configuring"; exit "returning to the
        level before the last edit command, or exit from configuration mode"."""
        if verb in ("exit", "quit"):
            if args == ("configuration-mode",) or (not self._stack and not self.level):
                self._config_mode = False
            else:
                self.level = self._stack.pop() if self._stack else ()
            return
        n = 1
        if verb == "up" and args and args[0].isdigit():
            n, args = int(args[0]), args[1:]
        levels = self._levels(self.level) if verb == "up" else []
        target = tuple(w for b in levels[: max(0, len(levels) - n)] for w in b)
        if not args:
            self.level, self._stack = target, []
            return
        saved = self.level
        self.level = target
        self._command(args, start, end, typed=typed)
        if args[0] != "edit":
            self.level = saved

    def _change(self, verb: str, args: Words, start: int, end: int) -> None:
        path = (*self.level, *args)
        if self.level and verb in ("set", "deactivate", "delete", "activate"):
            self.view[start] = " ".join((verb, *path))
        if not args and verb in ("set", "edit"):
            raise ParseError(f"{verb!r} with nothing after it", start)
        match verb:
            case "set":
                for words_, listed in _values(path, start):
                    self._add(Entry(words_, start, end, listed=listed), start)
            case "edit":
                # "If the statement does not exist, it is created."
                self._add(Entry(path, start, end), start)
                self._stack.append(self.level)
                self.level = path
            case "delete":
                self._delete(path, start)
            case "deactivate":
                self._mark_count += 1
                self._marks.add(self._mark_count, path)
            case "activate":
                for key in self._marks.under(path, start):
                    if self._marks.words[key] == path:
                        self._marks.remove(key)
            case "insert":
                self._insert(args, start)
            case "rename" | "copy":
                self._rename_or_copy(verb, args, start, end)

    def _delete(self, path: Words, start: int) -> None:
        """ "All subordinate statements and identifiers contained within the specified
        statement path are deleted with it", and so is what marked them inactive."""
        for words, _ in _values(path, start):
            for key in self._index.under(words, start):
                self._drop(key)
            for key in self._marks.under(words, start):
                self._marks.remove(key)

    def _add(self, entry: Entry, line: int) -> None:
        if entry.words in self._exact:
            return  # given again: no change, and it keeps its place
        if len(self.entries) >= MAX_STATEMENTS:
            raise ParseError(f"more than {MAX_STATEMENTS} statements", line)
        self.entries.append(entry)
        self._exact[entry.words] = len(self.entries) - 1
        self._index.add(len(self.entries) - 1, entry.words)

    def _drop(self, key: int) -> None:
        self.entries[key].alive = False
        self._exact.pop(self.entries[key].words, None)
        self._index.remove(key)

    def _reset(self) -> None:
        for key in list(self._index.words):
            self._drop(key)
        for key in list(self._marks.words):
            self._marks.remove(key)
        self.partial = []
        self._unseen = None

    def _identifiers(
        self, args: Words, keywords: tuple[str, ...], start: int
    ) -> tuple[Words, Words, Words, str]:
        """``<statement-path> identifier1 (keyword) identifier2`` -> path, id1, id2, keyword."""
        at = max((i for i, w in enumerate(args) if w in keywords), default=-1)
        second = args[at + 1 :]
        size = len(second)
        if at < 0 or not size or at - size < 0:
            raise ParseError(
                f"expected '<path> identifier {' | '.join(keywords)} identifier'", start
            )
        return (*self.level, *args[: at - size]), args[at - size : at], second, args[at]

    def _insert(self, args: Words, start: int) -> None:
        path, first, second, where = self._identifiers(args, ("before", "after"), start)
        moving = self._index.under((*path, *first), start)
        target = self._index.under((*path, *second), start)
        value = (*path, *second)
        if not moving and target and all(self._index.words[k] == value for k in target):
            # A new value in an ordered list: "insert system authentication-order tacplus
            # after radius" adds tacplus there.
            self._add(Entry((*path, *first), start, start), start)
            moving = self._index.under((*path, *first), start)
        if not moving or not target:
            self.partial.append(
                f"line {start}: insert names {' '.join((*path, *(second if moving else first)))}, "
                "which isn't in the file"
            )
            return
        self._moved += len(self.entries)
        if self._moved > MAX_MOVES:
            raise ParseError("too many statements moved by insert", start)
        order = [k for k, e in enumerate(self.entries) if e.alive]
        moving_set = set(moving)
        rest = [k for k in order if k not in moving_set]
        target_set = set(target)
        at = next((i for i, k in enumerate(rest) if k in target_set), None)
        if at is None:
            return  # placed relative to itself: nothing moves
        if where == "after":
            at += 1
            while at < len(rest) and rest[at] in target_set:
                at += 1
        new_order = [*rest[:at], *(k for k in order if k in moving_set), *rest[at:]]
        self._renumber(new_order)
        self.reordered = True

    def _renumber(self, order: list[int]) -> None:
        entries = [self.entries[k] for k in order]
        self.entries = []
        self._exact = {}
        self._index = _Index()
        for entry in entries:
            self._add(entry, entry.start)

    def _rename_or_copy(self, verb: str, args: Words, start: int, end: int) -> None:
        path, first, second, _ = self._identifiers(args, ("to",), start)
        old = (*path, *first)
        new = (*path, *second)
        found = self._index.under(old, start)
        if not found:
            self.partial.append(
                f"line {start}: {verb} names {' '.join(old)}, which isn't in the file"
            )
            return
        for key in found:
            entry = self.entries[key]
            words = (*new, *entry.words[len(old) :])
            if verb == "rename":
                self._index.remove(key)
                self._exact.pop(entry.words, None)
                entry.words, entry.path, entry.text = words, None, None
                self._exact[words] = key
                self._index.add(key, words)
            else:
                self._add(Entry(words, start, end, listed=entry.listed), start)
        for key in self._marks.under(old, start):
            words = (*new, *self._marks.words[key][len(old) :])
            if verb == "rename":
                self._marks.remove(key)
                self._marks.add(key, words)
            else:
                self._mark_count += 1
                self._marks.add(self._mark_count, words)


_CONFIGURE = frozenset({"private", "exclusive", "dynamic", "batch", "shared"})


def _pipes(args: Words) -> list[Words]:
    out: list[list[str]] = [[]]
    for w in args:
        if w == "|":
            out.append([])
        else:
            out[-1].append(w)
    return [tuple(s) for s in out]


def normal_words(words: Words) -> Words:
    """Brackets as words of their own: ``members [65535:10 65535:11]`` is how Juniper's guide
    types a set of values, and the CLI prints ``[ a b ]``."""
    out: list[str] = []
    for w in words:
        if w.startswith('"'):
            out.append(w)
            continue
        head = w
        while head.startswith("[") and head != "[":
            out.append("[")
            head = head[1:]
        tail = 0
        while head.endswith("]") and head != "]":
            tail += 1
            head = head[:-1]
        out.append(head)
        out.extend("]" * tail)
    return tuple(out)


def _values(path: Words, line: int) -> Iterator[tuple[Words, bool]]:
    """``kw [ a b ]`` as ``kw a`` and ``kw b``: "To specify a set, include the values in
    brackets." Anything else as it is."""
    if "[" not in path and "]" not in path:
        yield path, False
        return
    at = path.index("[") if "[" in path else -1
    if at < 1 or path[-1] != "]" or path.count("[") != 1 or path.count("]") != 1:
        raise ParseError("a '[ … ]' list that isn't at the end of the line", line)
    items = path[at + 1 : -1]
    if not items:
        yield path[:at], False
        return
    for item in items:
        yield (*path[:at], item), True


def _expand(text: str) -> Iterator[tuple[str, bool]]:
    """A statement from braces, with a ``[ … ]`` list given one value at a time."""
    words = normal_words(tokenize(text))
    if "[" not in words:
        yield text, False
        return
    try:
        values = list(_values(words, 0))
    except ParseError:
        yield text, False
        return
    for value, listed in values:
        yield " ".join(value), listed


def _without_tail(base: Words, tail: Words, first: Sequence[Words]) -> Words:
    """``show system authentication-order`` prints ``authentication-order [ … ];``: the
    statement itself, at the level above the path shown."""
    if tail and base and base[-1:] == tail and first and all(f[:1] == tail for f in first):
        return base[:-1]
    return base


def brace_view(lines: Sequence[tuple[int, int, str]], levels: Sequence[Words]) -> dict[int, str]:
    """Brace lines shown below the top, as they would read from the top: the enclosing blocks
    opened on the first line, and every line indented under them."""
    if not lines or not levels:
        return {}
    opened = " ".join(f"{' '.join(b)} {{" for b in levels)
    indent = "    " * len(levels)
    (first, _, text), *rest = lines
    return {first: f"{opened} {text}", **{s: indent + t for s, _, t in rest}}
