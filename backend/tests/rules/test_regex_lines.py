"""Whole-text, line-by-line searching (TODO M2.07): one RE2 pass must find exactly what a
search of each line on its own would, line numbers included."""

from __future__ import annotations

import time

import pytest

from kasauti.identity.detect import _line_prefix
from kasauti.rules import regex
from kasauti.shape.tokens import joined_lines, split_lines

TEXT = "a\n\n   \n  <deviceconfig>\nversion 17.9\r\nxx ab\na\nb\r#config-version=FGT60F-7.4.8-FW\n"
PATTERNS = [
    r"^\s*<deviceconfig>",  # \s* must not run back over blank lines
    r"^version (?P<value>\S+)$",  # $ at the end of a line, even before CRLF
    r"a.*b",  # never across a line break
    r"^b$",
    r"^#config-version=(?P<value>F[A-Z0-9]+)-",
    r"\n",  # a newline is never inside a line
    r"^$",
    r"nothing",
]


def _per_line(pattern: str, text: str) -> tuple[int, dict[str, str]] | None:
    for number, line in enumerate(split_lines(text), 1):
        m = regex._compiled(pattern).search(line)
        if m is not None:
            return number, {k: str(v) for k, v in m.groupdict().items() if v is not None}
    return None


@pytest.mark.parametrize("pattern", PATTERNS)
def test_one_pass_finds_what_each_line_would(pattern: str) -> None:
    assert regex.first_line(pattern, joined_lines(TEXT)) == _per_line(pattern, TEXT)


def test_every_matching_line_is_found_with_where_it_starts() -> None:
    joined = joined_lines(TEXT)
    found = [(n, s) for n, s, _ in regex.matching_lines(r"^a", joined)]
    assert found == [(1, 0), (7, joined.index("\na\nb") + 1)]


@pytest.mark.parametrize("prefix", ["<deviceconfig>", "version", "b", "a", "zz", "#config"])
def test_a_line_prefix_is_found_as_strip_and_startswith_would(prefix: str) -> None:
    expected = next(
        (n for n, ln in enumerate(split_lines(TEXT), 1) if ln.lstrip().startswith(prefix)), None
    )
    assert _line_prefix(joined_lines(TEXT), prefix) == expected


def test_a_million_short_lines_are_one_search() -> None:
    text = "x\n" * 1_000_000 + "hostname R1\n"
    started = time.monotonic()
    assert regex.first_line(r"^hostname (?P<value>\S+)", text) == (1_000_001, {"value": "R1"})
    assert _line_prefix(text, "hostname") == 1_000_001
    assert time.monotonic() - started < 2.0  # line by line, this took about 7 s
