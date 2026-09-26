"""Line splitting and tokenising shared by every shape family (PLAN §6.2)."""

from __future__ import annotations

import re

# A double-quoted string is one token (FortiOS ``edit "wan 1"``, Junos ``description "a b"``);
# anything else splits on whitespace. An unterminated quote is just part of a word.
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"(?=\s|$)|\S+')


def split_lines(text: str) -> list[str]:
    """Split on LF, CRLF or a lone CR. Line *n* of the result is line *n* in any editor.

    ``str.splitlines`` is not used: it also breaks on form feeds and Unicode separators, which
    would shift every later line number in the evidence.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def tokenize(text: str) -> tuple[str, ...]:
    return tuple(_TOKEN.findall(text))


def unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return re.sub(r"\\(.)", r"\1", token[1:-1])
    return token


def quote_if_needed(value: str) -> str:
    """Render a value as one token, so a slot captures it whole."""
    if value == "" or any(c.isspace() for c in value) or '"' in value:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value
