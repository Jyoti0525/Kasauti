"""The hostile-input corpus (TODO M2.07; PLAN §22: 0 crashes, 0 hangs beyond limits).

Generated, not stored: a committed zip bomb would trip every scanner that looks at the
repository, and a generator keeps each case readable and reproducible. Each case is a file an
attacker (or a broken export) could hand Kasauti, at a size that makes a quadratic cost show.

``ARCHIVES`` go through the upload intake, in the server's own process. ``FILES`` go through
the audit, in worker processes, exactly as an upload's jobs do.
"""

from __future__ import annotations

import io
import struct
import zipfile
from collections.abc import Callable
from dataclasses import dataclass

MIB = 1024 * 1024
RLO = chr(0x202E)
"""RIGHT-TO-LEFT OVERRIDE: makes ``gfc.exe`` display as ``exe.cfg``."""


@dataclass(frozen=True)
class Case:
    name: str
    """The file name it arrives under."""
    make: Callable[[int], bytes]
    """Its bytes, given a size in bytes to aim for."""
    why: str


def _zip(entries: dict[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _lzma_dictionary_bomb(_size: int) -> bytes:
    data = bytearray(_zip({"r.cfg": b"hostname R1\n" * 100}, zipfile.ZIP_LZMA))
    local = data.index(b"PK\x03\x04")
    name_len, extra_len = struct.unpack_from("<HH", data, local + 26)
    props = local + 30 + name_len + extra_len + 4  # after the 4-byte LZMA header in zip
    struct.pack_into("<I", data, props + 1, 0xFFFFFFFF)  # a 4 GiB dictionary
    return bytes(data)


def _overlapping_entries(size: int) -> bytes:
    """Many central-directory entries pointing at one compressed entry (the "non-recursive
    zip bomb" trick): each expands to the full size from the same few bytes."""
    one = _zip({"a.cfg": b"hostname R1\n" + b" " * size})
    start = one.index(b"PK\x01\x02")
    record = one[start : one.index(b"PK\x05\x06")]  # the one central-directory record
    count = 500
    central = record * count  # every record points at the same local header, offset 0
    end = struct.pack(
        "<4s4H2LH", b"PK\x05\x06", 0, 0, count, count, len(central), len(one[:start]), 0
    )
    return one[:start] + central + end


def _many_entries(_size: int) -> bytes:
    return _zip({f"d/{i}.cfg": b"x" for i in range(5000)}, zipfile.ZIP_STORED)


def _names(_size: int) -> bytes:
    return _zip(
        {
            "../../../../etc/passwd.cfg": b"hostname A\n",
            "/abs/b.cfg": b"hostname B\n",
            "C:\\Windows\\c.cfg": b"hostname C\n",
            "con.cfg": b"hostname D\n",  # a reserved device name on Windows
            "a\x00b.cfg": b"hostname E\n",
            RLO + "gfc.exe": b"hostname F\n",
            "..\\..\\g.cfg": b"hostname G\n",
            "x" * 4000 + ".cfg": b"hostname H\n",
        }
    )


def _truncated(_size: int) -> bytes:
    whole = _zip({"r.cfg": b"hostname R1\n" * 5000})
    return whole[: len(whole) // 2]


def _huge_comment(_size: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("r.cfg", b"hostname R1\n")
        zf.comment = b"c" * 65535
    return buf.getvalue()


def _nested(_size: int) -> bytes:
    inner = _zip({"r.cfg": b"hostname R1\n"})
    for _ in range(20):
        inner = _zip({"inner.zip": inner})
    return inner


ARCHIVES = [
    Case("lzma.zip", _lzma_dictionary_bomb, "an LZMA entry declaring a 4 GiB dictionary"),
    Case("overlap.zip", _overlapping_entries, "500 entries sharing one compressed stream"),
    Case("many.zip", _many_entries, "5,000 entries"),
    Case("names.zip", _names, "names that climb out, are absolute, reserved or deceptive"),
    Case("truncated.zip", _truncated, "cut off half way"),
    Case("comment.zip", _huge_comment, "a 64 KiB archive comment"),
    Case("nested.zip", _nested, "an archive nested 20 deep"),
]


def _repeat(unit: bytes, size: int, head: bytes = b"", tail: bytes = b"") -> bytes:
    return head + unit * max(1, (size - len(head) - len(tail)) // len(unit)) + tail


def _laughs(_size: int) -> bytes:
    entities = b"".join(
        b'<!ENTITY %c "%s">' % (98 + i, b"".join(b"&%c;" % (97 + i) for _ in range(10)))
        for i in range(9)
    )
    return (
        b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
        + entities
        + b"]><config>&j;</config>"
    )


def _xxe(_size: int) -> bytes:
    return (
        b'<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<config><hostname>&x;</hostname></config>"
    )


def _deep_xml(size: int) -> bytes:
    depth = size // 7
    return b"<a>" * depth + b"</a>" * depth


def _wide_xml(size: int) -> bytes:
    return _repeat(b'<entry name="x"><v>1</v></entry>\n', size, b"<config>\n", b"</config>\n")


def _deep_json(size: int) -> bytes:
    return b"[" * (size // 2) + b"]" * (size // 2)


def _deep_object(size: int) -> bytes:
    depth = size // 6
    return b'{"a":' * depth + b"1" + b"}" * depth


def _bigint(size: int) -> bytes:
    return b'{"n": ' + b"9" * size + b"}"


def _aliases(_size: int) -> bytes:
    rows = b"".join(
        b"%c: &%c [%s]\n" % (98 + i, 98 + i, b", ".join(b"*%c" % (97 + i) for _ in range(9)))
        for i in range(9)
    )
    return b"a: &a [x, x, x, x, x, x, x, x, x]\n" + rows


def _deep_yaml(size: int) -> bytes:
    return b"".join(b"  " * i + b"k:\n" for i in range(min(size // 400, 20000)))


def _deep_braces(size: int) -> bytes:
    depth = size // 6
    return b"system {\n" + b"a {\n" * depth + b"}\n" * (depth + 1)


def _deep_indent(size: int) -> bytes:
    return b"".join(b" " * i + b"interface x\n" for i in range(min(size // 5000, 3000)))


def _deep_forti(size: int) -> bytes:
    depth = size // 13
    return b"config a\n" * depth + b"end\n" * depth


def _utf16(size: int) -> bytes:
    return _repeat("interface Gi0/0\n shutdown\n".encode("utf-16-le"), size)


def _bidi(_size: int) -> bytes:
    return f"hostname R{RLO}1gfc\n username admin secret 5 $1$x$y\n".encode()


BAD_UTF8 = b"hostname \xff\xfe\xc3\x28 \xed\xa0\x80\n"


def _slots(size: int) -> bytes:
    line = b"ip address 10.0.0.1 255.255.255.0 secondary vrf x 1 2 3 4 5 6 7 8 9\n"
    return _repeat(line, size)


FILES = [
    Case("laughs.xml", _laughs, "billion laughs"),
    Case("xxe.xml", _xxe, "an external entity (XXE)"),
    Case("deep.xml", _deep_xml, "XML nested as deep as the size allows"),
    Case("wide.xml", _wide_xml, "XML with very many elements"),
    Case("deep.json", _deep_json, "JSON arrays nested as deep as the size allows"),
    Case("deep-object.json", _deep_object, "JSON objects nested deep"),
    Case("bigint.json", _bigint, "a number with a million digits"),
    Case("aliases.yaml", _aliases, "a YAML alias bomb"),
    Case("tags.yaml", lambda _s: b"a: !!python/object/apply:os.system ['id']\n", "a code tag"),
    Case("deep.yaml", _deep_yaml, "YAML nested deep by indentation"),
    Case("deep.conf", _deep_braces, "braces nested as deep as the size allows"),
    Case("comments.conf", lambda s: _repeat(b"/* ", s), "unclosed block comments, repeated"),
    Case("quotes.conf", lambda s: _repeat(b'set a "', s), "unclosed quotes, repeated"),
    Case("deep.cfg", _deep_indent, "indentation nested thousands deep"),
    Case("forti-deep.conf", _deep_forti, "FortiOS config blocks nested deep"),
    Case("banners.cfg", lambda s: _repeat(b"banner login\n", s), "EOS banners with no EOF"),
    Case("banners-delim.cfg", lambda s: _repeat(b"banner motd ^C\n", s), "Cisco banners unclosed"),
    Case("oneline.cfg", lambda s: b"hostname " + b"x" * s + b"\n", "one line, the whole file"),
    Case("tokens.cfg", lambda s: b"description " + _repeat(b"a ", s), "a line of a million words"),
    Case("blank.cfg", lambda s: b"hostname R1\n" + b"\n" * s, "a million empty lines"),
    Case("cr.cfg", lambda s: b"hostname R1" + b"\r" * s, "carriage returns only"),
    Case("nul-late.cfg", lambda s: b"hostname R1\n" + b"a" * 9000 + b"\x00" * s, "late NULs"),
    Case("utf16.cfg", _utf16, "UTF-16 without a BOM"),
    Case("badutf8.cfg", lambda s: _repeat(BAD_UTF8, s), "invalid UTF-8 and lone surrogates"),
    Case("bidi.cfg", _bidi, "a bidi override in a host name"),
    Case("brace-mix.cfg", lambda s: _repeat(b'{ } ; " # /* */ \\ ', s), "every lexer delimiter"),
    Case("path.rsc", lambda s: _repeat(b'/ip service set telnet disabled="', s), "unclosed quotes"),
    Case("slots.cfg", _slots, "many typed tokens per line"),
]
