"""Taking files in (TODO M2.04): display names, types, first-byte checks and zip archives."""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

from kasauti.ingest import upload
from kasauti.ingest.staging import Staging, read_once
from kasauti.ingest.upload import Received, display_name, inspect, new_id, type_refusal

CONFIG = b"hostname EDGE-R1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("router.cfg", "router.cfg"),
        ("site-a/core/router.cfg", "site-a/core/router.cfg"),
        ("../../etc/passwd.cfg", "etc/passwd.cfg"),
        ("/abs/path.cfg", "abs/path.cfg"),
        ("C:\\Users\\x\\r1.cfg", "Users/x/r1.cfg"),
        ("a/./b//c.cfg", "a/b/c.cfg"),
        # Right-to-left override: would display as "router.gfc.exe"-style trickery.
        ("router\u202eexe.cfg", "routerexe.cfg"),
        ("line\nbreak\x00.cfg", "linebreak.cfg"),
        ("wide\u3000space.cfg", "wide space.cfg"),
        ("..", ""),
    ],
)
def test_display_names_keep_the_path_and_nothing_that_misleads(raw: str, shown: str) -> None:
    assert display_name(raw) == shown


def test_a_very_long_name_keeps_its_end_where_the_file_name_is() -> None:
    name = display_name("d/" * 400 + "router.cfg")
    assert len(name) == 512
    assert name.startswith("…")
    assert name.endswith("/router.cfg")


@pytest.mark.parametrize(
    ("name", "refused"),
    [
        ("r1.cfg", None),
        ("R1.CONF", None),
        ("fw.xml", None),
        ("cloud.yml", None),
        ("bundle.zip", None),
        ("show_run", "not a configuration file type"),
        ("tool.exe", "not a configuration file type"),
        (".DS_Store", "not a configuration file type"),
        ("configs.tar.gz", ".gz archives aren't opened"),
        ("configs.7z", ".7z archives aren't opened"),
        ("", "the file has no name"),
    ],
)
def test_types_are_the_plans_list(name: str, refused: str | None) -> None:
    reason = type_refusal(name)
    assert reason is None if refused is None else reason is not None and refused in reason


@pytest.fixture
def staging(tmp_path: Path) -> Staging:
    stage = Staging(tmp_path / "staging")
    stage.prepare()
    return stage


UPLOAD = "00000000-0000-4000-8000-00000000000a"


def _received(staging: Staging, name: str, data: bytes) -> Received:
    file_id = new_id()
    with staging.create(UPLOAD, file_id) as sink:
        sink.write(data)
    return Received(file_id, name, len(data), "0" * 64)


@pytest.mark.parametrize(
    ("data", "refused"),
    [
        (CONFIG, None),
        ("hostname R1\n".encode("utf-16"), None),  # NUL bytes, but a BOM says it's text
        (b"", "the file is empty"),
        (b"\x7fELF\x02\x01\x01\x00" + bytes(200), "looks like a binary file"),
    ],
)
def test_a_file_is_checked_on_its_first_bytes(
    staging: Staging, data: bytes, refused: str | None
) -> None:
    body = _received(staging, "r1.cfg", data)
    (got,) = inspect(staging, UPLOAD, body)
    if refused is None:
        assert got == body
        assert staging.part(UPLOAD, body.id).read_bytes() == data
    else:
        assert got.reason is not None
        assert refused in got.reason
        assert not staging.part(UPLOAD, body.id).exists()


def _zip(entries: dict[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _expand(staging: Staging, data: bytes, name: str = "bundle.zip") -> dict[str, str | None]:
    body = _received(staging, name, data)
    rows = inspect(staging, UPLOAD, body)
    assert not staging.part(UPLOAD, body.id).exists(), "the archive itself is never kept"
    for row in rows:
        kept = staging.part(UPLOAD, row.id).exists()
        assert kept == row.accepted, row
    return {r.name: r.reason for r in rows}


def test_a_zip_is_expanded_entry_by_entry_under_its_own_ids(
    staging: Staging, tmp_path: Path
) -> None:
    rows = _expand(
        staging,
        _zip(
            {
                "site/r1.cfg": CONFIG,
                "../../../outside.cfg": b"hostname OUT\n",
                "C:/Windows/system.cfg": b"hostname WIN\n",
                "notes.pdf": b"%PDF-1.7",
                "inner.zip": _zip({"x.cfg": CONFIG}),
                "blob.cfg": bytes(range(256)) * 8,
            }
        ),
    )
    assert rows == {
        "bundle.zip/site/r1.cfg": None,
        "bundle.zip/outside.cfg": None,
        "bundle.zip/Windows/system.cfg": None,
        "bundle.zip/notes.pdf": rows["bundle.zip/notes.pdf"],
        "bundle.zip/inner.zip": "an archive inside an archive isn't opened; upload it on its own",
        "bundle.zip/blob.cfg": "looks like a binary file, not a text configuration",
    }
    assert "not a configuration file type" in str(rows["bundle.zip/notes.pdf"])
    # Zip-slip has nothing to act on: every file is inside the upload's directory, by id.
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert {p.parent for p in written} == {staging.root / UPLOAD}
    assert all(p.name.removesuffix(".part") != "outside.cfg" for p in written)


def test_symbolic_links_and_encrypted_entries_are_refused(staging: Staging) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        link = zipfile.ZipInfo("passwd.cfg")
        link.external_attr = (0o120777 << 16) | 0x10
        zf.writestr(link, "/etc/passwd")
        zf.writestr("locked.cfg", b"\x00" * 32)
    data = bytearray(buf.getvalue())
    # Mark the second entry encrypted, in its local header and its central directory record.
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = data.index(signature, data.index(signature) + 1) + offset
        data[at] |= 0x1
    rows = _expand(staging, bytes(data))
    assert rows == {
        "bundle.zip/passwd.cfg": "a symbolic link, not a file",
        "bundle.zip/locked.cfg": "encrypted; put it in the archive unencrypted",
    }


def test_a_file_named_zip_that_isnt_one_is_refused(staging: Staging) -> None:
    assert _expand(staging, CONFIG) == {"bundle.zip": "not a readable zip archive"}


def test_an_archive_with_nothing_in_it_says_so(staging: Staging) -> None:
    assert _expand(staging, _zip({"empty/": b""})) == {"bundle.zip": "the archive holds no files"}


def test_too_many_entries_and_the_archive_is_not_opened(
    staging: Staging, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upload, "MAX_ARCHIVE_ENTRIES", 3)
    rows = _expand(staging, _zip({f"r{i}.cfg": CONFIG + bytes([65 + i]) for i in range(4)}))
    assert rows == {"bundle.zip": "the archive holds 4 entries; at most 3 are opened"}


def test_a_zip_bomb_costs_at_most_the_limit(
    staging: Staging, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upload, "MAX_BYTES", 1024 * 1024)
    bomb = b"hostname BOMB\n" + b" " * (64 * 1024 * 1024)  # 64 MiB of spaces: ~64 KiB zipped
    data = _zip({"bomb.cfg": bomb})
    assert len(data) < 256 * 1024
    rows = _expand(staging, data)
    assert rows == {"bundle.zip/bomb.cfg": f"{len(bomb)} bytes when expanded; the limit is 1048576"}


def test_an_entry_that_lies_about_its_size_is_cut_off_and_refused(staging: Staging) -> None:
    """The archive says 16 bytes; the data inflates to far more. Reading stops at what was
    declared, and the checksum then fails."""
    data = bytearray(_zip({"liar.cfg": CONFIG * 1000}))
    for signature, offset in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        at = data.index(signature) + offset
        data[at : at + 4] = (16).to_bytes(4, "little")
    rows = _expand(staging, bytes(data))
    assert rows == {"bundle.zip/liar.cfg": "damaged or unreadable in the archive"}


def test_an_archive_stops_expanding_at_its_total_limit(
    staging: Staging, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upload, "MAX_EXPANDED_BYTES", 250_000)
    entries = {f"r{i}.cfg": b"hostname R%d\n" % i + b"!\n" * 50_000 for i in range(4)}
    rows = _expand(staging, _zip(entries))
    past = "the archive expands past 0 MiB; not opened"
    assert rows == {
        "bundle.zip/r0.cfg": None,
        "bundle.zip/r1.cfg": None,
        "bundle.zip/r2.cfg": past,
        "bundle.zip/r3.cfg": past,
    }


def test_staged_files_are_owner_only_and_read_once(staging: Staging) -> None:
    body = _received(staging, "r1.cfg", CONFIG)
    staging.commit(UPLOAD, body.id)
    path = staging.path(UPLOAD, body.id)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert (staging.root / UPLOAD).stat().st_mode & 0o777 == 0o700
    assert read_once(staging.root, UPLOAD, body.id, 1024) == CONFIG
    assert not path.exists()
    with pytest.raises(FileNotFoundError):
        read_once(staging.root, UPLOAD, body.id, 1024)


def test_staging_names_are_ids_only(staging: Staging) -> None:
    for bad in ("../x", "x", "00000000-0000-4000-8000-00000000000A"):
        with pytest.raises(ValueError, match="canonical UUIDs"):
            staging.path(UPLOAD, bad)
