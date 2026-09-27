"""The audit job's handler (TODO M2.04, M2.06), run in this process for speed; the API tests run
it in real worker processes."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import audit, load_kb
from kasauti.ingest.read import MAX_BYTES, decode
from kasauti.ingest.sealed import new_key
from kasauti.ingest.staging import STAGING_KEY_NAME, Staging
from kasauti.ingest.upload import new_id
from kasauti.ingest.worker import audit_file
from kasauti.jobs import JobError
from kasauti.jobs.child import set_worker_secrets
from kasauti.jobs.results import RESULT_LIMIT, encode_result

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"
CISCO = REPO / "datasets" / "authored" / "cisco_ios_xe"
WEAK = CISCO / "weak.cfg"


KEY = new_key()


@pytest.fixture(autouse=True)
def _worker_secrets() -> Iterator[None]:
    """What the pool hands a worker process when it starts."""
    set_worker_secrets({STAGING_KEY_NAME: KEY})
    yield
    set_worker_secrets({})


def _stage(staging: Staging, upload_id: str, data: bytes) -> str:
    file_id = new_id()
    with staging.create(upload_id, file_id) as sink:
        sink.write(data)
    staging.commit(upload_id, file_id)
    return file_id


def _payload(tmp_path: Path, data: bytes | None, **extra: Any) -> dict[str, Any]:
    staging = Staging(tmp_path / "staging", KEY)
    upload_id = new_id()
    file_id = new_id() if data is None else _stage(staging, upload_id, data)
    return {
        "upload": upload_id,
        "file": file_id,
        "name": "core/weak.cfg",
        "frameworks": ["nist_800_53r5"],
        "vendor": None,
        "staging": str(staging.root),
        "staging_key": staging.key_id,
        "packs": str(PACKS),
        **extra,
    }


def test_a_file_sealed_before_a_restart_says_so_and_is_deleted(tmp_path: Path) -> None:
    payload = _payload(tmp_path, WEAK.read_bytes())
    staged = Path(payload["staging"]) / payload["upload"] / payload["file"]
    assert staged.exists()
    set_worker_secrets({STAGING_KEY_NAME: new_key()})  # the server restarted: a new key
    with pytest.raises(JobError, match="the server restarted since it was uploaded"):
        audit_file(payload)
    assert not staged.exists()


def test_a_tampered_file_is_refused_not_audited(tmp_path: Path) -> None:
    payload = _payload(tmp_path, WEAK.read_bytes())
    staged = Path(payload["staging"]) / payload["upload"] / payload["file"]
    data = bytearray(staged.read_bytes())
    data[100] ^= 0x01
    staged.write_bytes(bytes(data))
    with pytest.raises(JobError, match="can't be opened any more"):
        audit_file(payload)
    assert not staged.exists()


def test_the_result_is_the_audit_the_command_line_gives(tmp_path: Path) -> None:
    result = audit_file(_payload(tmp_path, WEAK.read_bytes()))
    expected = audit(decode(WEAK.read_bytes(), "core/weak.cfg"), load_kb(PACKS))
    assert result == json.loads(expected.canonical_json())


def test_the_staged_file_is_gone_once_read(tmp_path: Path) -> None:
    payload = _payload(tmp_path, WEAK.read_bytes())
    audit_file(payload)
    assert not any(Path(payload["staging"]).rglob("*.cfg"))
    assert not any(p.is_file() for p in Path(payload["staging"]).rglob("*"))
    with pytest.raises(JobError, match="no longer here; upload it again"):
        audit_file(payload)


@pytest.mark.parametrize(
    ("data", "extra", "message"),
    [
        (b"\x00\x01\x02" * 100, {}, "looks like a binary file"),
        (b"   \n\n", {}, "file is empty"),
        (b"just some words\n", {}, "can't tell which vendor this is"),
        (b"hostname x\n", {"vendor": "no_such_pack"}, "no vendor pack 'no_such_pack'"),
        (b"hostname x\n", {"upload": "../../etc"}, "doesn't name uploaded files"),
        (
            b"hostname x\n",
            {"companions": [{"id": "../x", "name": "v.txt"}]},
            "doesn't name uploaded files",
        ),
        (
            b"hostname x\n",
            {"companions": [{"id": new_id(), "name": "v.txt"}] * 9},
            "at most 8 command outputs",
        ),
    ],
)
def test_failures_are_sentences_for_the_user(
    tmp_path: Path, data: bytes, extra: dict[str, Any], message: str
) -> None:
    with pytest.raises(JobError, match=message) as caught:
        audit_file(_payload(tmp_path, data, **extra))
    assert "some words" not in str(caught.value)


def test_no_file_the_upload_accepts_can_outgrow_the_result_limit(tmp_path: Path) -> None:
    """The densest input found: a bare ``interface`` line after line, each an entity whose every
    fact is written out. Its compressed result is 1.8 times its size here and 2.24 times at
    100,000 lines (measured 2026-09-27; gzip's window finds fewer repeats in a larger file). The
    limit keeps a margin over that for a file at the upload limit (TODO M2.04 follow-up)."""
    dense = WEAK.read_bytes() + b"".join(b"interface Loopback%d\n" % i for i in range(2000))
    result = audit_file(_payload(tmp_path, dense))
    assert len(encode_result(result)) <= 2.5 * len(dense)
    assert RESULT_LIMIT >= 3 * MAX_BYTES


def test_a_companion_output_on_its_own_says_what_it_is(tmp_path: Path) -> None:
    junos = REPO / "datasets" / "authored" / "juniper_junos"
    payload = _payload(tmp_path, (junos / "companions" / "show_version.txt").read_bytes())
    with pytest.raises(JobError) as caught:
        audit_file(payload)
    assert str(caught.value) == (
        "core/weak.cfg: `show version` output from a Juniper Junos OS device, not a "
        "configuration; it adds the serial number and hardware to that device's audit: "
        "upload it with that device's configuration (or kasauti audit <config> --companion "
        "<file>)"
    )


def test_a_device_s_command_outputs_are_read_deleted_and_used(tmp_path: Path) -> None:
    payload = _payload(tmp_path, WEAK.read_bytes())
    staging = Staging(Path(payload["staging"]), KEY)
    outputs = {
        name: _stage(staging, payload["upload"], (CISCO / "companions" / name).read_bytes())
        for name in ("show_version.txt", "show_inventory.txt")
    }
    payload["companions"] = [{"id": i, "name": f"core/{n}"} for n, i in outputs.items()]
    result = audit_file(payload)
    assert not any(p.is_file() for p in staging.root.rglob("*")), "every file read is deleted"
    assert [(c["file"], c["used"]) for c in result["companions"]] == [
        ("core/show_inventory.txt", True),
        ("core/show_version.txt", True),
    ]
    assert result["identity"]["serial"]["value"] is not None
    assert result["inventory"], "the hardware inventory comes from show inventory"


def test_a_missing_command_output_fails_the_audit_with_its_name(tmp_path: Path) -> None:
    payload = _payload(tmp_path, WEAK.read_bytes())
    payload["companions"] = [{"id": new_id(), "name": "core/show_version.txt"}]
    with pytest.raises(JobError, match=r"^core/show_version\.txt: the uploaded file is no longer"):
        audit_file(payload)
