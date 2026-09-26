"""The audit job's handler (TODO M2.04), run in this process for speed; the API tests run it in
real worker processes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import audit, load_kb
from kasauti.ingest.read import decode
from kasauti.ingest.staging import Staging
from kasauti.ingest.upload import new_id
from kasauti.ingest.worker import audit_file
from kasauti.jobs import JobError

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"
WEAK = REPO / "datasets" / "authored" / "cisco_ios_xe" / "weak.cfg"


def _payload(tmp_path: Path, data: bytes | None, **extra: Any) -> dict[str, Any]:
    staging = Staging(tmp_path / "staging")
    upload_id, file_id = new_id(), new_id()
    if data is not None:
        with staging.create(upload_id, file_id) as sink:
            sink.write(data)
        staging.commit(upload_id, file_id)
    return {
        "upload": upload_id,
        "file": file_id,
        "name": "core/weak.cfg",
        "frameworks": ["nist_800_53r5"],
        "vendor": None,
        "staging": str(staging.root),
        "packs": str(PACKS),
        **extra,
    }


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
        (b"hostname x\n", {"upload": "../../etc"}, "doesn't name an uploaded file"),
    ],
)
def test_failures_are_sentences_for_the_user(
    tmp_path: Path, data: bytes, extra: dict[str, Any], message: str
) -> None:
    with pytest.raises(JobError, match=message) as caught:
        audit_file(_payload(tmp_path, data, **extra))
    assert "some words" not in str(caught.value)
