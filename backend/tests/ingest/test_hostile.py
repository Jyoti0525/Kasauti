"""Hostile inputs (TODO M2.07; PLAN §22: 0 crashes, 0 hangs beyond limits).

Three layers, as an attacker would meet them: the upload intake (in the server's own process),
each shape family's parser forced onto the file (the uploader can name any vendor), and the
whole audit in worker processes. Time bounds are generous for slow CI machines; before the
M2.07 fixes, 256 KiB of nested XML took three minutes.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from sqlalchemy import Engine

from kasauti.ingest.read import IngestError, decode
from kasauti.ingest.sealed import new_key
from kasauti.ingest.staging import Staging
from kasauti.ingest.upload import Received, inspect, new_id
from kasauti.ingest.worker import STAGING_KEY_NAME
from kasauti.jobs import JobQueue, JobState, WorkerPool
from kasauti.jobs.kinds import HANDLERS
from kasauti.shape.base import MAX_DEPTH
from kasauti.shape.model import ShapeFamily
from kasauti.shape.parse import parse_text

sys.path.insert(0, str(Path(__file__).parent))
from hostile import ARCHIVES, FILES, MIB, RLO, Case

REPO = Path(__file__).resolve().parents[3]
KEY = new_key()
SECONDS = 10.0


# -- the intake --------------------------------------------------------------------------------


@pytest.fixture
def staging(tmp_path: Path) -> Staging:
    stage = Staging(tmp_path / "staging", KEY)
    stage.prepare()
    return stage


def _intake(staging: Staging, case: Case) -> list[Received]:
    upload_id, file_id = new_id(), new_id()
    data = case.make(MIB)
    with staging.create(upload_id, file_id) as sink:
        sink.write(data)
    started = time.monotonic()
    rows = inspect(staging, upload_id, Received(file_id, case.name, len(data), "0" * 64))
    assert time.monotonic() - started < SECONDS, case.why
    return rows


@pytest.mark.parametrize("case", ARCHIVES, ids=lambda c: c.name)
def test_the_intake_survives_every_hostile_archive(staging: Staging, case: Case) -> None:
    rows = _intake(staging, case)
    for row in rows:
        assert row.accepted or row.reason, row
        # Names are labels: nothing that climbs, is absolute, or hides characters.
        assert ".." not in row.name.split("/")
        assert not row.name.startswith("/")
        assert not any(ch in row.name for ch in ("\x00", RLO, "\\", ":"))


def test_the_intake_refuses_what_it_should(staging: Staging) -> None:
    reasons = {c.name: {r.reason for r in _intake(staging, c)} for c in ARCHIVES}
    assert reasons["lzma.zip"] == {
        "compressed with a method Kasauti doesn't read; use standard zip (deflate)"
    }
    assert reasons["many.zip"] == {"the archive holds 5000 entries; at most 1000 are opened"}
    assert reasons["truncated.zip"] == {"not a readable zip archive"}
    assert reasons["nested.zip"] == {
        "an archive inside an archive isn't opened; upload it on its own"
    }
    # 500 names for one compressed stream: the first is read, the rest are overlaps.
    assert reasons["overlap.zip"] == {None, "damaged or unreadable in the archive"}


# -- the parsers, forced ----------------------------------------------------------------------

FAMILY = {
    ".xml": ShapeFamily.XML,
    ".json": ShapeFamily.JSON_YAML,
    ".yaml": ShapeFamily.JSON_YAML,
    ".conf": ShapeFamily.BRACE,
    ".cfg": ShapeFamily.INDENT,
    ".rsc": ShapeFamily.PATH_COMMAND,
}


def _family(case: Case) -> ShapeFamily:
    if case.name.startswith("forti"):
        return ShapeFamily.BLOCK_EDIT
    return FAMILY[Path(case.name).suffix]


@pytest.mark.parametrize("case", FILES, ids=lambda c: c.name)
def test_each_parser_takes_a_hostile_mebibyte_in_linear_time(case: Case) -> None:
    try:
        artifact = decode(case.make(MIB), case.name)
    except IngestError:
        return  # refused before any parser sees it (UTF-16 without a BOM reads as binary)
    started = time.monotonic()
    tree = parse_text(artifact.text, source_file=case.name, family=_family(case))
    assert time.monotonic() - started < SECONDS, case.why
    assert all(len(s.path) <= MAX_DEPTH for s in tree.statements)


@pytest.mark.parametrize("name", ["deep.xml", "deep.json", "deep-object.json", "deep.conf"])
def test_nesting_past_the_limit_is_read_line_by_line_with_a_warning(name: str) -> None:
    case = next(c for c in FILES if c.name == name)
    tree = parse_text(case.make(64 * 1024).decode(), source_file=name, family=_family(case))
    assert tree.family is ShapeFamily.FLAT
    assert f"nested more than {MAX_DEPTH} levels deep" in tree.warnings[0]


def test_a_real_depth_still_parses_as_blocks() -> None:
    nested = "".join(f"{'  ' * i}level{i}\n" for i in range(MAX_DEPTH))
    tree = parse_text(nested, source_file="deep.cfg", family=ShapeFamily.INDENT)
    assert tree.family is ShapeFamily.INDENT
    assert len(tree.statements[-1].path) == MAX_DEPTH - 1


# -- the whole audit, in worker processes -----------------------------------------------------

VENDOR = {
    ShapeFamily.XML: "paloalto_panos",
    ShapeFamily.BRACE: "juniper_junos",
    ShapeFamily.INDENT: "cisco_ios_xe",
    ShapeFamily.BLOCK_EDIT: "fortinet_fortios",
}
INTERNAL = ("internal error", "ended unexpectedly", "timed out", "unreadable result")


def test_every_hostile_file_ends_its_audit_job_cleanly(any_engine: Engine, tmp_path: Path) -> None:
    """Named for the vendor whose parser it attacks, every file's job ends: audited, or failed
    with a sentence for the user. Never a crash, a hang, or an internal error."""
    staging = Staging(tmp_path / "staging", KEY)
    staging.prepare()
    queue = JobQueue(any_engine, set(HANDLERS))
    jobs: dict[str, str] = {}
    for case in FILES:
        upload_id, file_id = new_id(), new_id()
        with staging.create(upload_id, file_id) as sink:
            sink.write(case.make(256 * 1024))
        staging.commit(upload_id, file_id)
        payload = {
            "upload": upload_id,
            "file": file_id,
            "name": case.name,
            "frameworks": ["nist_800_53r5"],
            "vendor": VENDOR.get(_family(case)),
            "staging": str(staging.root),
            "staging_key": staging.key_id,
            "packs": str(REPO / "packs"),
        }
        jobs[queue.enqueue("audit_file", payload, timeout_s=120)] = case.name
    pool = WorkerPool(queue, HANDLERS, workers=2, poll_s=0.05, secrets={STAGING_KEY_NAME: KEY})
    pool.run_until_idle(timeout_s=600)
    for job_id, name in jobs.items():
        job = queue.get(job_id)
        assert job is not None
        assert job.state in (JobState.SUCCEEDED, JobState.FAILED), name
        if job.state is JobState.FAILED:
            assert job.error is not None
            assert job.error.startswith(f"{name}: "), (name, job.error)
            assert not any(word in job.error for word in INTERNAL), (name, job.error)
